package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Docker executes fixed argument vectors. Neither SQL nor process diagnostics are
// returned in errors: psql diagnostics can include credential or application data.
type Docker struct{ Endpoint, Engine string }

type toolError struct {
	ExitCode    int
	Interrupted bool
}

func (e *toolError) Error() string {
	if e.Interrupted {
		return "Docker operation interrupted; outcome may be ambiguous"
	}
	return "Docker operation failed; outcome may be ambiguous"
}
func toolExit(err error) *int {
	v := 0
	if err != nil {
		v = -1
		var e *toolError
		if errors.As(err, &e) {
			v = e.ExitCode
		}
	}
	return &v
}

func ValidateEndpoint(endpoint string) error {
	if runtime.GOOS == "windows" && endpoint == "npipe:////./pipe/dockerDesktopLinuxEngine" {
		return nil
	}
	if runtime.GOOS != "windows" {
		allowed := []string{"unix:///var/run/docker.sock", "unix:///run/docker.sock"}
		if home, err := os.UserHomeDir(); err == nil {
			allowed = append(allowed, "unix://"+filepath.Join(home, ".docker", "desktop", "docker.sock"))
		}
		for _, p := range allowed {
			if p == endpoint {
				return nil
			}
		}
	}
	return errors.New("only an explicitly named local Docker socket is admitted")
}

type limitedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		return 0, errors.New("process output budget exceeded")
	}
	n, e := w.w.Write(b)
	w.remaining -= int64(n)
	return n, e
}

func (d Docker) command(ctx context.Context, input io.Reader, output io.Writer, limit int64, args ...string) error {
	if err := ValidateEndpoint(d.Endpoint); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	argv := append([]string{"--host", d.Endpoint}, args...)
	cmd := exec.CommandContext(ctx, "docker", argv...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "DOCKER_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Stdin = input
	cmd.Stdout = &limitedWriter{output, limit}
	// Drain stderr with a bounded retained size. It is never exported.
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		code := -1
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			code = exited.ExitCode()
		}
		return &toolError{code, ctx.Err() != nil}
	}
	return nil
}
func (d Docker) output(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	var b bytes.Buffer
	err := d.command(ctx, input, &b, 1<<20, args...)
	return b.Bytes(), err
}
func (d Docker) verifyEngine(ctx context.Context) error {
	b, e := d.output(ctx, nil, "info", "--format", "{{json .}}")
	if e != nil {
		return e
	}
	var info struct{ ID, OSType string }
	if json.Unmarshal(b, &info) != nil || info.ID != d.Engine || info.OSType != "linux" || len(d.Engine) < 16 {
		return errors.New("Docker engine identity mismatch")
	}
	return nil
}

type Container struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Image, User string
		Labels      map[string]string
		Env         []string
	}
	HostConfig struct {
		ReadonlyRootfs       bool
		Memory, NanoCpus     int64
		PidsLimit            int64
		CapDrop, SecurityOpt []string
		PortBindings         map[string]any
		RestartPolicy        struct{ Name string }
		Tmpfs                map[string]string
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	NetworkSettings struct {
		Networks map[string]struct{ NetworkID string }
	}
	State struct{ Running bool }
}
type Volume struct {
	Name, Driver, CreatedAt string
	Labels, Options         map[string]string
}
type Network struct {
	ID           string `json:"Id"`
	Name, Driver string
	Internal     bool
	Labels       map[string]string
}

func (d Docker) inspect(ctx context.Context, kind, id string, value any) error {
	b, e := d.output(ctx, nil, kind, "inspect", id)
	if e != nil {
		return e
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil || len(raw) != 1 {
		return errors.New("invalid Docker identity observation")
	}
	return json.Unmarshal(raw[0], value)
}

const ownerLabel = "dev.themis.postgres.owner"

func labelsOK(labels map[string]string, run, role string) bool {
	return len(labels) == 3 && labels[ownerLabel] == run && labels["dev.themis.postgres.role"] == role && labels["dev.themis.postgres.policy"] == Workflow
}
func labelArgs(run, role string) []string {
	return []string{"--label", ownerLabel + "=" + run, "--label", "dev.themis.postgres.role=" + role, "--label", "dev.themis.postgres.policy=" + Workflow}
}
func (d Docker) container(ctx context.Context, i Inventory, r Resource, running bool) error {
	var c Container
	if !hexID.MatchString(r.ID) {
		return errors.New("invalid immutable container ID")
	}
	if e := d.inspect(ctx, "container", r.ID, &c); e != nil {
		return e
	}
	if c.ID != r.ID || c.Image != i.ImageID || c.Config.Image != Image || c.Config.User != "999:999" || !labelsOK(c.Config.Labels, i.Run, r.Role) ||
		!c.HostConfig.ReadonlyRootfs || c.HostConfig.Memory != MemoryBytes || c.HostConfig.NanoCpus != 1000000000 || c.HostConfig.PidsLimit != 64 ||
		len(c.HostConfig.PortBindings) != 0 || c.HostConfig.RestartPolicy.Name != "no" || len(c.HostConfig.CapDrop) != 1 || !strings.EqualFold(c.HostConfig.CapDrop[0], "ALL") ||
		len(c.HostConfig.SecurityOpt) != 1 || c.HostConfig.SecurityOpt[0] != "no-new-privileges" || (running && !c.State.Running) {
		return errors.New("container identity or safety configuration mismatch")
	}
	if len(c.Mounts) != 1 || c.Mounts[0].Type != "volume" || c.Mounts[0].Name != r.Volume.Name || c.Mounts[0].Destination != "/var/lib/postgresql" || !c.Mounts[0].RW {
		return errors.New("unexpected database mount")
	}
	if len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks[i.Network.Name].NetworkID != i.Network.ID {
		return errors.New("unexpected database network")
	}
	if len(c.HostConfig.Tmpfs) != 2 || c.HostConfig.Tmpfs["/tmp"] != "rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700" || c.HostConfig.Tmpfs["/var/run/postgresql"] != "rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700" {
		return errors.New("unexpected temporary storage")
	}
	return d.volume(ctx, i, r)
}
func (d Docker) volume(ctx context.Context, i Inventory, r Resource) error {
	var v Volume
	if e := d.inspect(ctx, "volume", r.Volume.Name, &v); e != nil {
		return e
	}
	if digest("volume", v) != digest("volume", r.Volume) || !labelsOK(v.Labels, i.Run, r.Role) || v.Driver != "local" || v.Options["type"] != "tmpfs" || v.Options["o"] != "size=134217728,uid=999,gid=999,mode=0700" {
		return errors.New("volume identity mismatch")
	}
	return nil
}
func (d Docker) network(ctx context.Context, i Inventory) error {
	var n Network
	if e := d.inspect(ctx, "network", i.Network.ID, &n); e != nil {
		return e
	}
	if digest("network", n) != digest("network", i.Network) || !n.Internal || n.Driver != "bridge" || !labelsOK(n.Labels, i.Run, "network") {
		return errors.New("network identity mismatch")
	}
	return nil
}

func (d Docker) sql(ctx context.Context, id, sql string) (string, error) {
	b, e := d.output(ctx, strings.NewReader(sql), "exec", "--user", "999:999", "-i", id, "psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-At", "-h", "127.0.0.1", "-p", "5432", "-U", "themis", "-d", Database)
	return strings.TrimSpace(string(b)), e
}
func (d Docker) databaseIdentity(ctx context.Context, r Resource) (DBIdentity, error) {
	b, e := d.sql(ctx, r.ID, `SELECT json_build_object('database',current_database(),'system',system_identifier::text,'boot',pg_postmaster_start_time()::text,'version',current_setting('server_version_num')) FROM pg_control_system();`)
	var v DBIdentity
	if e != nil {
		return v, e
	}
	if json.Unmarshal([]byte(b), &v) != nil || v.Database != Database || v.Version != "180006" || v.System == "" || v.Boot == "" {
		return v, errors.New("PostgreSQL identity invalid")
	}
	return v, nil
}

func (d Docker) target(ctx context.Context, i Inventory, r Resource) error {
	if err := d.verifyEngine(ctx); err != nil {
		return err
	}
	if err := d.network(ctx, i); err != nil {
		return err
	}
	if err := d.container(ctx, i, r, true); err != nil {
		return err
	}
	v, e := d.databaseIdentity(ctx, r)
	if e != nil {
		return e
	}
	if v != r.DB {
		return errors.New("PostgreSQL source or destination replaced or restarted")
	}
	return nil
}
