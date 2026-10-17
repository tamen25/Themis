package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type durableContainer struct {
	ID           string `json:"Id"`
	Image        string
	RestartCount int
	Config       struct {
		Image, User          string
		Labels               map[string]string
		Env, Entrypoint, Cmd []string
	}
	HostConfig struct {
		ReadonlyRootfs, Privileged              bool
		Memory, MemorySwap, NanoCpus, PidsLimit int64
		CapDrop, CapAdd, SecurityOpt, Binds     []string
		Devices                                 []json.RawMessage
		PortBindings                            map[string]any
		RestartPolicy                           struct{ Name string }
		Tmpfs                                   map[string]string
		Ulimits                                 []struct {
			Name       string
			Hard, Soft int64
		}
		LogConfig struct {
			Type   string
			Config map[string]string
		}
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	NetworkSettings struct {
		Networks map[string]struct{ NetworkID string }
	}
	State struct {
		Running, OOMKilled    bool
		Pid, ExitCode         int
		StartedAt, FinishedAt string
	}
}

func durableLabelsOK(labels map[string]string, run, role string) bool {
	return len(labels) == 3 && labels[ownerLabel] == run && labels["dev.themis.postgres.role"] == role && labels["dev.themis.postgres.policy"] == DurableWorkflow
}
func durableLabelArgs(run, role string) []string {
	return []string{"--label", ownerLabel + "=" + run, "--label", "dev.themis.postgres.role=" + role, "--label", "dev.themis.postgres.policy=" + DurableWorkflow}
}
func durableServerArgs() []string {
	return []string{"-c", bootstrap, "--", "postgres", "-c", "listen_addresses=127.0.0.1", "-c", "shared_buffers=16MB", "-c", "max_connections=8", "-c", "work_mem=1MB", "-c", "temp_file_limit=4096", "-c", "statement_timeout=5000", "-c", "lock_timeout=2000", "-c", "idle_in_transaction_session_timeout=5000", "-c", "min_wal_size=4MB", "-c", "max_wal_size=16MB", "-c", "fsync=on", "-c", "synchronous_commit=on", "-c", "full_page_writes=on"}
}

func (d Docker) durableVolume(ctx context.Context, i DurableInventory, r Resource) error {
	var v Volume
	if e := d.inspect(ctx, "volume", r.Volume.Name, &v); e != nil {
		return e
	}
	if digest("volume", v) != digest("volume", r.Volume) || v.Driver != "local" || len(v.Options) != 0 || !durableLabelsOK(v.Labels, i.Run, r.Role) {
		return errors.New("persistent volume identity or driver mismatch")
	}
	return nil
}
func (d Docker) durableNetwork(ctx context.Context, i DurableInventory) error {
	var n Network
	if e := d.inspect(ctx, "network", i.Network.ID, &n); e != nil {
		return e
	}
	if digest("network", n) != digest("network", i.Network) || !n.Internal || n.Driver != "bridge" || !durableLabelsOK(n.Labels, i.Run, "network") {
		return errors.New("durable network mismatch")
	}
	return nil
}
func (d Docker) durableContainer(ctx context.Context, i DurableInventory, r Resource, running bool) (durableContainer, error) {
	return d.durableContainerIdentity(ctx, i, r, running, true)
}

// Cleanup may remove the exact originally owned container after a restart;
// recovery admission still requires the original boot and restart count.
func (d Docker) durableContainerIdentity(ctx context.Context, i DurableInventory, r Resource, running, originalBoot bool) (durableContainer, error) {
	var c durableContainer
	if !hexID.MatchString(r.ID) {
		return c, errors.New("invalid exact container ID")
	}
	if e := d.inspect(ctx, "container", r.ID, &c); e != nil {
		return c, e
	}
	h := c.HostConfig
	if c.ID != r.ID || c.Image != i.ImageID || c.Config.Image != Image || c.Config.User != "999:999" || !durableLabelsOK(c.Config.Labels, i.Run, r.Role) || !slices.Equal(c.Config.Entrypoint, []string{"/bin/sh"}) || !slices.Equal(c.Config.Cmd, durableServerArgs()) ||
		!h.ReadonlyRootfs || h.Privileged || h.Memory != MemoryBytes || h.MemorySwap != MemoryBytes || h.NanoCpus != 1000000000 || h.PidsLimit != 64 || len(h.PortBindings) != 0 || h.RestartPolicy.Name != "no" || len(h.Binds) != 0 || len(h.Devices) != 0 || len(h.CapAdd) != 0 ||
		len(h.CapDrop) != 1 || !strings.EqualFold(h.CapDrop[0], "ALL") || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges"}) || (originalBoot && c.RestartCount != 0) || (running && (!c.State.Running || c.State.Pid <= 0)) {
		return c, errors.New("durable container identity, boot or limits mismatch")
	}
	if len(h.Ulimits) != 1 || h.Ulimits[0].Name != "fsize" || h.Ulimits[0].Hard != FileBytes || h.Ulimits[0].Soft != FileBytes || h.LogConfig.Type != "local" || len(h.LogConfig.Config) != 2 || h.LogConfig.Config["max-size"] != "1m" || h.LogConfig.Config["max-file"] != "2" {
		return c, errors.New("file/log budget mismatch")
	}
	if len(c.Mounts) != 1 || c.Mounts[0].Type != "volume" || c.Mounts[0].Name != r.Volume.Name || c.Mounts[0].Destination != "/var/lib/postgresql" || !c.Mounts[0].RW || len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks[i.Network.Name].NetworkID != i.Network.ID {
		return c, errors.New("unexpected persistent mounts or network")
	}
	if len(h.Tmpfs) != 2 || h.Tmpfs["/tmp"] != "rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700" || h.Tmpfs["/var/run/postgresql"] != "rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700" {
		return c, errors.New("temporary storage limits mismatch")
	}
	start := i.SourceStarted
	if r.Role == "restore" {
		start = i.RestoreStarted
	}
	if originalBoot && start != "" && c.State.StartedAt != start {
		return c, errors.New("container restarted or replaced")
	}
	for _, expected := range []string{"PGDATA=/var/lib/postgresql/18/docker", "POSTGRES_USER=themis", "POSTGRES_DB=" + Database, "POSTGRES_PASSWORD_FILE=/var/lib/postgresql/themis-secrets/password", "PGPASSFILE=/var/lib/postgresql/themis-secrets/pgpass", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256 --wal-segsize=1 --data-checksums"} {
		if !slices.Contains(c.Config.Env, expected) {
			return c, errors.New("database environment mismatch")
		}
	}
	return c, d.durableVolume(ctx, i, r)
}
func (d Docker) durableTarget(ctx context.Context, i DurableInventory, r Resource) error {
	if e := d.verifyEngine(ctx); e != nil {
		return e
	}
	if e := d.durableNetwork(ctx, i); e != nil {
		return e
	}
	if _, e := d.durableContainer(ctx, i, r, true); e != nil {
		return e
	}
	v, e := d.databaseIdentity(ctx, r)
	if e != nil {
		return e
	}
	if v != r.DB {
		return errors.New("durable PostgreSQL system or postmaster replaced")
	}
	return nil
}

type StorageObservation struct{ DatabaseBytes, VolumeBytes, AvailableBytes int64 }

func (d Docker) durableBudget(ctx context.Context, r Resource) (StorageObservation, error) {
	var s StorageObservation
	v, e := d.sql(ctx, r.ID, "SELECT pg_database_size(current_database());")
	if e != nil {
		return s, e
	}
	s.DatabaseBytes, e = strconv.ParseInt(v, 10, 64)
	if e != nil {
		return s, errors.New("invalid database size observation")
	}
	b, e := d.output(ctx, nil, "exec", "--user", "999:999", r.ID, "du", "-sb", "--", "/var/lib/postgresql")
	if e != nil {
		return s, e
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return s, errors.New("invalid volume size observation")
	}
	s.VolumeBytes, e = strconv.ParseInt(fields[0], 10, 64)
	if e != nil {
		return s, e
	}
	b, e = d.output(ctx, nil, "exec", "--user", "999:999", r.ID, "df", "-Pk", "--", "/var/lib/postgresql")
	if e != nil {
		return s, e
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		return s, errors.New("invalid free space observation")
	}
	fields = strings.Fields(lines[1])
	if len(fields) < 6 {
		return s, errors.New("invalid free space fields")
	}
	kb, e := strconv.ParseInt(fields[3], 10, 64)
	if e != nil {
		return s, e
	}
	s.AvailableBytes = kb * 1024
	// This is a measured budget for a fixed closed workload, not a local-driver
	// filesystem quota. RLIMIT_FSIZE independently caps every individual file.
	if s.DatabaseBytes <= 0 || s.DatabaseBytes > DatabaseBytes || s.VolumeBytes <= 0 || s.VolumeBytes > VolumeBytes || s.AvailableBytes < 512<<20 {
		return s, fmt.Errorf("persistent storage budget unavailable")
	}
	return s, nil
}
