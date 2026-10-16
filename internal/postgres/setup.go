package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type DBIdentity struct {
	Database string `json:"database"`
	System   string `json:"system"`
	Boot     string `json:"boot"`
	Version  string `json:"version"`
}
type Resource struct {
	Role   string     `json:"role"`
	ID     string     `json:"id"`
	Volume Volume     `json:"volume"`
	DB     DBIdentity `json:"databaseIdentity"`
}
type Inventory struct {
	Version       string           `json:"version"`
	Run           string           `json:"run"`
	Directory     string           `json:"directory"`
	Actor         localstate.Actor `json:"actor"`
	Endpoint      string           `json:"endpoint"`
	Engine        string           `json:"engine"`
	Image         string           `json:"image"`
	ImageID       string           `json:"imageId"`
	Network       Network          `json:"network"`
	Source        Resource         `json:"source"`
	Restore       Resource         `json:"restore"`
	Approver      []byte           `json:"approver"`
	LedgerKey     []byte           `json:"ledgerKey"`
	CleanupBefore time.Time        `json:"cleanupBefore"`
}
type keys struct{ Approver, Ledger []byte }

func (i Inventory) validate() error {
	if i.Version != Version || !hexID.MatchString(i.Run) || i.Image != Image || !strings.HasPrefix(i.ImageID, "sha256:") || len(i.ImageID) != 71 ||
		!filepath.IsAbs(i.Directory) || i.Engine == "" || i.Actor.UID == "" || len(i.Approver) != 32 || len(i.LedgerKey) != 32 ||
		!hexID.MatchString(i.Source.ID) || !hexID.MatchString(i.Restore.ID) || i.Source.ID == i.Restore.ID ||
		i.Source.Role != "source" || i.Restore.Role != "restore" || i.Source.DB.Database != Database || i.Restore.DB.Database != Database ||
		i.Source.DB.System == "" || i.Source.DB.System == i.Restore.DB.System || i.Source.DB.Boot == "" || i.Restore.DB.Boot == "" ||
		i.Source.DB.Version != "180006" || i.Restore.DB.Version != "180006" || !hexID.MatchString(i.Network.ID) ||
		i.Network.Name != "themis-pg-"+i.Run || !labelsOK(i.Network.Labels, i.Run, "network") || !i.Network.Internal {
		return errors.New("invalid owned PostgreSQL inventory")
	}
	for _, r := range []Resource{i.Source, i.Restore} {
		if r.Volume.Name != "themis-pg-"+i.Run+"-"+r.Role || r.Volume.CreatedAt == "" || !labelsOK(r.Volume.Labels, i.Run, r.Role) {
			return errors.New("invalid owned volume")
		}
	}
	return ValidateEndpoint(i.Endpoint)
}
func loadInventory(dir string) (Inventory, error) {
	var i Inventory
	abs, e := filepath.Abs(dir)
	if e != nil {
		return i, e
	}
	if e = localstate.Read(filepath.Join(abs, "inventory.json"), &i); e != nil {
		return i, e
	}
	a, e := localstate.CurrentActor()
	if e != nil {
		return i, e
	}
	if i.Directory != abs || a != i.Actor {
		return i, errors.New("original directory or actor mismatch")
	}
	return i, i.validate()
}

// Setup is separate installation authority. It never discovers or adopts a DB.
// Each create intent precedes its effect; each acknowledged identity is published
// immediately. A lost create acknowledgement is not guessed from a resource name.
func Setup(ctx context.Context, dir, endpoint, engine string) (inv Inventory, err error) {
	d := Docker{endpoint, engine}
	if err = d.verifyEngine(ctx); err != nil {
		return inv, err
	}
	var image struct {
		ID               string `json:"Id"`
		Architecture, Os string
	}
	if err = d.inspect(ctx, "image", Image, &image); err != nil {
		return inv, err
	}
	if image.Architecture != "amd64" || image.Os != "linux" {
		return inv, errors.New("only pinned linux/amd64 image is supported")
	}
	abs, e := localstate.CreateDirectory(dir)
	if e != nil {
		return inv, e
	}
	a, e := localstate.CurrentActor()
	if e != nil {
		return inv, e
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return inv, e
	}
	lpub, lpriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return inv, e
	}
	inv = Inventory{Version: Version, Run: localstate.RandomID(), Directory: abs, Actor: a, Endpoint: endpoint, Engine: engine, Image: Image, ImageID: image.ID,
		Approver: pub, LedgerKey: lpub, CleanupBefore: time.Now().UTC().Add(30 * time.Minute)}
	if err = localstate.WriteNew(filepath.Join(abs, "keys.json"), keys{priv, lpriv}); err != nil {
		return inv, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "setup-intent.json"), inv); err != nil {
		return inv, err
	}
	lock, e := localstate.OpenLock(filepath.Join(abs, "runner.lock"), true)
	if e != nil {
		return inv, e
	}
	defer lock.Close()
	if e = lock.Acquire(ctx); e != nil {
		return inv, e
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	name := "themis-pg-" + inv.Run
	args := append([]string{"network", "create", "--internal", "--driver", "bridge"}, labelArgs(inv.Run, "network")...)
	args = append(args, name)
	if err = d.verifyEngine(ctx); err != nil {
		return inv, err
	}
	b, e := d.output(ctx, nil, args...)
	if e != nil {
		return inv, e
	}
	id := strings.TrimSpace(string(b))
	if !hexID.MatchString(id) {
		return inv, errors.New("network acknowledgement ambiguous")
	}
	if err = d.inspect(ctx, "network", id, &inv.Network); err != nil {
		return inv, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "owned-network.json"), inv.Network); err != nil {
		return inv, err
	}
	for _, role := range []string{"source", "restore"} {
		r := Resource{Role: role}
		if err = localstate.WriteNew(filepath.Join(abs, role+"-intent.json"), map[string]string{"run": inv.Run, "role": role}); err != nil {
			return inv, err
		}
		if err = d.verifyEngine(ctx); err != nil {
			return inv, err
		}
		args = append([]string{"volume", "create", "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size=134217728,uid=999,gid=999,mode=0700"}, labelArgs(inv.Run, role)...)
		args = append(args, name+"-"+role)
		b, e = d.output(ctx, nil, args...)
		if e != nil {
			return inv, e
		}
		if strings.TrimSpace(string(b)) != name+"-"+role {
			return inv, errors.New("volume acknowledgement ambiguous")
		}
		if err = d.inspect(ctx, "volume", name+"-"+role, &r.Volume); err != nil {
			return inv, err
		}
		if err = localstate.WriteNew(filepath.Join(abs, "owned-"+role+"-volume.json"), r.Volume); err != nil {
			return inv, err
		}
		if err = d.verifyEngine(ctx); err != nil {
			return inv, err
		}
		args = []string{"container", "create", "--name", name + "-" + role, "--user", "999:999", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no", "--cpus", "1", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64", "--network", inv.Network.ID,
			"--mount", "type=volume,source=" + r.Volume.Name + ",target=/var/lib/postgresql",
			"--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700",
			"--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700",
			"--env", "PGDATA=/var/lib/postgresql/18/docker", "--env", "POSTGRES_USER=themis", "--env", "POSTGRES_DB=" + Database,
			"--env", "POSTGRES_PASSWORD_FILE=/var/lib/postgresql/themis-secrets/password", "--env", "PGPASSFILE=/var/lib/postgresql/themis-secrets/pgpass",
			"--env", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256 --wal-segsize=1 --data-checksums"}
		args = append(args, labelArgs(inv.Run, role)...)
		args = append(args, "--entrypoint", "/bin/sh", Image, "-c", bootstrap, "--", "postgres", "-c", "listen_addresses=127.0.0.1", "-c", "shared_buffers=16MB", "-c", "max_connections=8", "-c", "work_mem=1MB", "-c", "temp_file_limit=4096", "-c", "statement_timeout=5000", "-c", "lock_timeout=2000", "-c", "idle_in_transaction_session_timeout=5000", "-c", "min_wal_size=4MB", "-c", "max_wal_size=16MB", "-c", "fsync=on", "-c", "synchronous_commit=on", "-c", "full_page_writes=on")
		b, e = d.output(ctx, nil, args...)
		if e != nil {
			return inv, e
		}
		r.ID = strings.TrimSpace(string(b))
		if !hexID.MatchString(r.ID) {
			return inv, errors.New("container acknowledgement ambiguous")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "owned-"+role+".json"), r); err != nil {
			return inv, err
		}
		if err = d.verifyEngine(ctx); err != nil {
			return inv, err
		}
		if _, err = d.output(ctx, nil, "start", r.ID); err != nil {
			return inv, err
		}
		secret := localstate.RandomID()
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, f := range []struct {
			name, body string
			mode       int64
		}{{"themis-secrets/", "", 0700}, {"themis-secrets/password", secret + "\n", 0600}, {"themis-secrets/pgpass", "127.0.0.1:5432:*:themis:" + secret + "\n", 0600}, {"themis-secrets/ready", "ready\n", 0600}} {
			h := &tar.Header{Name: f.name, Mode: f.mode, Uid: 999, Gid: 999, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
			if strings.HasSuffix(f.name, "/") {
				h.Typeflag = tar.TypeDir
			}
			if err = tw.WriteHeader(h); err != nil {
				return inv, err
			}
			if _, err = tw.Write([]byte(f.body)); err != nil {
				return inv, err
			}
		}
		if err = tw.Close(); err != nil {
			return inv, err
		}
		if _, err = d.output(ctx, &buf, "cp", "-a", "-", r.ID+":/var/lib/postgresql"); err != nil {
			return inv, err
		}
		for {
			r.DB, e = d.databaseIdentity(ctx, r)
			if e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return inv, errors.New("PostgreSQL setup readiness timed out")
			case <-time.After(200 * time.Millisecond):
			}
		}
		if role == "source" {
			inv.Source = r
		} else {
			inv.Restore = r
		}
		if err = localstate.WriteNew(filepath.Join(abs, "ready-"+role+".json"), r); err != nil {
			return inv, err
		}
	}
	if err = inv.validate(); err != nil {
		return inv, err
	}
	for _, r := range []Resource{inv.Source, inv.Restore} {
		if err = d.target(ctx, inv, r); err != nil {
			return inv, err
		}
	}
	if err = localstate.WriteNew(filepath.Join(abs, "inventory.json"), inv); err != nil {
		return inv, err
	}
	return inv, nil
}

// The fixed bootstrap permits secret delivery after the bounded tmpfs volume is
// mounted. No caller text enters this shell, and failed delivery exits in 30s.
const bootstrap = `n=0; while [ ! -f /var/lib/postgresql/themis-secrets/ready ]; do n=$((n+1)); [ "$n" -le 30 ] || exit 70; sleep 1; done; exec /usr/local/bin/docker-entrypoint.sh "$@"`

func PlanFile(dir string, c Contract) (Plan, error) {
	i, e := loadInventory(dir)
	if e != nil {
		return Plan{}, e
	}
	p, e := Compile(c, i)
	if e != nil {
		return p, e
	}
	return p, localstate.WriteNew(filepath.Join(i.Directory, "plan.json"), p)
}

type Grant struct {
	Version, Plan, Run, Database, Operations  string
	StartBefore, ExecuteBefore, CleanupBefore time.Time
	Signature                                 []byte
}

func grantMessage(g Grant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.authorization.v1", g))
}
func Approve(dir, expected string) (Grant, error) {
	i, e := loadInventory(dir)
	if e != nil {
		return Grant{}, e
	}
	var p Plan
	if e = localstate.Read(filepath.Join(dir, "plan.json"), &p); e != nil {
		return Grant{}, e
	}
	if e = p.Validate(); e != nil {
		return Grant{}, e
	}
	if expected != p.Digest || digest("inventory", i) != digest("inventory", p.Inventory) {
		return Grant{}, errors.New("reviewed plan or inventory mismatch")
	}
	var k keys
	if e = localstate.Read(filepath.Join(dir, "keys.json"), &k); e != nil {
		return Grant{}, e
	}
	if len(k.Approver) != 64 || !bytes.Equal(ed25519.PrivateKey(k.Approver).Public().(ed25519.PublicKey), i.Approver) {
		return Grant{}, errors.New("approver key mismatch")
	}
	now := time.Now().UTC()
	if !now.Add(150 * time.Second).Before(i.CleanupBefore) {
		return Grant{}, errors.New("insufficient remaining cleanup authority; use a fresh setup")
	}
	g := Grant{Version: Version, Plan: p.Digest, Run: i.Run, Database: Database, Operations: "seed,commit,backup,stop-source,restore,verify", StartBefore: now.Add(30 * time.Second), ExecuteBefore: now.Add(150 * time.Second), CleanupBefore: i.CleanupBefore}
	g.Signature = ed25519.Sign(k.Approver, grantMessage(g))
	return g, localstate.WriteNew(filepath.Join(dir, "authorization.json"), g)
}
func validateGrant(p Plan, g Grant, now time.Time, start bool) error {
	if p.Validate() != nil || g.Version != Version || g.Plan != p.Digest || g.Run != p.Inventory.Run || g.Database != Database ||
		g.Operations != "seed,commit,backup,stop-source,restore,verify" || g.CleanupBefore != p.Inventory.CleanupBefore || !now.Before(g.ExecuteBefore) ||
		g.ExecuteBefore.Sub(g.StartBefore) > 120*time.Second || (start && !now.Before(g.StartBefore)) ||
		!ed25519.Verify(p.Inventory.Approver, grantMessage(g), g.Signature) {
		return errors.New("missing, expired or mismatched PostgreSQL authorization")
	}
	return nil
}

func acquire(dir string) (*localstate.Lock, error) {
	l, e := localstate.OpenLock(filepath.Join(dir, "runner.lock"), false)
	if e != nil {
		return nil, e
	}
	ok, e := l.Try()
	if e != nil || !ok {
		l.Close()
		return nil, fmt.Errorf("experiment is active or lock unavailable")
	}
	return l, nil
}
