package postgres

import (
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

// SetupReplication has installation authority only. It creates, records and
// physically clones a new pair; it cannot terminate or promote either server.
func SetupReplication(ctx context.Context, dir, endpoint, engine string) (i ReplicationInventory, err error) {
	d := Docker{endpoint, engine}
	if err = d.verifyEngine(ctx); err != nil {
		return i, err
	}
	var image struct {
		ID               string `json:"Id"`
		Architecture, Os string
	}
	if err = d.inspect(ctx, "image", Image, &image); err != nil {
		return i, err
	}
	if image.Architecture != "amd64" || image.Os != "linux" {
		return i, errors.New("pinned linux/amd64 PostgreSQL image required")
	}
	abs, err := localstate.CreateDirectory(dir)
	if err != nil {
		return i, err
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return i, err
	}
	now := time.Now().UTC()
	i = ReplicationInventory{Version: ReplicationVersion, Run: localstate.RandomID(), Directory: abs, Endpoint: endpoint, Engine: engine, Image: Image, ImageID: image.ID, Actor: actor, CreatedAt: now, CleanupBefore: now.Add(30 * time.Minute), Profiles: map[string]string{}, Starts: map[string]string{}}
	k := replicationKeys{Password: localstate.RandomID(), ReplicationPassword: localstate.RandomID()}
	for _, pair := range []struct{ pub, priv *[]byte }{{&i.PrepareKey, &k.Prepare}, {&i.TerminationKey, &k.Termination}, {&i.PromotionKey, &k.Promotion}, {&i.LedgerKey, &k.Ledger}, {&i.CleanupKey, &k.Cleanup}} {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return i, e
		}
		*pair.pub, *pair.priv = pub, priv
	}
	if err = localstate.WriteNew(filepath.Join(abs, "replication-keys.json"), k); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "replication-setup-intent.json"), i); err != nil {
		return i, err
	}
	l, err := localstate.OpenLock(filepath.Join(abs, "runner.lock"), true)
	if err != nil {
		return i, err
	}
	defer l.Close()
	if err = l.Acquire(ctx); err != nil {
		return i, err
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	name := "themis-pgr-" + i.Run
	a := append([]string{"network", "create", "--internal", "--driver", "bridge"}, replicationLabels(i.Run, "network")...)
	b, err := d.output(ctx, nil, append(a, name)...)
	if err != nil {
		return i, err
	}
	networkID := strings.TrimSpace(string(b))
	if !hexID.MatchString(networkID) {
		return i, errors.New("network creation ambiguous")
	}
	if err = d.inspect(ctx, "network", networkID, &i.Network); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "replication-owned-network.json"), i.Network); err != nil {
		return i, err
	}
	for _, role := range []string{"primary", "standby"} {
		r := Resource{Role: role}
		volume := name + "-" + role
		if present, e := d.exists(ctx, "volume", volume); e != nil || present {
			return i, errors.New("volume unavailable; adoption forbidden")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "replication-"+role+"-create-intent.json"), map[string]string{"volume": volume}); err != nil {
			return i, err
		}
		a = append([]string{"volume", "create", "--driver", "local"}, replicationLabels(i.Run, role)...)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, err = d.output(ctx, nil, append(a, volume)...)
		if err != nil {
			return i, err
		}
		if strings.TrimSpace(string(b)) != volume {
			return i, errors.New("volume creation ambiguous")
		}
		if err = d.inspect(ctx, "volume", volume, &r.Volume); err != nil {
			return i, err
		}
		if err = localstate.WriteNew(filepath.Join(abs, "replication-owned-"+role+"-volume.json"), r.Volume); err != nil {
			return i, err
		}
		a = []string{"container", "create", "--name", volume, "--user", "999:999", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no", "--cpus", "1", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64", "--ulimit", "fsize=8388608:8388608", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", "--network", i.Network.ID, "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700", "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700", "--env", "PGDATA=/var/lib/postgresql/18/docker", "--env", "POSTGRES_USER=themis", "--env", "POSTGRES_DB=" + Database, "--env", "POSTGRES_PASSWORD_FILE=/var/lib/postgresql/themis-secrets/password", "--env", "PGPASSFILE=/var/lib/postgresql/themis-secrets/pgpass", "--env", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256 --wal-segsize=1 --data-checksums"}
		a = append(a, replicationLabels(i.Run, role)...)
		a = append(a, "--entrypoint", "/bin/sh", Image)
		a = append(a, replicationServerArgs(role)...)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, err = d.output(ctx, nil, a...)
		if err != nil {
			return i, err
		}
		r.ID = strings.TrimSpace(string(b))
		if !hexID.MatchString(r.ID) {
			return i, errors.New("container creation ambiguous")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "replication-owned-"+role+".json"), r); err != nil {
			return i, err
		}
		if _, err = d.output(ctx, nil, "start", r.ID); err != nil {
			return i, err
		}
		if _, err = pitrExec(ctx, d, r.ID, "mkdir", "-m", "700", "-p", "/var/lib/postgresql/themis-secrets", "/var/lib/postgresql/themis-replication", "/var/lib/postgresql/themis-recovery", "/var/lib/postgresql/themis-logs"); err != nil {
			return i, err
		}
		files := map[string]string{"themis-secrets/password": k.Password + "\n", "themis-secrets/pgpass": "127.0.0.1:5432:*:themis:" + k.Password + "\n"}
		if role == "primary" {
			files["themis-secrets/ready"] = "ready\n"
		} else {
			files["themis-secrets/replication-pass"] = i.PrimaryIP + ":5432:replication:themis_repl:" + k.ReplicationPassword + "\n"
		}
		if err = pitrDeliver(ctx, d, r.ID, "/var/lib/postgresql", files); err != nil {
			return i, err
		}
		address, e := d.replicationAddress(ctx, r.ID, i.Network.ID)
		if e != nil {
			return i, e
		}
		if role == "primary" {
			i.PrimaryIP = address
			for {
				r.DB, err = d.databaseIdentity(ctx, r)
				if err == nil {
					break
				}
				if err = replicationWait(ctx); err != nil {
					return i, err
				}
			}
			i.Primary = r
		} else {
			i.Standby = r
			i.StandbyIP = address
		}
		versions, e := pitrCheckTools(ctx, d, r.ID)
		if e != nil {
			return i, e
		}
		if err = localstate.WriteNew(filepath.Join(abs, "replication-tool-versions-"+role+".json"), versions); err != nil {
			return i, err
		}
	}
	// Replication credentials and connection configuration only enter private stdin
	// and files. No password or DSN appears in Docker argv or public observations.
	if _, err = d.replicationSQL(ctx, i.Primary.ID, "CREATE ROLE themis_repl WITH LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '"+k.ReplicationPassword+"';"); err != nil {
		return i, err
	}
	hba := "local all all scram-sha-256\nhost all themis 127.0.0.1/32 scram-sha-256\nhost replication themis_repl " + i.StandbyIP + "/32 scram-sha-256\n"
	if err = pitrDeliver(ctx, d, i.Primary.ID, "/var/lib/postgresql/18/docker", map[string]string{"pg_hba.conf.themis": hba}); err != nil {
		return i, err
	}
	if _, err = pitrExec(ctx, d, i.Primary.ID, "mv", "-T", "--", "/var/lib/postgresql/18/docker/pg_hba.conf.themis", "/var/lib/postgresql/18/docker/pg_hba.conf"); err != nil {
		return i, err
	}
	if _, err = d.replicationSQL(ctx, i.Primary.ID, "SELECT pg_reload_conf();"); err != nil {
		return i, err
	}
	// Fixed plain physical clone. No slot can retain unbounded WAL.
	if _, err = pitrExec(ctx, d, i.Standby.ID, "env", "PGPASSFILE=/var/lib/postgresql/themis-secrets/replication-pass", "pg_basebackup", "-w", "-h", i.PrimaryIP, "-p", "5432", "-U", "themis_repl", "-D", "/var/lib/postgresql/18/docker", "-Fp", "-Xstream", "--no-slot", "--checkpoint=fast", "--manifest-checksums=SHA256"); err != nil {
		return i, errors.New("physical standby clone failed")
	}
	if _, err = pitrExec(ctx, d, i.Standby.ID, "pg_verifybackup", "--exit-on-error", "/var/lib/postgresql/18/docker"); err != nil {
		return i, errors.New("physical standby backup verification failed")
	}
	conf := fmt.Sprintf("include = '/var/lib/postgresql/18/docker/postgresql.conf'\nprimary_conninfo = 'host=%s port=5432 user=themis_repl application_name=themis_standby passfile=/var/lib/postgresql/themis-secrets/replication-pass connect_timeout=3 sslmode=disable'\n", i.PrimaryIP)
	if err = pitrDeliver(ctx, d, i.Standby.ID, "/var/lib/postgresql/themis-replication", map[string]string{"standby.conf": conf, "pg_hba.conf": hba}); err != nil {
		return i, err
	}
	if err = pitrDeliver(ctx, d, i.Standby.ID, "/var/lib/postgresql/18/docker", map[string]string{"standby.signal": ""}); err != nil {
		return i, err
	}
	if err = pitrDeliver(ctx, d, i.Standby.ID, "/var/lib/postgresql/themis-recovery", map[string]string{"start": "start\n"}); err != nil {
		return i, err
	}
	for {
		i.Standby.DB, err = d.databaseIdentity(ctx, i.Standby)
		if err == nil {
			break
		}
		if err = replicationWait(ctx); err != nil {
			return i, err
		}
	}
	for _, r := range i.resources() {
		var c durableContainer
		if err = d.inspect(ctx, "container", r.ID, &c); err != nil {
			return i, err
		}
		i.Profiles[r.Role], i.Starts[r.Role] = replicationProfile(c), c.State.StartedAt
	}
	if err = i.validate(); err != nil {
		return i, err
	}
	for _, r := range i.resources() {
		if err = d.replicationTarget(ctx, i, r); err != nil {
			return i, err
		}
		if _, err = d.replicationBudget(ctx, r); err != nil {
			return i, err
		}
	}
	if err = localstate.WriteNew(filepath.Join(abs, "replication-ownership.json"), i); err != nil {
		return i, err
	}
	h := replicationInventoryHash(i)
	if err = localstate.WriteNew(filepath.Join(abs, "replication-ownership-seal.json"), inventorySeal{ReplicationVersion, h, ed25519.Sign(k.Cleanup, []byte(h))}); err != nil {
		return i, err
	}
	g := replicationCleanupGrant{ReplicationVersion, h, i.CleanupBefore, nil}
	g.Signature = ed25519.Sign(k.Cleanup, replicationCleanupMessage(g))
	err = localstate.WriteNew(filepath.Join(abs, "replication-cleanup-capability.json"), g)
	return i, err
}
func replicationWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.New("replication operation canceled or timed out")
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}
