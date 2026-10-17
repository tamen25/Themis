package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type durableCleanupGrant struct {
	Version, Inventory string
	NotAfter           time.Time
	Signature          []byte
}

func cleanupGrantMessage(g durableCleanupGrant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.durable.cleanup-capability.v1", g))
}

// SetupDurable is installation authority only. It creates no fault grant and
// accepts no existing resource, host directory mount or database connection.
func SetupDurable(ctx context.Context, dir, endpoint, engine string) (i DurableInventory, err error) {
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
		return i, errors.New("pinned linux/amd64 image required")
	}
	abs, e := localstate.CreateDirectory(dir)
	if e != nil {
		return i, e
	}
	backupDir, e := localstate.CreateDirectory(filepath.Join(abs, "backup-store"))
	if e != nil {
		return i, e
	}
	a, e := localstate.CurrentActor()
	if e != nil {
		return i, e
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return i, e
	}
	lpub, lpriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return i, e
	}
	cpub, cpriv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return i, e
	}
	i = DurableInventory{Inventory: Inventory{Version: DurableVersion, Run: localstate.RandomID(), Directory: abs, Actor: a, Endpoint: endpoint, Engine: engine, Image: Image, ImageID: image.ID, Approver: pub, LedgerKey: lpub, CleanupBefore: time.Now().UTC().Add(30 * time.Minute)}, Storage: DurableStorage, CreatedAt: time.Now().UTC(), BackupDirectory: backupDir, CleanupKey: cpub}
	i.BackupID = digest("themis.postgres.durable.backup-id.v1", i.Run)
	if err = localstate.WriteNew(filepath.Join(abs, "durable-keys.json"), durableKeys{priv, lpriv, cpriv}); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "durable-setup-intent.json"), i); err != nil {
		return i, err
	}
	l, e := localstate.OpenLock(filepath.Join(abs, "runner.lock"), true)
	if e != nil {
		return i, e
	}
	defer l.Close()
	if e = l.Acquire(ctx); e != nil {
		return i, e
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	name := "themis-pgd-" + i.Run
	args := append([]string{"network", "create", "--internal", "--driver", "bridge"}, durableLabelArgs(i.Run, "network")...)
	args = append(args, name)
	if err = d.verifyEngine(ctx); err != nil {
		return i, err
	}
	b, e := d.output(ctx, nil, args...)
	if e != nil {
		return i, e
	}
	id := strings.TrimSpace(string(b))
	if !hexID.MatchString(id) {
		return i, errors.New("new network create outcome ambiguous")
	}
	if err = d.inspect(ctx, "network", id, &i.Network); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "durable-owned-network.json"), i.Network); err != nil {
		return i, err
	}
	for _, role := range []string{"source", "restore"} {
		r := Resource{Role: role}
		if err = localstate.WriteNew(filepath.Join(abs, "durable-"+role+"-intent.json"), map[string]string{"run": i.Run, "role": role}); err != nil {
			return i, err
		}
		volumeName := name + "-" + role
		if exists, e := d.exists(ctx, "volume", volumeName); e != nil || exists {
			return i, errors.New("persistent volume name unavailable; adoption forbidden")
		}
		args = append([]string{"volume", "create", "--driver", "local"}, durableLabelArgs(i.Run, role)...)
		args = append(args, volumeName)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, e = d.output(ctx, nil, args...)
		if e != nil {
			return i, e
		}
		if strings.TrimSpace(string(b)) != volumeName {
			return i, errors.New("persistent volume create ambiguous")
		}
		if err = d.inspect(ctx, "volume", volumeName, &r.Volume); err != nil {
			return i, err
		}
		if err = localstate.WriteNew(filepath.Join(abs, "durable-owned-"+role+"-volume.json"), r.Volume); err != nil {
			return i, err
		}
		args = []string{"container", "create", "--name", volumeName, "--user", "999:999", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no", "--cpus", "1", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64", "--ulimit", "fsize=8388608:8388608", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", "--network", i.Network.ID,
			"--mount", "type=volume,source=" + volumeName + ",target=/var/lib/postgresql",
			"--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700", "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700",
			"--env", "PGDATA=/var/lib/postgresql/18/docker", "--env", "POSTGRES_USER=themis", "--env", "POSTGRES_DB=" + Database, "--env", "POSTGRES_PASSWORD_FILE=/var/lib/postgresql/themis-secrets/password", "--env", "PGPASSFILE=/var/lib/postgresql/themis-secrets/pgpass", "--env", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256 --wal-segsize=1 --data-checksums"}
		args = append(args, durableLabelArgs(i.Run, role)...)
		args = append(args, "--entrypoint", "/bin/sh", Image)
		args = append(args, durableServerArgs()...)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, e = d.output(ctx, nil, args...)
		if e != nil {
			return i, e
		}
		r.ID = strings.TrimSpace(string(b))
		if !hexID.MatchString(r.ID) {
			return i, errors.New("new container create outcome ambiguous")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "durable-owned-"+role+".json"), r); err != nil {
			return i, err
		}
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		if _, err = d.output(ctx, nil, "start", r.ID); err != nil {
			return i, err
		}
		if err = deliverDurableCredentials(ctx, d, r.ID); err != nil {
			return i, err
		}
		for {
			r.DB, e = d.databaseIdentity(ctx, r)
			if e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return i, errors.New("durable PostgreSQL readiness timed out")
			case <-time.After(200 * time.Millisecond):
			}
		}
		var c durableContainer
		if err = d.inspect(ctx, "container", r.ID, &c); err != nil {
			return i, err
		}
		if role == "source" {
			i.Source = r
			i.SourceStarted = c.State.StartedAt
		} else {
			i.Restore = r
			i.RestoreStarted = c.State.StartedAt
		}
		if err = localstate.WriteNew(filepath.Join(abs, "durable-ready-"+role+".json"), r); err != nil {
			return i, err
		}
	}
	if err = i.validate(); err != nil {
		return i, err
	}
	for _, r := range []Resource{i.Source, i.Restore} {
		if err = d.durableTarget(ctx, i, r); err != nil {
			return i, err
		}
		if _, err = d.durableBudget(ctx, r); err != nil {
			return i, err
		}
	}
	if err = localstate.WriteNew(filepath.Join(abs, "durable-ownership.json"), i); err != nil {
		return i, err
	}
	ih := digest("themis.postgres.durable.inventory.v1", i)
	if err = localstate.WriteNew(filepath.Join(abs, "durable-ownership-seal.json"), inventorySeal{DurableVersion, ih, ed25519.Sign(cpriv, []byte(ih))}); err != nil {
		return i, err
	}
	g := durableCleanupGrant{Version: DurableVersion, Inventory: ih, NotAfter: i.CleanupBefore}
	g.Signature = ed25519.Sign(cpriv, cleanupGrantMessage(g))
	err = localstate.WriteNew(filepath.Join(abs, "durable-cleanup-capability.json"), g)
	return i, err
}

func deliverDurableCredentials(ctx context.Context, d Docker, id string) error {
	secret := localstate.RandomID()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, v := range []struct {
		name, body string
		mode       int64
	}{{"themis-secrets/", "", 0700}, {"themis-secrets/password", secret + "\n", 0600}, {"themis-secrets/pgpass", "127.0.0.1:5432:*:themis:" + secret + "\n", 0600}, {"themis-secrets/ready", "ready\n", 0600}} {
		h := &tar.Header{Name: v.name, Mode: v.mode, Uid: 999, Gid: 999, Typeflag: tar.TypeReg, Size: int64(len(v.body))}
		if strings.HasSuffix(v.name, "/") {
			h.Typeflag = tar.TypeDir
		}
		if e := tw.WriteHeader(h); e != nil {
			return e
		}
		if _, e := tw.Write([]byte(v.body)); e != nil {
			return e
		}
	}
	if e := tw.Close(); e != nil {
		return e
	}
	_, e := d.output(ctx, &b, "cp", "-a", "-", id+":/var/lib/postgresql")
	return e
}
