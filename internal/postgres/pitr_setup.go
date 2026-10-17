package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// SetupPITR creates only new disposable resources. Partial installations retain
// acknowledged IDs for manual review; no unacknowledged create is ever adopted.
func SetupPITR(ctx context.Context, dir, endpoint, engine string) (i PITRInventory, err error) {
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
	abs, err := localstate.CreateDirectory(dir)
	if err != nil {
		return i, err
	}
	if _, err = localstate.CreateDirectory(filepath.Join(abs, "capsule")); err != nil {
		return i, err
	}
	if _, err = localstate.CreateDirectory(filepath.Join(abs, "capsule", "wal")); err != nil {
		return i, err
	}
	a, err := localstate.CurrentActor()
	if err != nil {
		return i, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return i, err
	}
	lpub, lpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return i, err
	}
	cpub, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return i, err
	}
	now := time.Now().UTC()
	i = PITRInventory{Inventory: Inventory{Version: PITRVersion, Run: localstate.RandomID(), Directory: abs, Actor: a, Endpoint: endpoint, Engine: engine, Image: Image, ImageID: image.ID, Approver: pub, LedgerKey: lpub, CleanupBefore: now.Add(30 * time.Minute)}, CreatedAt: now, CleanupKey: cpub, Profiles: map[string]string{}, Starts: map[string]string{}}
	password := localstate.RandomID()
	if err = localstate.WriteNew(filepath.Join(abs, "pitr-keys.json"), pitrKeys{priv, lpriv, cpriv, password}); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "pitr-setup-intent.json"), i); err != nil {
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
	name := "themis-pgp-" + i.Run
	args := append([]string{"network", "create", "--internal", "--driver", "bridge"}, pitrLabels(i.Run, "network")...)
	b, err := d.output(ctx, nil, append(args, name)...)
	if err != nil {
		return i, err
	}
	id := strings.TrimSpace(string(b))
	if !hexID.MatchString(id) {
		return i, errors.New("network creation ambiguous")
	}
	if err = d.inspect(ctx, "network", id, &i.Network); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "pitr-owned-network.json"), i.Network); err != nil {
		return i, err
	}
	// Mounting the image's existing PostgreSQL parent initializes each new volume
	// with UID 999 ownership, without a privileged/root initializer.
	for _, role := range []string{"archive", "source", "restore"} {
		r := Resource{Role: role}
		volume := name + "-" + role
		if present, e := d.exists(ctx, "volume", volume); e != nil || present {
			return i, errors.New("volume unavailable; adoption forbidden")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "pitr-"+role+"-create-intent.json"), map[string]string{"volume": volume}); err != nil {
			return i, err
		}
		args = append([]string{"volume", "create", "--driver", "local"}, pitrLabels(i.Run, role)...)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, err = d.output(ctx, nil, append(args, volume)...)
		if err != nil {
			return i, err
		}
		if strings.TrimSpace(string(b)) != volume {
			return i, errors.New("volume creation ambiguous")
		}
		if err = d.inspect(ctx, "volume", volume, &r.Volume); err != nil {
			return i, err
		}
		if err = localstate.WriteNew(filepath.Join(abs, "pitr-owned-"+role+"-volume.json"), r.Volume); err != nil {
			return i, err
		}
		network := i.Network.ID
		if role == "archive" {
			network = "none"
		}
		args = []string{"container", "create", "--name", volume, "--user", "999:999", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no", "--cpus", "1", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64", "--ulimit", "fsize=8388608:8388608", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2", "--network", network, "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16777216,uid=999,gid=999,mode=0700", "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=1048576,uid=999,gid=999,mode=0700", "--env", "PGDATA=/var/lib/postgresql/18/docker", "--env", "POSTGRES_USER=themis", "--env", "POSTGRES_DB=" + Database, "--env", "POSTGRES_PASSWORD_FILE=/var/lib/postgresql/themis-secrets/password", "--env", "PGPASSFILE=/var/lib/postgresql/themis-secrets/pgpass", "--env", "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256 --wal-segsize=1 --data-checksums"}
		if role == "source" {
			args = append(args, "--mount", "type=volume,source="+i.Archive.Volume.Name+",target=/themis-store")
		}
		args = append(args, pitrLabels(i.Run, role)...)
		args = append(args, "--entrypoint", "/bin/sh", Image)
		args = append(args, pitrServerArgs(role)...)
		if err = d.verifyEngine(ctx); err != nil {
			return i, err
		}
		b, err = d.output(ctx, nil, args...)
		if err != nil {
			return i, err
		}
		r.ID = strings.TrimSpace(string(b))
		if !hexID.MatchString(r.ID) {
			return i, errors.New("container creation ambiguous")
		}
		if err = localstate.WriteNew(filepath.Join(abs, "pitr-owned-"+role+".json"), r); err != nil {
			return i, err
		}
		if _, err = d.output(ctx, nil, "start", r.ID); err != nil {
			return i, err
		}
		if _, err = pitrExec(ctx, d, r.ID, "mkdir", "-m", "700", "-p", "/var/lib/postgresql/themis-secrets", "/var/lib/postgresql/themis-tools", "/var/lib/postgresql/themis-logs", "/var/lib/postgresql/themis-recovery"); err != nil {
			return i, err
		}
		if role == "archive" {
			if _, err = pitrExec(ctx, d, r.ID, "mkdir", "-m", "700", "/var/lib/postgresql/wal"); err != nil {
				return i, err
			}
			i.Archive = r
		} else {
			files := map[string]string{"themis-secrets/password": password + "\n", "themis-secrets/pgpass": "127.0.0.1:5432:*:themis:" + password + "\n", "themis-tools/archive-wal": pitrArchiveScript, "themis-tools/restore-wal": pitrRestoreScript, "themis-secrets/ready": "ready\n"}
			if err = pitrDeliver(ctx, d, r.ID, "/var/lib/postgresql", files); err != nil {
				return i, err
			}
			if role == "source" {
				for {
					r.DB, err = d.databaseIdentity(ctx, r)
					if err == nil {
						break
					}
					select {
					case <-ctx.Done():
						return i, errors.New("PITR source readiness timeout")
					case <-time.After(200 * time.Millisecond):
					}
				}
				i.Source = r
			} else {
				i.Restore = r
			}
		}
		versions, e := pitrCheckTools(ctx, d, r.ID)
		if e != nil {
			return i, e
		}
		if err = localstate.WriteNew(filepath.Join(abs, "pitr-tool-versions-"+role+".json"), versions); err != nil {
			return i, err
		}
		var c durableContainer
		if err = d.inspect(ctx, "container", r.ID, &c); err != nil {
			return i, err
		}
		i.Profiles[role] = pitrProfile(c)
		i.Starts[role] = c.State.StartedAt
	}
	if err = i.validate(); err != nil {
		return i, err
	}
	if err = d.pitrSource(ctx, i); err != nil {
		return i, err
	}
	if err = localstate.WriteNew(filepath.Join(abs, "pitr-ownership.json"), i); err != nil {
		return i, err
	}
	h := pitrInventoryHash(i)
	if err = localstate.WriteNew(filepath.Join(abs, "pitr-ownership-seal.json"), inventorySeal{PITRVersion, h, ed25519.Sign(cpriv, []byte(h))}); err != nil {
		return i, err
	}
	g := pitrCleanupGrant{PITRVersion, h, i.CleanupBefore, nil}
	g.Signature = ed25519.Sign(cpriv, pitrCleanupMessage(g))
	err = localstate.WriteNew(filepath.Join(abs, "pitr-cleanup-capability.json"), g)
	return i, err
}
