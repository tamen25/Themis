package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

const pitrArchiveCommand = "timeout 5 /bin/sh /var/lib/postgresql/themis-tools/archive-wal %p %f"
const pitrRestoreCommand = "/bin/sh /var/lib/postgresql/themis-tools/restore-wal %f %p"
const pitrGate = `n=0; while [ ! -f /var/lib/postgresql/themis-recovery/start ]; do n=$((n+1)); [ "$n" -le 1200 ] || exit 70; sleep 1; done; exec postgres "$@"`

// Only PostgreSQL-generated names and paths enter these fixed scripts. They
// publish via exclusive links; existing bytes are accepted only if identical.
const pitrArchiveScript = `set -eu
umask 077
p=$1; f=$2; d=/themis-store/wal
[ "$p" = "pg_wal/$f" ] || exit 71
if printf '%s' "$f" | grep -Eq '^[0-9A-F]{24}$'; then
  [ "$(stat -c %s -- "$p")" = 1048576 ] || exit 73
elif printf '%s' "$f" | grep -Eq '^([0-9A-F]{24}\.[0-9A-F]{8}\.backup|[0-9A-F]{8}\.history)$'; then
  [ "$(stat -c %s -- "$p")" -le 8192 ] || exit 73
else exit 72; fi
[ -d "$d" ] && [ ! -L "$d" ] || exit 74
if [ -e "$d/$f" ]; then
  [ ! -L "$d/$f" ] && cmp -s -- "$p" "$d/$f" || exit 77
  sync -f "$d/$f"
  sync -f "$d"
  exit 0
fi
[ "$(du -sb -- "$d" | cut -f1)" -lt 32505856 ] || exit 75
[ "$(find "$d" -mindepth 1 -maxdepth 1 -type f | wc -l)" -lt 64 ] || exit 75
t="$d/.partial-$f"
(set -C; cat -- "$p" > "$t") || exit 76
trap 'rm -f -- "$t"' EXIT HUP INT TERM
cmp -s -- "$p" "$t" || exit 77
sync -f "$t"
ln -- "$t" "$d/$f"
sync -f "$d"
`
const pitrRestoreScript = `set -eu
f=$1; p=$2; d=/var/lib/postgresql/themis-restore-wal
printf '%s' "$f" | grep -Eq '^([0-9A-F]{24}|[0-9A-F]{8}\.history)$' || exit 71
case "$p" in pg_wal/RECOVERYXLOG|pg_wal/RECOVERYHISTORY) ;; *) exit 72;; esac
[ -f "$d/$f" ] && [ ! -L "$d/$f" ] || exit 73
cp -- "$d/$f" "$p"
`

func pitrLabelsOK(labels map[string]string, run, role string) bool {
	return len(labels) == 3 && labels[ownerLabel] == run && labels["dev.themis.postgres.role"] == role && labels["dev.themis.postgres.policy"] == PITRWorkflow
}
func pitrLabels(run, role string) []string {
	return []string{"--label", ownerLabel + "=" + run, "--label", "dev.themis.postgres.role=" + role, "--label", "dev.themis.postgres.policy=" + PITRWorkflow}
}
func pitrServerArgs(role string) []string {
	if role == "archive" {
		return []string{"-c", "exec sleep 1200"}
	}
	base := durableServerArgs()
	base = append(base, "-c", "wal_level=replica", "-c", "max_wal_senders=2", "-c", "wal_keep_size=16MB", "-c", "hot_standby=on", "-c", "logging_collector=on", "-c", "log_directory=/var/lib/postgresql/themis-logs", "-c", "log_filename=server.log", "-c", "log_rotation_age=0", "-c", "log_rotation_size=0")
	if role == "source" {
		return append(base, "-c", "archive_mode=on", "-c", "archive_command="+pitrArchiveCommand)
	}
	base[1] = pitrGate
	// The gate execs postgres itself; the dummy shell argv[0] remains fixed.
	base = append(base[:3], base[4:]...)
	return append(base, "-c", "archive_mode=off", "-c", "restore_command="+pitrRestoreCommand, "-c", "config_file=/var/lib/postgresql/themis-recovery/postgresql.conf", "-c", "recovery_target_timeline=1", "-c", "recovery_target_action=pause")
}
func pitrProfile(c durableContainer) string {
	c.State = durableContainer{}.State
	c.RestartCount = 0
	return digest("themis.postgres.pitr.container-profile.v1", c)
}
func (d Docker) pitrVolume(ctx context.Context, i PITRInventory, r Resource) error {
	var v Volume
	if err := d.inspect(ctx, "volume", r.Volume.Name, &v); err != nil {
		return err
	}
	if digest("volume", v) != digest("volume", r.Volume) || !pitrLabelsOK(v.Labels, i.Run, r.Role) {
		return errors.New("PITR original volume replaced")
	}
	return nil
}
func (d Docker) pitrNetwork(ctx context.Context, i PITRInventory) error {
	var v Network
	if err := d.inspect(ctx, "network", i.Network.ID, &v); err != nil {
		return err
	}
	if digest("network", v) != digest("network", i.Network) {
		return errors.New("PITR original network replaced")
	}
	return nil
}
func (d Docker) pitrContainer(ctx context.Context, i PITRInventory, r Resource, running, boot bool) (c durableContainer, err error) {
	if err = d.verifyEngine(ctx); err != nil {
		return c, err
	}
	if err = d.inspect(ctx, "container", r.ID, &c); err != nil {
		return c, err
	}
	if c.ID != r.ID || c.Image != i.ImageID || !pitrLabelsOK(c.Config.Labels, i.Run, r.Role) || pitrProfile(c) != i.Profiles[r.Role] || (running && (!c.State.Running || c.State.Pid <= 0)) || (boot && (c.RestartCount != 0 || c.State.StartedAt != i.Starts[r.Role])) {
		return c, errors.New("PITR original container profile or boot mismatch")
	}
	return c, d.pitrVolume(ctx, i, r)
}
func (d Docker) pitrSource(ctx context.Context, i PITRInventory) error {
	if _, err := d.pitrContainer(ctx, i, i.Source, true, true); err != nil {
		return err
	}
	if err := d.pitrNetwork(ctx, i); err != nil {
		return err
	}
	v, err := d.databaseIdentity(ctx, i.Source)
	if err != nil {
		return err
	}
	if v != i.Source.DB {
		return errors.New("PITR source database identity changed")
	}
	return nil
}
func pitrDeliver(ctx context.Context, d Docker, id, root string, files map[string]string) error {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Uid: 999, Gid: 999, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := io.WriteString(tw, body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	_, err := d.output(ctx, &b, "exec", "-i", "--user", "999:999", id, "tar", "-xmf", "-", "--no-same-owner", "--keep-old-files", "-C", root)
	return err
}
func pitrExec(ctx context.Context, d Docker, id string, args ...string) ([]byte, error) {
	return d.output(ctx, nil, append([]string{"exec", "--user", "999:999", id}, args...)...)
}
func pitrCheckTools(ctx context.Context, d Docker, id string) (map[string]string, error) {
	versions := map[string]string{}
	for _, tool := range []string{"postgres", "pg_basebackup", "pg_verifybackup", "pg_waldump", "psql"} {
		b, err := pitrExec(ctx, d, id, tool, "--version")
		if err != nil || strings.TrimSpace(string(b)) != tool+" (PostgreSQL) 18.6 (Debian 18.6-1.pgdg12+2)" {
			return nil, errors.New("PITR requires exact pinned PostgreSQL 18.6 utilities")
		}
		versions[tool] = strings.TrimSpace(string(b))
	}
	return versions, nil
}

func retainPITRLogs(ctx context.Context, i PITRInventory) error {
	k, err := pitrLoadKeys(i)
	if err != nil {
		return err
	}
	d := Docker{i.Endpoint, i.Engine}
	for _, r := range []Resource{i.Source, i.Restore} {
		var b bytes.Buffer
		if err = d.command(ctx, nil, &b, 128<<10, "cp", r.ID+":/var/lib/postgresql/themis-logs/server.log", "-"); err != nil {
			if r.Role == "restore" {
				continue
			}
			return err
		}
		tr := tar.NewReader(&b)
		h, e := tr.Next()
		if e != nil || h.Name != "server.log" || h.Typeflag != tar.TypeReg || h.Size > 65536 {
			return errors.New("bounded PostgreSQL logs unavailable")
		}
		body, e := io.ReadAll(tr)
		if e != nil {
			return e
		}
		sanitized := strings.ReplaceAll(string(body), k.Password, "[REDACTED]")
		if err = pitrPublish(filepath.Join(i.Directory, "pitr-"+r.Role+".postgres.log"), strings.NewReader(sanitized), 65536); err != nil {
			return err
		}
	}
	return nil
}
