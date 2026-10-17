package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func replicationIP(v string) bool {
	a, e := netip.ParseAddr(v)
	return e == nil && a.Is4() && a.IsPrivate()
}
func replicationLabelsOK(v map[string]string, run, role string) bool {
	return len(v) == 3 && v[ownerLabel] == run && v["dev.themis.postgres.role"] == role && v["dev.themis.postgres.policy"] == ReplicationWorkflow
}
func replicationLabels(run, role string) []string {
	return []string{"--label", ownerLabel + "=" + run, "--label", "dev.themis.postgres.role=" + role, "--label", "dev.themis.postgres.policy=" + ReplicationWorkflow}
}
func replicationServerArgs(role string) []string {
	a := durableServerArgs()
	a = append(a, "-c", "listen_addresses=*", "-c", "wal_level=replica", "-c", "max_wal_senders=3", "-c", "max_replication_slots=0", "-c", "wal_keep_size=4MB", "-c", "max_slot_wal_keep_size=4MB", "-c", "archive_mode=off", "-c", "hot_standby=on", "-c", "wal_sender_timeout=5000", "-c", "wal_receiver_timeout=5000", "-c", "wal_receiver_status_interval=1s", "-c", "synchronous_commit=remote_apply")
	a = append(a, "-c", "transaction_timeout=10000", "-c", "logging_collector=on", "-c", "log_directory=/var/lib/postgresql/themis-logs", "-c", "log_filename=server.log", "-c", "log_rotation_age=0", "-c", "log_rotation_size=0")
	if role == "standby" {
		a[1] = pitrGate
		a = append(a[:3], a[4:]...)
		a = append(a, "-c", "config_file=/var/lib/postgresql/themis-replication/standby.conf")
	}
	return a
}
func replicationProfile(c durableContainer) string {
	c.State = durableContainer{}.State
	c.RestartCount = 0
	return digest("themis.postgres.replication.container-profile.v1", c)
}
func (d Docker) replicationVolume(ctx context.Context, i ReplicationInventory, r Resource) error {
	var v Volume
	if e := d.inspect(ctx, "volume", r.Volume.Name, &v); e != nil {
		return e
	}
	if digest("volume", v) != digest("volume", r.Volume) || !replicationLabelsOK(v.Labels, i.Run, r.Role) {
		return errors.New("original replication volume replaced")
	}
	return nil
}
func (d Docker) replicationNetwork(ctx context.Context, i ReplicationInventory) error {
	var v Network
	if e := d.inspect(ctx, "network", i.Network.ID, &v); e != nil {
		return e
	}
	if digest("network", v) != digest("network", i.Network) {
		return errors.New("original replication network changed")
	}
	return nil
}
func (d Docker) replicationContainer(ctx context.Context, i ReplicationInventory, r Resource, running, boot bool) (c durableContainer, err error) {
	if !hexID.MatchString(r.ID) {
		return c, errors.New("invalid exact replica ID")
	}
	if err = d.verifyEngine(ctx); err != nil {
		return c, err
	}
	if err = d.inspect(ctx, "container", r.ID, &c); err != nil {
		return c, err
	}
	h := c.HostConfig
	if c.ID != r.ID || c.Image != i.ImageID || c.Config.Image != Image || c.Config.User != "999:999" || !replicationLabelsOK(c.Config.Labels, i.Run, r.Role) || !slices.Equal(c.Config.Entrypoint, []string{"/bin/sh"}) || !slices.Equal(c.Config.Cmd, replicationServerArgs(r.Role)) || replicationProfile(c) != i.Profiles[r.Role] || !h.ReadonlyRootfs || h.Privileged || h.Memory != MemoryBytes || h.MemorySwap != MemoryBytes || h.NanoCpus != 1000000000 || h.PidsLimit != 64 || h.RestartPolicy.Name != "no" || len(h.PortBindings) != 0 || len(h.CapAdd) != 0 || len(h.Binds) != 0 || len(h.Devices) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges"}) || (running && (!c.State.Running || c.State.Pid <= 0)) || (boot && (c.RestartCount != 0 || c.State.StartedAt != i.Starts[r.Role])) {
		return c, errors.New("replication container identity, boot or safety profile mismatch")
	}
	if len(c.Mounts) != 1 || c.Mounts[0].Type != "volume" || c.Mounts[0].Name != r.Volume.Name || c.Mounts[0].Destination != "/var/lib/postgresql" || !c.Mounts[0].RW || len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks[i.Network.Name].NetworkID != i.Network.ID {
		return c, errors.New("replica mount or network mismatch")
	}
	if err = d.replicationVolume(ctx, i, r); err != nil {
		return c, err
	}
	return c, nil
}
func (d Docker) replicationTarget(ctx context.Context, i ReplicationInventory, r Resource) error {
	if _, e := d.replicationContainer(ctx, i, r, true, true); e != nil {
		return e
	}
	if e := d.replicationNetwork(ctx, i); e != nil {
		return e
	}
	id, e := d.databaseIdentity(ctx, r)
	if e != nil {
		return e
	}
	if id != r.DB {
		return errors.New("original replica database system or boot changed")
	}
	address, e := d.replicationAddress(ctx, r.ID, i.Network.ID)
	want := i.PrimaryIP
	if r.Role == "standby" {
		want = i.StandbyIP
	}
	if e != nil || address != want {
		return errors.New("original replica network address changed")
	}
	return nil
}
func (d Docker) replicationAddress(ctx context.Context, id, network string) (string, error) {
	var v struct {
		NetworkSettings struct {
			Networks map[string]struct{ NetworkID, IPAddress string }
		}
	}
	if e := d.inspect(ctx, "container", id, &v); e != nil {
		return "", e
	}
	if len(v.NetworkSettings.Networks) != 1 {
		return "", errors.New("unexpected replica network")
	}
	for _, n := range v.NetworkSettings.Networks {
		if n.NetworkID == network && replicationIP(n.IPAddress) {
			return n.IPAddress, nil
		}
	}
	return "", errors.New("replica private address not observed")
}

type ReplicationObservation struct {
	Primary, Standby                                                                                                 DBIdentity
	SynchronousStandbyNames, SynchronousCommit, SenderState, SyncState, SenderUser, SenderApplication, SenderAddress string
	CurrentLSN, SentLSN, WriteLSN, FlushLSN, ReplayLSN                                                               string
	ReceiverState, ReceiverHost                                                                                      string
	ReceiverPort                                                                                                     int
	ReceivedLSN, ReplayedLSN                                                                                         string
	InRecovery, ReadOnly, Fsync, FullPageWrites, PrimaryWritable, ReplayPaused, AuthenticationVerified               bool
	Slots                                                                                                            int
}

func observeReplication(ctx context.Context, d Docker, i ReplicationInventory) (o ReplicationObservation, err error) {
	for _, r := range i.resources() {
		if err = d.replicationTarget(ctx, i, r); err != nil {
			return o, err
		}
	}
	o.Primary, o.Standby = i.Primary.DB, i.Standby.DB
	v, err := d.replicationSQL(ctx, i.Primary.ID, `SELECT json_build_object('SynchronousStandbyNames',current_setting('synchronous_standby_names'),'SynchronousCommit',current_setting('synchronous_commit'),'AuthenticationVerified',coalesce((SELECT rolreplication AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE rolname='themis_repl'),false) AND (SELECT count(*)=3 AND bool_and(auth_method='scram-sha-256' AND error IS NULL) FROM pg_hba_file_rules),'PrimaryWritable',NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off','Fsync',current_setting('fsync')='on','FullPageWrites',current_setting('full_page_writes')='on','Slots',(SELECT count(*) FROM pg_replication_slots),'SenderState',r.state,'SyncState',r.sync_state,'SenderUser',r.usename,'SenderApplication',r.application_name,'SenderAddress',host(r.client_addr),'CurrentLSN',pg_current_wal_lsn()::text,'SentLSN',r.sent_lsn::text,'WriteLSN',r.write_lsn::text,'FlushLSN',r.flush_lsn::text,'ReplayLSN',r.replay_lsn::text) FROM pg_stat_replication r;`)
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal([]byte(v), &o); err != nil {
		return o, errors.New("WAL sender observation missing or ambiguous")
	}
	var receiver struct {
		ReceiverState, ReceiverHost, ReceivedLSN, ReplayedLSN string
		ReceiverPort                                          int
		InRecovery, ReadOnly, ReplayPaused                    bool
	}
	v, err = d.replicationSQL(ctx, i.Standby.ID, `SELECT json_build_object('ReceiverState',status,'ReceiverHost',sender_host,'ReceiverPort',sender_port,'ReceivedLSN',pg_last_wal_receive_lsn()::text,'ReplayedLSN',pg_last_wal_replay_lsn()::text,'InRecovery',pg_is_in_recovery(),'ReadOnly',current_setting('transaction_read_only')='on','ReplayPaused',pg_get_wal_replay_pause_state()<>'not paused') FROM pg_stat_wal_receiver;`)
	if err != nil {
		return o, err
	}
	if json.Unmarshal([]byte(v), &receiver) != nil {
		return o, errors.New("WAL receiver observation missing or ambiguous")
	}
	o.ReceiverState, o.ReceiverHost, o.ReceiverPort = receiver.ReceiverState, receiver.ReceiverHost, receiver.ReceiverPort
	o.ReceivedLSN, o.ReplayedLSN = receiver.ReceivedLSN, receiver.ReplayedLSN
	o.InRecovery, o.ReadOnly = receiver.InRecovery, receiver.ReadOnly
	o.ReplayPaused = receiver.ReplayPaused
	return o, nil
}

func retainReplicationLog(ctx context.Context, i ReplicationInventory, r Resource) error {
	k, err := loadReplicationKeys(i)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	d := Docker{i.Endpoint, i.Engine}
	if err = d.command(ctx, nil, &b, 128<<10, "cp", r.ID+":/var/lib/postgresql/themis-logs/server.log", "-"); err != nil {
		return errors.New("bounded PostgreSQL log observation unavailable")
	}
	tr := tar.NewReader(&b)
	h, err := tr.Next()
	if err != nil || h.Name != "server.log" || h.Typeflag != tar.TypeReg || h.Size > 65536 {
		return errors.New("bounded PostgreSQL log shape invalid")
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return err
	}
	body := strings.ReplaceAll(strings.ReplaceAll(string(data), k.Password, "[REDACTED]"), k.ReplicationPassword, "[REDACTED]")
	return pitrPublish(filepath.Join(i.Directory, "replication-"+r.Role+".postgres.log"), strings.NewReader(body), 65536)
}

type ReplicationStorage struct {
	StorageObservation
	WALBytes int64
}

func (d Docker) replicationBudget(ctx context.Context, r Resource) (s ReplicationStorage, err error) {
	s.StorageObservation, err = d.durableBudget(ctx, r)
	if err != nil {
		return s, err
	}
	v, err := d.replicationSQL(ctx, r.ID, "SELECT coalesce(sum(size),0)::bigint FROM pg_ls_waldir();")
	if err != nil {
		return s, err
	}
	s.WALBytes, err = strconv.ParseInt(v, 10, 64)
	if err != nil || s.WALBytes < 1 || s.WALBytes > 32<<20 {
		return s, errors.New("replication WAL storage budget unverified")
	}
	return s, nil
}

// A canceled synchronous wait can print COMMIT plus a warning. Do not discard
// that diagnostic and then assert remote acknowledgement. The fixed helper
// retains stderr only in private bounded tmpfs, rejects any diagnostic, and
// removes the file. SQL and credentials never enter shell or Docker argv.
const replicationPSQL = `set -u
umask 077
f=$(mktemp /tmp/themis-psql.XXXXXX) || exit 70
trap 'rm -f -- "$f"' EXIT HUP INT TERM
timeout --signal=TERM --kill-after=1 12 psql -X -w -v ON_ERROR_STOP=1 -At -h 127.0.0.1 -p 5432 -U themis -d themis_recovery 2>"$f"
r=$?
[ "$r" -eq 0 ] && [ ! -s "$f" ]
`

func (d Docker) replicationSQL(ctx context.Context, id, sql string) (string, error) {
	b, err := d.output(ctx, strings.NewReader(sql), "exec", "--user", "999:999", "-i", id, "/bin/sh", "-c", replicationPSQL)
	return strings.TrimSpace(string(b)), err
}
