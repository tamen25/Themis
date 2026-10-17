# Disposable PostgreSQL physical backup and PITR

T3.2 adds `themis-postgres pitr` for one newly created, owned local Docker
environment. It is a separate versioned workflow, not a change to either logical
restore command. It accepts no existing database, connection string, user SQL,
archive destination, shell script, target name or timeline.

| Mode | Backup | Failure | Recovery |
| --- | --- | --- | --- |
| T3.0 default | `pg_dump` custom archive | Controlled stop, source tmpfs lost | Logical restore into another system identifier |
| T3.1 `durable` | Independent logical archive | Approved persistent source SIGKILL | Logical restore; no WAL replay |
| T3.2 `pitr` | Physical base backup plus retained WAL | Separately approved original source SIGKILL | Named target after backup completion, pause inspection, promotion |

## Fixed environment and authority

The pinned image is
`docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c`.
Only Linux/amd64 and server 180006 are admitted. `postgres`, `psql`,
`pg_basebackup`, `pg_verifybackup` and `pg_waldump` must report
`18.6 (Debian 18.6-1.pgdg12+2)`.
The exact image digest must already be present in the original engine; pull that
digest explicitly before setup on a fresh machine. Setup never pulls an image
automatically or substitutes a mutable tag.

Setup creates three exact containers and local persistent volumes: source,
destination, and archive/verifier. Source and destination share a new internal
bridge without host ports. The verifier has no network. All run as 999:999 with
a read-only root, dropped capabilities, no added devices or host mounts, one CPU,
256 MiB memory, 64 PIDs, an 8 MiB hard per-file limit, bounded tmpfs, and bounded
Docker logs. Mounting the image's PostgreSQL parent initializes private volume
ownership without a privileged initializer. The fresh destination waits in a
fixed gate; it never runs initdb.

The sealed private inventory pins actor, original absolute directory, socket,
engine ID, image, original container configuration/boot, all volume creation
identities and the internal network. Physical recovery **preserves the source
PostgreSQL system identifier**. Container ID, distinct volume and independently
observed postmaster boot establish destination independence instead.

Three different private keys authorize preparation/failure, sign COMMIT and
prepared artifact metadata, and authorize cleanup. Domain-separated formats
reject old logical grants. Preparation cannot authorize SIGKILL. Failure approval
reviews the final prepared digest, which binds the original inventory, actual
base file identity/hash, archive identities, ordered WAL hashes, receipt ledger,
target name/LSN/timeline and contract. Ambiguous or failed invocations are consumed
permanently. There is no automatic execution restart or grant renewal.

## Backup and archive protocol

Archiving is configured before workload transactions with fsync,
synchronous_commit and full_page_writes enabled. A fixed five-second archive
command accepts only generated WAL/history names, checks sizes, copies into an
exclusive partial file, compares bytes, syncs, links without replacement and syncs
the directory. An identical persisted file is the only acceptable repeat. Unknown
partial publications, missing segments and archival lag over ten seconds deny
preparation. An actual closed segment must parse before workload begins.

Sixteen real transactions precede the backup. `pg_basebackup -w -h 127.0.0.1
-U themis -D - -Ft -Xfetch --checkpoint=fast --manifest-checksums=SHA256` streams
at most 64 MiB to protected host storage. The adapter rejects unsafe paths, links,
devices, duplicate entries, unbounded files, tablespaces and recovery signals.
The manifest binds the actual source system identifier and required timeline-1
WAL range. Extraction into the owned verifier permits **full** `pg_verifybackup`
including required WAL parsing, without checksum or WAL skip options. This choice
follows the [PostgreSQL 18 backup tool](https://www.postgresql.org/docs/18/app-pgbasebackup.html)
and [verification tool](https://www.postgresql.org/docs/18/app-pgverifybackup.html)
documentation. Tool success alone is not recovery proof.

After backup completion, a segment switch forces the recovery target into WAL
outside the base backup. Transactions 17–20 commit, then PostgreSQL creates a
fixed generated restore point. The loss scenario acknowledges 21–23 after that
point. A later sentinel and explicit switch close the required archive sequence.
Every contiguous required 1 MiB segment, through the sentinel, is retained in
private host storage with hashes and OS file identity. Archive volume inode,
owner/mode/size and checksums are checked independently. `pg_waldump` parses the
suffix and observes the named point. A final signed seal publishes eligibility;
partial preparation never grants fault authority.

The archive script bounds its WAL directory to 32 MiB. Base expansion and host
archive are capped at 64 MiB; tar entries at 4096, path length at 192, each file
at 8 MiB, database at 16 MiB. Measured source, destination and verifier volume
usage must remain within 128 MiB with at least 512 MiB filesystem free space.
These closed-workload guards are **not a filesystem-wide persistent-volume
quota**. PostgreSQL's max_wal_size is a soft limit; a failing archive can retain
source WAL. The isolated fixed workload, command deadlines and resource guards
are the supported scope, not an arbitrary write workload. See PostgreSQL's
[archiving requirements](https://www.postgresql.org/docs/18/continuous-archiving.html).

## Target proof, application fidelity and acknowledged loss

After durable intent and fresh identity checks, exactly one Docker SIGKILL call
is allowed. The runner independently checks the unchanged original boot, stopped
state, PID 0, exit 137 and absence of OOM termination. It reopens and checks the
base, manifest and host WAL after source loss and rechecks the original archive.

The destination must still have no PGDATA. The base is extracted and fully
verified again before any recovery configuration is installed. Only approved WAL
bytes are copied into its own volume and checked there. A fixed restore command,
`recovery.signal`, exact generated target, timeline 1 and action `pause` start
actual archive recovery. The target proof requires SQL observations of recovery,
the paused state, **exact replay LSN**, and all target settings. Startup logs and
readiness alone cannot establish this proof.

While paused, independently read rows must match IDs 1–20, deterministic payloads
and original signed COMMIT XIDs (`xmin` in this fresh cluster), the exact schema
and constraints, and balances 9980/10020. Only then may replay resume. The runner
requires completed recovery, timeline 2 and a history record branching from
timeline 1 at the exact target LSN, then an actual committed health update and
subsequent read. PostgreSQL documents pause/resume semantics in its
[recovery target settings](https://www.postgresql.org/docs/18/runtime-config-wal.html#RUNTIME-CONFIG-WAL-RECOVERY-TARGET).

Target fidelity and acknowledged loss are different assertions. All signed host
receipts remain in scope, including post-target acknowledgements. Recovering
exactly to transaction 20 while losing acknowledged 21–23 is **FAIL** against the
zero-loss contract. Missing observations or target proof are INCONCLUSIVE.
An in-flight transaction has explicit uncertainty and no invented receipt.
Receipt offsets are comparable only within their process session; elapsed loss
time remains null. One runner monotonic clock bounds recovery between last
source availability query start and application readiness; the observed-stop
interval is the lower bound. Equality passes the declared time limit.

## Commands

Build with `go build -o bin/ ./cmd/themis-postgres`. Example in PowerShell:

```powershell
$state = Join-Path $PWD '.themis/pitr-healthy'
$endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$engine = docker --host $endpoint info --format '{{.ID}}'
bin/themis-postgres pitr setup --state $state --endpoint $endpoint --engine-id $engine
bin/themis-postgres pitr plan --state $state --contract examples/postgres-pitr/healthy.json
$plan = Get-Content (Join-Path $state 'pitr-plan.json') -Raw | ConvertFrom-Json
# Review the complete plan before approving preparation.
bin/themis-postgres pitr approve-prepare --state $state --expect-digest $plan.digest
bin/themis-postgres pitr prepare --state $state
$prepared = Get-Content (Join-Path $state 'pitr-prepared.json') -Raw | ConvertFrom-Json
# Independently review actual base/WAL/receipt/target metadata before SIGKILL.
bin/themis-postgres pitr approve-failure --state $state --expect-digest $prepared.Digest
bin/themis-postgres pitr run --state $state
bin/themis-postgres pitr reconcile --state $state
bin/themis-postgres pitr replay --state $state
```

Linux admits the explicit original local Unix Docker socket. There is no remote
Docker, DSN or automatic Docker context fallback. Approvals permit start for
30 seconds and at most 120 seconds of execution; each command is capped at
20 seconds. Preparation and execution each also have a 120-second process budget.
Cleanup uses its own 45-second context within a separate 30-minute capability.

Exit 0 means live PASS, 3 FAIL, 4 INCONCLUSIVE, 7 CLEANUP_PENDING, 2 admission or
request error. Healthy, ack-loss, missing-wal, cleanup-denied and inflight-crash
contracts demonstrate these boundaries. Cleanup pending is operational, not a
new application verdict. Offline replay always returns INCONCLUSIVE with live
trust false, even for a self-consistent forged report and replacement key.

## Cleanup, evidence and limitations

Reconciliation needs the protected sealed original inventory and separate cleanup
capability, never a valid journal, report or continued backup availability. It
preflights every extant original object before deletion, revalidates exact IDs,
and requires successful independent absence calls. Corrupt/missing inventory,
expired authority or failed Docker calls do not mean cleanup. Repeated cleanup
creates new receipts and preserves original report/journal bytes. Unacknowledged
setup creates require manual review; resources are never rediscovered/adopted.

Docker resources, including the archive/verifier volume, are removed. Protected
host base/WAL and control evidence are retained locally for review/replay and
remain the operator's retention responsibility. Do not upload that directory.
Share only sanitized PostgreSQL logs, manifests, segment metadata/hashes, public
keys, signed COMMIT receipts, journals, reports and cleanup observations. Raw
backups/WAL include database authentication data and must stay private.

This is a same-user trusted local experiment. The Docker administrator and local
key holder can bypass it; signatures do not attest honest sensors or whole-run
execution. There is no T4 trust service, power-loss durability claim, filesystem
quota, streaming replication, automated failover, cloud/existing target support
or production readiness claim. Chaos Mesh remains disabled and Kubernetes
permissions are unchanged.

Run `go test -count=1 ./...` for portable checks. Real tests require explicit
`THEMIS_POSTGRES_DOCKER=1`, `THEMIS_POSTGRES_ENDPOINT`,
`THEMIS_POSTGRES_ENGINE`, and `THEMIS_POSTGRES_TEST_STATE`; optional
`THEMIS_POSTGRES_EVIDENCE` exports selected sanitized evidence. Run
`go test -count=1 -v -timeout=20m ./internal/postgres -run 'TestRealPITR'`.
The tests distinguish real PostgreSQL/Docker/OS effects from pure parser,
threshold, signature and fault-injected storage checks. Docker skips are not
executed recovery demonstrations.
