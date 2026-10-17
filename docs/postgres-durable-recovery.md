# Durable logical recovery with an unclean source failure

T3.1 adds `themis.postgres-durable/v1alpha1`, workflow
`pg-logical-persistent-sigkill-v1`, alongside the unchanged T3.0 temporary-volume
workflow. Only newly created, synthetic local Docker PostgreSQL 18.6 databases
are admitted. No existing server, hostname, DSN, arbitrary SQL, host bind mount,
Kubernetes target, physical backup, WAL archive, PITR or failover is supported.

## Safety and storage

Supply the admitted local socket and the original engine ID explicitly. Setup
creates a random internal bridge, two separate named **local-driver persistent
volumes with no options**, and two non-root containers using the existing pinned
PostgreSQL image. Source and destination system IDs must differ. Admission binds
the original OS actor, private directory, full container IDs, image identity,
labels, original postmaster/container boots, mount paths and volume creation
timestamps. No resource is adopted by label or name. Docker administration and
the original local OS actor are trusted; Docker offers no atomic volume-UID
precondition on removal.

Each container has CPU 1, memory/swap 256 MiB, PIDs 64, a read-only root,
all capabilities dropped, no-new-privileges, no published ports, restart disabled,
bounded socket/temporary tmpfs, and two rotated 1 MiB local log files. A hard
8 MiB **per-file** `RLIMIT_FSIZE` applies; WAL segments are 1 MiB. Fixed SQL and
at most 19 acknowledged synthetic commits keep the workload finite. Admission
and observations enforce database size <=16 MiB, measured volume use <=128 MiB,
backup <=8 MiB, expansion <=32 MiB, and free space >=512 MiB. Statements, locks,
tools and whole invocations have separate deadlines.

**Measured volume guards are not a filesystem-wide persistent-volume quota.**
Docker's default local driver on the tested Desktop engine does not supply one.
`max_wal_size` is a soft PostgreSQL setting. A hostile Docker administrator,
host filesystem exhaustion, daemon failure or OS crash can exceed this adapter's
assumptions. Failure to observe the budgets denies continuation. This mode proves
same-host retention after container termination/removal; it does not establish
power-loss, disk-loss, off-site or disaster durability.

## CLI and the two approvals

Build with `go build -o bin/ ./cmd/themis-postgres`. Substitute an actual local
engine ID; never copy another operator's private state or approval:

```powershell
$state="$PWD/.themis/durable-demo"
$endpoint='npipe:////./pipe/dockerDesktopLinuxEngine'
$engine='REPLACE_WITH_ORIGINAL_ENGINE_ID'
themis-postgres durable setup --state $state --endpoint $endpoint --engine-id $engine
themis-postgres durable plan --state $state --contract examples/postgres-durable/healthy.json
# Review the immutable plan and resource identities before approving.
themis-postgres durable approve-prepare --state $state --expect-digest PLAN_SHA256
themis-postgres durable prepare --state $state
# Review the validated publication and its actual SHA-256 before approving fault.
themis-postgres durable approve-failure --state $state --expect-digest PLAN_SHA256 --expect-backup-sha256 BACKUP_SHA256
themis-postgres durable run --state $state
themis-postgres durable reconcile --state $state
themis-postgres durable replay --state $state
```

Unix uses the explicitly admitted local socket and a private local filesystem.
`approve-prepare` grants only preparation. `approve-failure` binds SIGKILL once to
the actual published backup identity, size and digest; source container/system,
restore container, engine, endpoint, plan, database, deadlines and independent
cleanup deadline are signed. A T3.0 grant cannot authorize this workflow. Start
within 30 seconds of each approval. Execution expires after 150 seconds from
approval and has a 120-second runtime cap. Setup's cleanup capability expires
after 30 minutes; it does not require the execution grant or signing keys.

Every phase has a durable exclusive invocation claim. A consumed phase is never
resumed or retried. Interruptions require reconciliation and a fresh experiment.
The runner holds an OS lock; another process cannot reconcile while it runs.
If preparation fails, reconcile the owned setup explicitly before starting again.

## Backup publication and independent receipts

After each actual matching PostgreSQL COMMIT acknowledgement and successful
`psql` exit, a separate host-held Ed25519 key signs ID, payload, transaction XID,
sequence, prior receipt hash, process session, monotonic offset and descriptive
UTC time. The host reloads all receipts for evaluation. Missing, forged or
out-of-order receipts cannot establish complete coverage. A lost acknowledgement
produces no receipt, even if PostgreSQL actually committed.

Preparation runs exact pinned `pg_dump`/`pg_restore` versions and custom archive
format **PGDMP 1.16.0**, with a bounded complete archive expansion validation.
It writes to an exclusive private partial file in `state/backup-store`, syncs the
file, validates bytes, size, header and SHA-256, rechecks the live original source,
then publishes by exclusive hard link and synchronizes the directory where
supported. Signed metadata binds the stable OS file identity as well as content.
A signed final preparation seal commits the source schema, ledger head, journal
head and backup digest. Incomplete publication cannot authorize failure.

The exact private path is derived from the original setup. Replacement, even by
an identical-byte file with a different file identity, is refused. No external
archive is imported or adopted. Validation repeats before the fault, after source
termination, immediately before restore and after the tool completes. Raw backups
and databases stay private and are excluded from review archives.

## Failure, recovery and timing

The runner persists one-time intent and syncs the execution journal before the
only failure command: `docker container kill --signal KILL FULL_SOURCE_ID`.
It rechecks the exact target immediately before that effect. Docker command
acknowledgement and ambiguity are recorded separately. Successful acknowledgement
alone is insufficient: an independent inspect must observe the original source
not running, PID 0, exit 137, no OOM kill and unchanged boot identity. A bounded
copy of only `PG_VERSION` independently observes persistent source-volume bytes.
No whole data directory is copied. The source is never restarted for recovery.

Only the validated host archive is restored to the original independently fresh,
empty destination, using one PostgreSQL restore transaction. Verification checks
schema and constraints, exact IDs and payloads, missing/unexpected/duplicate/
corrupt rows, account conservation, and an actual committed health write followed
by a read. A command exit alone cannot prove recovered application readiness.

The contract's anchor is **`last-available-query-start-to-ready`**. One runner's
monotonic clock records durable intent, source availability query start/end,
kill invocation start/end, first verified unavailable observation start/end,
restore start, and verified ready. The threshold compares the conservative upper
interval from availability-query **start** to ready, including the identity
checks and failure observation between them. A separate lower observed interval
starts at the stopped observation's end; their difference bounds observation
uncertainty. Provisioning, backup preparation and approval waits precede this
interval; cleanup follows it. This differs explicitly from T3.0's observed-stop
to ready anchor. Neither is production failover or a physical recovery interval.

Preparation and failure execution can be different processes. Receipt offsets
are ordered only within each process session; clocks across sessions are never
subtracted. The time-based acknowledged-loss gap is therefore **unknown/null**.
The report gives exact acknowledged missing IDs/count when coverage permits and
the contiguous acknowledged recovery point. It does not claim production RPO.

## Scenarios, verdicts and cleanup

| Contract | Expected observation |
| --- | --- |
| `healthy` | 16 acknowledged rows restored; PASS requires complete evidence and cleanup |
| `ack-loss` | Real acknowledged commits 17–19 follow backup; restored archive lacks them: FAIL |
| `missing-receipt` | Actual receipt 8 withheld from verifier input; coverage missing: INCONCLUSIVE |
| `cleanup-denied` | Recovery measured, immediate cleanup withheld: INCONCLUSIVE / CLEANUP_PENDING |
| `inflight-crash` | Actual transaction 17 writes then waits before COMMIT; source killed; no fabricated acknowledgement: INCONCLUSIVE |

A credible violated guarantee remains FAIL when other evidence is missing.
Insufficient evidence, ambiguous termination, interruption or receipt uncertainty
cannot establish PASS. Exit codes are 0 PASS, 3 FAIL, 4 INCONCLUSIVE, 7 cleanup
pending, 2 invalid request/admission. Cleanup state remains separately reported.

Reconciliation reads the original protected sealed inventory and independent
signed cleanup capability. It does not reconstruct authority from a plan,
journal, report or imported bundle. It preflights all original identities before
the first deletion. A missing backup file or backup directory does not remove
cleanup authority. It writes its own durable intent, removes exact container IDs,
then their verified original volumes and network, and confirms absence through
successful Docker list calls. Errors never imply absence. Cleanup uses its own
deadline after cancellation and runner death. Restarted original containers are
refused for execution but remain removable by exact original cleanup authority.
No prune or unrelated resource removal exists.

Missing/corrupt final inventory or capability fails closed. A partial setup before
final sealed inventory publication requires manual review of its acknowledged
private installation records; unknown create acknowledgements are never guessed.
There is no autonomous janitor or daemon-offline cleanup guarantee. Reconciliation
retains raw backup, receipt and journal evidence and never changes the historical
report. Repeated reconciliation publishes fresh receipts without rewriting history.

Offline replay checks structure and signatures but always returns INCONCLUSIVE
with `liveTrustedExecution=false`. Embedded public keys, self-contained reports
and unsigned journals cannot establish externally trusted execution PASS. T4
whole-evidence signing and external trust-root binding remain deferred.

## Validation

Use the environment variables documented for [T3.0](postgres-recovery.md), with
new private state and evidence roots, then run:

```powershell
go test -count=1 -v -timeout=25m ./internal/postgres -run TestRealDurable
go test ./internal/postgres -run '^$' -fuzz '^FuzzDurableContract$' -fuzztime 10s
```

Ordinary `go test ./...` explicitly skips opt-in Docker tests. Real tests use
separate owned environments, actual SIGKILL, real commits, archive corruption,
partial restore input, observed tool cancellation, and an actual runner process
kill after source termination. Signed expiry fixtures and write-failure wrappers
are controlled tests, not host-clock changes or real filesystem power-loss tests.
Read the handoff's exact child commands/exits and failed attempts; test source or
skipped names are not proof of live execution. Future WAL/PITR/physical/failover
experiments need new contracts, authority scopes, sensors and timing semantics.

Primary references: [PostgreSQL shutdown](https://www.postgresql.org/docs/18/server-shutdown.html),
[pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html),
[pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html),
[Docker kill](https://docs.docker.com/reference/cli/docker/container/kill/),
[persistent volumes](https://docs.docker.com/engine/storage/volumes/).
