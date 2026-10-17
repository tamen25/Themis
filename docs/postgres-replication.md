# Disposable PostgreSQL streaming replication and controlled failover

T3.3 adds `themis-postgres replication`. It creates one new primary and one genuine
physical streaming standby. It does not change logical restore or named-target
PITR, implement asynchronous failover, elect a leader or accept an existing target.
The only supported environment is an owned disposable local synthetic pair.

## Setup and trust boundary

Use the original explicit local Docker socket and engine ID. The exact image is
`docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c`.
Setup requires this Linux/amd64 image already installed, with PostgreSQL and tools
reporting `18.6 (Debian 18.6-1.pgdg12+2)`. No mutable-tag or automatic pull fallback
exists. Never copy another experiment's private directory or authorization.

Setup records exact container IDs, two separate persistent local-driver volumes
and their creation identities, a dedicated internal bridge, original actor,
absolute protected directory, image/configuration hashes and container/postmaster
boots. No database port is published. `pg_basebackup -Fp -Xstream --no-slot` makes
the physical clone, then `pg_verifybackup` checks it before standby startup.
System identifiers must match; container, volume and postmaster identities differ.
Neither names nor labels alone authorize an operation.

A fixed dedicated `themis_repl` LOGIN/REPLICATION role authenticates through SCRAM.
The primary's reviewed HBA permits replication only from the original standby's
private IPv4 address. Private passfiles and fixed `primary_conninfo` contain the
generated credentials. They never appear in Docker command arguments or exported
evidence. Admin SQL runs only over each exact container's loopback interface.
There is no public SQL, DSN, address, configuration or Docker-command interface.

Each container runs as 999:999 with a read-only root, all capabilities dropped,
no-new-privileges, restart disabled, CPU 1, memory/swap 256 MiB and PIDs 64. Temporary
mounts and Docker logs are bounded. WAL segments are 1 MiB; each file has a hard
8 MiB limit. The database is limited to a measured 16 MiB, each volume to a measured
128 MiB, WAL to a measured 32 MiB, and filesystem free space must exceed 512 MiB.
The workload has exactly 20 fixed transactions. Slots are disabled, archiving is
off, `wal_keep_size` is 4 MiB, and sender/receiver/statement/transaction/tool/run
deadlines are finite. A disconnected standby cannot pin WAL through a slot.

These are closed-workload and measured storage guards, **not a filesystem-wide
persistent-volume quota**. `max_wal_size` is soft. The local OS actor, pinned
software, Docker daemon and administrator remain trusted. No power-loss, disk-loss,
production split-brain prevention or mutually untrusted tenant isolation is claimed.

## Synchronous acknowledgement and approval

Preparation configures `FIRST 1 (themis_standby)` and requires effective
`synchronous_commit=remote_apply`, fsync and full-page writes. It observes the
exact sender user/application/address, streaming and sync states, receiver peer,
read-only recovery, unpaused replay and sent/write/flush/replay positions. A file
mentioning synchronous replication is insufficient. PostgreSQL documents these
[acknowledgement semantics](https://www.postgresql.org/docs/18/runtime-config-wal.html#GUC-SYNCHRONOUS-COMMIT)
and [standby behavior](https://www.postgresql.org/docs/18/warm-standby.html).

Each fixed transaction sets transaction-local `remote_apply`. Only successful
matching COMMIT output and tool exit produce an exclusive durable host receipt.
The fixed bounded SQL helper rejects any PostgreSQL diagnostic, including warnings
that a synchronous wait was interrupted even though `COMMIT` was printed. Such
outcomes remain ambiguous and publish no receipt.
Receipts bind payload, XID, mode, observed WAL flush LSN, process clock session,
order, plan and previous hash under a host-only ledger key. Preparation independently
reads the standby rows/XIDs/schema/balances and checks replay coverage. A signed
prepared digest binds this evidence, original inventory and a random invocation.

Preparation, termination, promotion and cleanup have distinct signature keys and
scopes. T3.0/T3.1/PITR grants cannot authorize failover. The operator separately
reviews and approves termination/fencing and promotion against the prepared
digest. A plan or preparation grant permits neither. Start approvals last 30
seconds, execution expires 150 seconds after issuance and has a 120-second runtime
cap. Cleanup has independent 30-minute authority and a 45-second operation budget.
This is separate capability scope under one trusted operator, not independent
human approval or T4 whole-run attestation.

## Fencing, promotion and measurement

The one-use runner persists intent, validates the current journal, rechecks both
original identities, synchronous evidence, receipt coverage and approvals, and
verifies a final committed primary health write/read. It invokes one SIGKILL
against the full primary ID. A successful API reply is insufficient: independently
observe the original stopped state, PID 0, exit 137, unchanged boot, no OOM and
restart policy `no`. Persist another intent and remove only that stopped original
container. A successful independent absence call is required before promotion.
Its persistent data volume remains until cleanup. The original container ID can
no longer restart. A trusted administrator can recreate resources or bypass this
boundary; this is not Byzantine fencing. PostgreSQL's
[failover documentation](https://www.postgresql.org/docs/18/warm-standby-failover.html)
explains the competing-primary hazard.

Promotion requires its own unexpired approval, a durable one-time claim, valid
intent journal, freshly observed primary absence and the exact original read-only
standby with sufficient received/replayed WAL. `pg_promote(true,10)` is used as
[documented](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-RECOVERY-CONTROL).
Its success alone never passes: independently observe recovery ended, current WAL
timeline 2, timeline-1 ancestry covering acknowledged WAL, unchanged system/boot,
correct application state and a new committed health write/read. Check primary
absence again. Checkpoint metadata may still describe an older checkpoint;
current WAL and the timeline history establish the new active timeline.

One runner monotonic clock records intent, last verified primary write availability,
termination outcome, independently observed stop, fencing, promotion and promoted
write readiness. The last-primary-query-start to readiness is the conservative
upper duration; observed-stop-end to readiness is the lower duration. PASS requires
the upper bound <= the limit. FAIL requires the lower bound > the limit. A limit
inside the uncertainty interval is INCONCLUSIVE. No cross-process monotonic clocks
are subtracted. Exact missing/duplicate/corrupt/unexpected IDs and the contiguous
acknowledged recovery prefix are separate from the unknown time-based RPO.

The endpoint is the completion of the first successful committed health write/read,
recorded before subsequent identity/absence/storage checks. Those checks still
gate PASS. The objective measures time to verified readiness, including runner and
observation overhead; it does not identify an unobserved instant when PostgreSQL
first became writable or claim a production application outage duration.

The four contracts exercise healthy PASS, a real timing violation against 1 ms
without artificial delay, missing host receipt coverage after fencing (promotion
withheld), and withheld immediate cleanup. No asynchronous data loss is claimed.

## Commands and evidence

```powershell
go build -o bin/ ./cmd/themis-postgres
$state = "$PWD/.themis/replication-demo"
$endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$engine = docker --host $endpoint info --format '{{.ID}}'
bin/themis-postgres replication setup --state $state --endpoint $endpoint --engine-id $engine
bin/themis-postgres replication plan --state $state --contract examples/postgres-replication/healthy.json
# Review the full plan; substitute its actual digest.
bin/themis-postgres replication approve-prepare --state $state --expect-digest PLAN_DIGEST
bin/themis-postgres replication prepare --state $state
# Separately review actual replica/receipt evidence and the prepared digest.
bin/themis-postgres replication approve-termination --state $state --expect-digest PREPARED_DIGEST
bin/themis-postgres replication approve-promotion --state $state --expect-digest PREPARED_DIGEST
bin/themis-postgres replication run --state $state
bin/themis-postgres replication reconcile --state $state
bin/themis-postgres replication replay --state $state
```

Linux uses an explicitly admitted original Unix Docker socket. Exit codes: live
PASS 0, measured FAIL 3, INCONCLUSIVE 4, CLEANUP_PENDING 7, admission/request error 2.
Reconciliation never restarts, resumes or promotes a database. It needs the sealed
original inventory and separate unexpired cleanup capability, preflights every
original resource and independently observes absence. Missing identity or API
access remains unresolved. Docker has no atomic immutable volume UID deletion
fence; trusted administration remains an assumption. Partial setup retains
acknowledged create records for explicit review; it never discovers/adopts objects.

The journal is append-only and poisoned on write/sync failure. Cancellation,
ambiguous calls, journal damage and process death never resume destructive actions.
Cleanup survives damaged history and runner death; later immutable receipts never
rewrite historical reports/journals. Protected control state remains operator
managed. Raw database volumes, credentials, passfiles, keys, capabilities and
runtime inventory must not be exported. Selected receipts, observations, sanitized
logs and reports are suitable synthetic evidence. Offline replay always returns
INCONCLUSIVE with live trust false, even for a self-consistent forged PASS.

Run the portable suite normally. Real tests require `THEMIS_POSTGRES_DOCKER=1`,
`THEMIS_POSTGRES_ENDPOINT`, `THEMIS_POSTGRES_ENGINE`, and
`THEMIS_POSTGRES_TEST_STATE`; optional `THEMIS_POSTGRES_EVIDENCE` selects sanitized
exports. Run `go test -count=1 -v -timeout=20m ./internal/postgres -run TestRealReplication`.
Test logs distinguish real PostgreSQL/Docker/OS effects from controlled response
loss and injected journal corruption. Skips do not count as executed experiments.
