# Disposable PostgreSQL logical recovery

T3.0 is a separate, experimental local Docker workflow. Chaos Mesh remains
planning-only: final-actuator Pod UID binding and independent fault expiry are
still blocked. The Kubernetes controller and all existing CLIs are unchanged.
The local HTTP CLI continues to work without Docker or PostgreSQL.

`themis-postgres` can create one source and one distinct restore server, both
owned by a new experiment. It has no existing-server, discovery, SQL, DSN,
cloud, Kubernetes, physical backup, PITR or failover interface.

## Build and run

Requires Go 1.26.9, Docker CLI and a local Linux Docker engine with linux/amd64
support. Supported endpoints are the Docker Desktop Linux named pipe on Windows,
or `/var/run/docker.sock`, `/run/docker.sock` and the current user's
`.docker/desktop/docker.sock` on Unix. TCP and SSH endpoints are rejected,
including loopback TCP. An explicit original engine ID is mandatory.

PowerShell example (replace the engine ID with your verified local engine ID):

```powershell
go build -trimpath -o bin/themis-postgres.exe ./cmd/themis-postgres
$endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
docker --host $endpoint info --format '{{.ID}}'
docker --host $endpoint pull docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c
$state = "$PWD/.themis/postgres-example"
bin/themis-postgres.exe setup --state $state --endpoint $endpoint --engine-id ORIGINAL_ENGINE_ID
bin/themis-postgres.exe plan --state $state --contract examples/postgres-recovery/healthy.json
# Review the complete private plan and exact identities before approval.
$plan = Get-Content "$state/plan.json" -Raw | ConvertFrom-Json
bin/themis-postgres.exe approve --state $state --expect-digest $plan.digest
bin/themis-postgres.exe run --state $state
bin/themis-postgres.exe reconcile --state $state
bin/themis-postgres.exe replay --state $state
```

Invoke the compiled binary for actual exit codes: PASS 0, invalid/denied command
2, measured FAIL 3, INCONCLUSIVE 4, CLEANUP_PENDING 7. `go run` wraps program
exits. Setup requires a new state directory. Approval permits starting within 30
seconds, executing within 150 seconds; the run also has a 120-second deadline.
Cleanup authority is separate and expires 30 minutes after setup. Reconciliation
after that expiry requires manual review; it does not silently renew authority.
Keep runs short and reconcile immediately after interruption.

`dumpExit` and `restoreExit` record the Docker exec client process exit. A normal
successful exec propagates the PostgreSQL tool's result. On cancellation or runner
death, the inner tool's terminal outcome can be unknown even after the client
exits; the run remains INCONCLUSIVE and cleanup proves resource removal separately.

Run each scenario with a **new setup** and its corresponding example contract:

| Scenario | Real experiment | Expected result |
| --- | --- | --- |
| healthy | Back up 16 acknowledged commits; restore all 16 | PASS / 0 |
| ack-loss | Back up 16, acknowledge 17–19, stop source, restore 16 | FAIL / 3 |
| missing-receipt | Withhold receipt 8 after actual acknowledgement | INCONCLUSIVE / 4 |
| cleanup-denied | Withhold immediate cleanup under synthetic policy | INCONCLUSIVE, CLEANUP_PENDING / 7 |

The last case is a deliberate local cleanup-policy denial, **not** a simulated
Docker authorization error. `reconcile` performs actual cleanup afterward and
publishes a new receipt. It never rewrites the original journal or report.

## Identity, authorization and limits

Setup is explicit installation authority. It pins PostgreSQL 18.6-bookworm by
OCI index digest, records the actual local image ID, and creates a dedicated
internal bridge network, two exact 64-hex container IDs and two random named
volumes. Containers run as UID/GID 999, without capabilities or host ports, with
a read-only root, no-new-privileges, no restart policy, one CPU, 256 MiB RAM and
64 PIDs. Each data volume is a local-driver tmpfs capped at 128 MiB. `/tmp`
and the PostgreSQL socket directory have separate 16 MiB/1 MiB caps. PostgreSQL
connection count, statement/lock/idle-transaction time and temporary files are
bounded. Every Docker subprocess has a 20-second limit and bounded stdout.
The backup is limited to 8 MiB. SQL and diagnostics are never exported as errors.

Passwords are random per server and delivered through a tar stdin stream into
the already-mounted private volume, with UID 999 and mode 0600. Only password
file paths appear in container configuration. A fixed startup wait exits after
30 seconds if delivery fails. Connections use authenticated loopback TCP inside
each container; there are no host port mappings. The internal bridge is owned
but carries no database connection traffic.

The private inventory binds original actor, absolute directory, endpoint, engine,
network ID, container IDs, image, volume creation identity, database name,
PostgreSQL system identifiers and postmaster boot timestamps. System IDs must
differ. Revalidation rejects restarted or substituted databases. Plans snapshot
this inventory and the complete contract. Their digest is domain-separated
SHA-256 over versioned compact typed Go JSON with an empty digest field; this
is **not** RFC 8785 canonical JSON. Changes require a new plan and approval.

A PostgreSQL-specific Ed25519 authorization binds that digest, exact operation
set and expiry. Its private signer stays on the host and is independent of the
COMMIT receipt signer and earlier local/Kubernetes authorizations. Approval is
an explicit local operator action, not a two-person or remote approval system.
The OS actor and Docker daemon administrator are trusted. Possession of a Docker
socket is broad host authority; the adapter cannot confine a malicious operator.

## Measurements and verdicts

Fixed application DDL creates constrained transaction, account and health tables.
Each ordered transaction inserts a deterministic payload and transfers one unit
between accounts. The host publishes a signed receipt only after the matching
transaction output and final `COMMIT` command acknowledgement arrive with exit 0.
The receipt binds plan, transaction ID, payload, PostgreSQL XID, monotonic
acknowledgement offset and previous receipt hash. A dropped acknowledgement is
uncertain, never a successful receipt. Receipts live outside both databases.

The adapter executes authenticated `pg_dump -Fc -Z0`, syncs and exclusively
publishes the archive, checks size/header/SHA-256, and binds a signed private
backup attestation to source, destination and plan. `pg_restore --list` checks
table inventory. The complete bytes are checked again immediately before actual
single-transaction restore into an empty destination. A listable archive alone
does not prove recovery. PostgreSQL documents custom archive behavior in
[pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html) and transactional
restore/error handling in [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html).

The declared outage anchor is **observed exact source container shutdown**.
Stopping it also discards its tmpfs data. Restore-to-readiness includes destination
identity/emptiness checks, archive verification, restore, schema comparison,
row/account checks and a committed health update with a subsequent read.
It excludes provisioning, backup and the source stop request itself. Elapsed
time uses Go's monotonic clock in the same process. It is a single-host synthetic
restore measurement, not production RTO, automated failover or recovery from
host/storage failure.

The verifier reloads the durable signed host receipts, compares every restored ID
and payload, checks duplicates, unexpected IDs, gaps, account conservation and
schema/constraint definitions. Missing trustworthy acknowledged IDs quantify
data loss. Complete coverage is required to call that count exact; otherwise
reported loss is only a proven lower bound. The recovery point is the contiguous
acknowledged prefix present with matching payload, not the highest sequence.
The acknowledgement-time gap ends at the last retained commit in this synthetic
window; it is not a PITR or backup-age estimate. Transaction IDs with invalid or
missing receipts are explicitly uncertain.

All required assertions need sufficient evidence for PASS, including cleanup and
no unresolved ambiguity. Inclusive limits pass at equality. Credible integrity,
data-loss or measured time violations yield FAIL even if other evidence is
incomplete. A failed command alone yields INCONCLUSIVE. CLEANUP_PENDING is an
operational disposition separate from the correctness verdict.

## Durability, recovery and provenance

Protected owner-only files use the existing localstate implementation. Setup
persists intent before creates and acknowledged identities immediately afterward.
The one-use invocation is consumed before effects. An OS-held lock prevents
reconciliation while a live runner owns the experiment; death releases the lock.
There is no operation retry or ambiguous restore resume.

Execution journal records are bounded, sequenced, hash-chained, append-only and
synced. A short write or sync error permanently poisons the writer. Cleanup uses
the original protected inventory independently of the journal and run deadline.
Deletion verifies original engine, exact IDs, labels and resource configuration,
then observes absence with successful bounded list calls. Docker errors are never
treated as NotFound. Cleanup removes only these containers, volumes and network;
it does not prune. Repeated cleanup is safe. Named Docker volumes lack immutable
UIDs: name, creation time, options and ownership labels are checked, but Docker
admin races between inspect and remove cannot be fenced atomically. No unattended
janitor, daemon-offline cleanup, power-loss durability or persistent volume backup
guarantee is claimed. A lost create acknowledgement requires manual review;
the reconciler never guesses an identity from a name or label.

Historical reports remain immutable. Offline replay checks plan/journal structure
but always returns INCONCLUSIVE with unverified whole-run provenance, even for a
historical candidate PASS. Individual receipt signatures authenticate those
bytes under their embedded key; they do not attest honest sensor execution,
external key identity, whole-run completeness or current resource state. The
complete T4 signing service is deferred.

Keep `.themis` private: it contains backup data, credentials in live Docker
volumes, authorization and signing keys. Export only synthetic reports, journals,
public verification keys and reviewed identity summaries. Never archive the raw
state directory or database volume. Password file permissions follow
[libpq's password-file rules](https://www.postgresql.org/docs/18/libpq-pgpass.html).
The hard tmpfs cap uses Docker's
[local volume driver options](https://docs.docker.com/engine/storage/volumes/).

## Developer validation

Ordinary `go test ./...` runs pure adversarial, serialization, receipt, threshold
and journal storage tests. Docker tests explicitly skip unless opted in. To run
the real suite after pulling the pinned image:

```powershell
$env:THEMIS_POSTGRES_DOCKER='1'
$env:THEMIS_POSTGRES_ENDPOINT='npipe:////./pipe/dockerDesktopLinuxEngine'
$env:THEMIS_POSTGRES_ENGINE='ORIGINAL_ENGINE_ID'
$env:THEMIS_POSTGRES_TEST_STATE="$PWD/.themis/postgres-tests"
$env:THEMIS_POSTGRES_EVIDENCE="$PWD/.cache/postgres-evidence"
go test -count=1 -v -timeout=12m ./internal/postgres -run TestRealPostgres
```

Unix uses its admitted socket and an owner-only ext4 state directory. Tests
create only random Themis-owned resources. Real negative tests alter only their
own synthetic data, archives or containers. Interruption tests observe actual
`pg_dump` / `pg_restore` processes before cancellation or killing the runner.
Use the execution evidence archive for observed results and any failed attempts;
test source or skipped test names are not evidence of live execution.
## Separate durable workflow

T3.1's [persistent-volume and SIGKILL workflow](postgres-durable-recovery.md)
has a different version, two approval scopes, durable archive identity and a
different explicit recovery-time anchor. The temporary-storage commands and
contracts documented above retain their existing behavior and formats.
