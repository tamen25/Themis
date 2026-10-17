# T071: Owned two-instance replication and explicit failover

Status: T3.3 implementation design; verification evidence required before release.

One concrete `replication` command namespace uses a new version, immutable plan,
prepared-state seal and separate keys/scopes for preparation, primary termination,
standby promotion, host COMMIT receipts and cleanup. Existing recovery formats,
Kubernetes permissions and disabled Chaos Mesh execution remain unchanged.

Setup creates a primary and genuine `pg_basebackup` physical standby on distinct
persistent local volumes and one internal bridge, with no published ports. Pin
the existing PostgreSQL 18.6 Linux/amd64 image and tools. A dedicated SCRAM
replication role, exact peer addresses and private passfile authorize streaming;
passwords travel only over process stdin/private files. No public DSN, SQL,
endpoint, shell, configuration or workload extension is accepted.

Use `FIRST 1 (themis_standby)` and transaction-local `remote_apply`. Verify effective
settings, physical identity, distinct original boots, sender/receiver addresses,
streaming/sync state and received/flushed/replayed LSNs. Publish host receipts
only after matching real COMMIT acknowledgements, then independently verify
standby contents and replay coverage. No slots or archive are enabled; fixed
workload, deadlines, per-file hard limits and measured disk/WAL guards bound
consumption. Persistent local-driver volumes have no claimed filesystem quota.

After preparation, separately review the same sealed state for termination and
promotion approvals. Neither approval alone permits the sequence. Bind one
invocation, original identities, budgets, acknowledgement evidence, exact SIGKILL
and the fencing prerequisite. Persist intent before each effect; never retry or
resume an ambiguous termination, fence or promotion.

Fencing is stronger than a successful kill response: verify the unchanged original
primary stopped with PID zero, exit 137, no OOM and restart policy `no`, remove
only that stopped original container under the explicit termination scope, then
independently observe its absence. Freshly recheck absence and the exact original
standby before promotion. Removal does not remove the persistent source volume.
The original container ID cannot restart. Trusted Docker administrators can
recreate resources or bypass this design; no Byzantine or production split-brain
claim is made. Unproven fencing forbids promotion and PASS.

Promotion uses PostgreSQL `pg_promote`, but success additionally requires recovery
ended, the original system/boot, timeline 2 with timeline-1 ancestry, intact
acknowledged application state and an actual committed health write/read. One
runner monotonic clock records last primary write availability through promoted
write readiness. Compare the full uncertainty interval: PASS when its upper
bound meets the limit, credible FAIL when its lower bound exceeds the limit,
otherwise INCONCLUSIVE. Exact missing acknowledgement IDs are separate from
unknown time-based RPO. No asynchronous-loss result is fabricated.

Cleanup uses sealed original inventory and a separate capability, independently
of journals or preparation evidence, after process death as well. It preflights
all original resources, observes absence and publishes new receipts without
rewriting history. Offline replay never authenticates whole-run PASS. Cancellation,
missing evidence, poisoned journals and unresolved cleanup remain conservative.

References: PostgreSQL 18 [standby setup and synchronous replication](https://www.postgresql.org/docs/18/warm-standby.html),
[acknowledgement modes](https://www.postgresql.org/docs/18/runtime-config-wal.html#GUC-SYNCHRONOUS-COMMIT),
[promotion](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-RECOVERY-CONTROL),
[fencing requirement](https://www.postgresql.org/docs/18/warm-standby-failover.html),
and [WAL retention limits](https://www.postgresql.org/docs/18/runtime-config-replication.html).
