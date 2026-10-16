# T034: Separate cleanup inventory, current state and historical outcome

Status: Implemented for owned Kind T2.1; pending independent review.

Persist an owner-only inventory and authorization before creating a synced
append-only journal. Establish baseline first. Sync intent, then freshly
revalidate API/fixture identity immediately before Apply. Keep no-Apply, known
receipt and lost-acknowledgement uncertainty distinct. A failed writer is
poisoned and never repaired or resumed.

Remove has an independent timeout/context. A signed inactive resource receipt,
fresh identity checks and separate recovery probes establish cleanup and
recovery independently. Failed immediate cleanup yields CLEANUP_PENDING/exit 7
and blocks PASS. The fixture still expires the effect independently.

An OS-held liveness lock prevents reconciliation from racing a live runner. It
protects local coordination only; it grants no Kubernetes authority. After death,
reconciliation uses the protected inventory even when the journal is corrupt,
authenticates the original fixture and cleanup key, observes current resource
state and recovery, and writes a new immutable receipt. Historical journal/report
bytes and verdict never change. The preinstalled workload remains; cleanup means
the bounded fault is inactive/fenced, not that the test application was deleted.

There is no automatic execution resume, replacement target adoption, PID-based
cleanup, Kubernetes finalizer or fault resource. Missing inventory, expired
cleanup authority, replacement or unreachable fixture stays unresolved. Whole
environment teardown uses the installer's owned-cluster UID guard separately.
