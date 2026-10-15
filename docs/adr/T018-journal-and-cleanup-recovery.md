# T018: Durable intent and conservative reconciliation

Status: accepted for experimental T1.1 only.

A separate versioned state machine permits only defined transitions and ordered
phase samples. Before fault application, sync the exact approved plan and
redacted authorization, resource handle, target/proxy identity, lease expiry and
private fixture reference. Immutable records publish atomically without
replacement; event files are append-only with a sync after each event. Unix
directory entries are synced. Windows file flushes do not claim directory-fsync
or tested power-loss durability.

Claim is exclusive and apply is inspect-before-act, with retained receipts.
Missing acknowledgments remain ambiguous instead of being retried as new
effects. Replay revalidates inputs and derives verdicts from observations.
Partial/corrupt records cannot produce successful completion. No automatic
resume or reapplication exists.

Cancellation cleanup has a separate timeout. Reconciliation uses the protected
pre-mutation inventory even when audit history is corrupt; it authenticates the
exact resource before control actions, never kills a PID, and independently
checks all listeners. Only connection refusal establishes closure. Corrupt
inventory is not reconstructed from partial events; preserve evidence and rely
on independent expiry. New cleanup receipts preserve historical journals and
verdicts. Resource disappearance alone never establishes application recovery.

Cleanup pending uses execution status CLEANUP_PENDING and exit 7, retaining a
separate credible FAIL if present. Storage may still block the caller; the
fault-side expiry boundary must remain independent of that storage.
