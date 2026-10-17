# T066: Conservative durable recovery evidence

Status: Accepted for T3.1's disposable local synthetic scope.

A Docker kill exit alone is insufficient: independently verify original source
PID 0, stopped state, exit 137, unchanged boot and no OOM flag. Observe retained
PG_VERSION bytes in the persistent source volume. Restore the independent host
archive into the original fresh destination and verify full schema/constraints,
exact data, conservation and an actual committed health write/read. Reload and
verify retained receipt signatures, order and coverage. A proven missing
acknowledged commit can establish FAIL despite other incomplete evidence.

Incomplete observations, partial publication/restore, invalid provenance or
uncertain transactions cannot establish PASS. Cleanup state remains separate.
Read back the journal before final assessment; a corrupt chain cannot pass.
Runner death retains incomplete historical evidence and independently
reconcilable exact ownership. Tests distinguish actual Docker/PostgreSQL effects,
actual OS process death, controlled writer/expiry faults and skipped checks.

Unsigned whole reports and embedded public keys cannot attest remote execution.
Offline replay always returns INCONCLUSIVE with live trust false. No T4 signing,
physical source-volume crash recovery, host power-loss, failover, WAL, Kubernetes
database fault or external provider activation is introduced.
