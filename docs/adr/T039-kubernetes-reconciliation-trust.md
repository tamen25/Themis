# T039: Cleanup survives damaged evidence, not lost identity

Status: Implemented for T2.2.

Use protected inventory independently of journal validity. Verify environment,
operator, original Pod UID/spec/container/image, owner chain and boot around
exact-Pod forwarding. Changed run/workload generation can deny execution without
preventing removal on an unchanged original boot. Never guess missing identities.
Reconciliation refuses a live runner; cancel is the coordinated active operation.

Use separate expiring credentials, independent contexts, idempotent Remove and
actual recovery probes. Preserve historical bytes and publish a new receipt.
Publication failure leaves CLEANUP_PENDING even after signed inactivity.
Missing/corrupt inventory or unavailable coordination means pending/unknown,
without an acceptance claim. Cleanup never upgrades historical cancellation,
INCONCLUSIVE or incomplete execution. No generic scanner or authority refresh.
