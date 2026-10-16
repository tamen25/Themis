# T061 — Database cleanup and crash recovery

Status: Accepted for experimental T3.0.

Persist private create intent and acknowledged inventory before experiment actions; consume the invocation once and hold an OS lock. Sync bounded append-only hash-chained journal entries before effects; poison writers after short writes or sync failures. Reconcile using the original private inventory, separate cleanup expiry, exact IDs and labels, independently of a damaged journal. Do not retry ambiguous effects or rewrite history. Unacknowledged resource creates require manual review. Named volume creation identity is checked but Docker lacks an atomic immutable volume UID delete fence. Docker admins remain trusted.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
