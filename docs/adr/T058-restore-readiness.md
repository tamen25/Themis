# T058 — Restore readiness and time

Status: Accepted for experimental T3.0.

Start the monotonic interval after observing the exact source container stopped. Include preflight, archive verification, restoration, schema/constraint and application invariant checks, then a committed health update and subsequent read. Exclude setup, backup and stop-request latency. Report restore tool time separately. This is synthetic single-host restore-to-readiness, not production RTO or HA failover.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
