# T056 — Bounded logical backup and restore

Status: Accepted for experimental T3.0.

Use the same pinned PostgreSQL 18.6 image for server, pg_dump custom archive and transactional pg_restore. Limit data volumes with 128 MiB tmpfs, private archive to 8 MiB, processes and runtime. Verify archive digest/readability, empty exact destination and restored application behavior separately. A fixed bootstrap permits private file delivery after tmpfs mount. A stopped source loses its tmpfs data; this is intentional synthetic source loss, not persistent storage recovery.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
