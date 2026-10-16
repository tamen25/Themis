# T062 — Future physical backup, PITR and failover

Status: Accepted for experimental T3.0.

Do not generalize the concrete logical adapter into a provider registry. Physical backups, WAL retention/verification, PITR timeline selection, multi-node failover, external credentials and production recovery require new safety and measurement designs. Passing a synthetic logical restore proves none of these. Chaos Mesh execution blockers remain open and Kubernetes controller RBAC stays unchanged.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
