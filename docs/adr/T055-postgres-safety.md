# T055 — PostgreSQL-specific safety and identity

Status: Accepted for experimental T3.0.

The user authorized a separate database workstream while Chaos Mesh execution remains blocked. Use a new local Docker adapter with explicit original engine/socket, owned exact container IDs, image digest, private actor/directory and distinct PostgreSQL system/boot identities. Local and Kubernetes grants convey no database authority. No external database or arbitrary SQL/DSN interface is accepted. T054's historical sequencing does not block this separately authorized work; its external-provider gates remain unchanged.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
