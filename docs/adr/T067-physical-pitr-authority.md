# T067: Physical PITR needs distinct authority

Status: Implemented for disposable local T3.2; independent review required.

Add one concrete `pitr_*` workflow and CLI namespace in the existing PostgreSQL
package. A new version binds preparation plan plus actual signed prepared
backup/WAL/receipt/target metadata into the fault approval. Logical grants cannot
authorize it. Exact actor, directory, engine, source boot/system/volume and fresh
destination identities remain required. Preserve every T0–T3.1 format and the
controller's RBAC. Do not build a database framework or enable Chaos Mesh.

See [physical recovery](../postgres-pitr.md) for the protocol and limitations.
