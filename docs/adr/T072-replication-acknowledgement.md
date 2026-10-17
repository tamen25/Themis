# T072: Verify acknowledgement semantics and replica contents

Status: Implemented for disposable local T3.3; independent review required.

Use one physical PostgreSQL 18.6 standby and `remote_apply`. Observe effective
settings, exact sender/receiver peers, streaming/sync states and WAL positions.
Each transaction explicitly selects remote_apply; only matching real COMMIT
acknowledgement plus successful tool exit permits a signed external host receipt.
Any SQL diagnostic is rejected; an interrupted synchronous wait can otherwise
print COMMIT with a warning and incorrectly imply remote acknowledgement.
The prepared seal binds full ordered receipt coverage and original replica state.
Independently compare standby and promoted data, payloads/XIDs, schema and balance
invariants. Matching system identifiers are required by physical replication;
distinct container/volume/postmaster identities establish separate instances.

Missing receipts, a disconnected/paused receiver, ineffective configuration or
insufficient replay cannot prove zero acknowledged loss. No slot or archive is
enabled; a finite closed workload and observed disk/WAL budgets avoid unbounded
retention claims. This is a tested synchronous method, not asynchronous replication
or production RPO=0. See [protocol](../postgres-replication.md).
