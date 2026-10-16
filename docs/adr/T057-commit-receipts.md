# T057 — Independent acknowledged-COMMIT ledger

Status: Accepted for experimental T3.0.

Issue fixed ordered application transactions. Only final matching COMMIT acknowledgement and successful psql exit allow publication of a durable host receipt. Bind ID, payload, XID, monotonic offset, plan and previous hash with a host-only Ed25519 key separate from authorization. Reload receipts after restore; missing or forged bytes cannot establish coverage. A lost acknowledgement remains uncertain.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
