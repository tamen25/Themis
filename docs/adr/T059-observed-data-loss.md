# T059 — Observed recovery point and data loss

Status: Accepted for experimental T3.0.

Compare restored ordered IDs and exact contents against independently retained signed receipts. Detect duplicates, gaps, unexpected rows and corrupt payload. The recovery point is the contiguous acknowledged prefix actually present. Exact loss needs full receipt coverage; valid missing acknowledged IDs otherwise provide a lower bound. Invalid receipts are uncertain. Credible violations dominate missing evidence under the existing pure result aggregator; inclusive thresholds pass at equality.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
