# T060 — Database evidence provenance

Status: Accepted for experimental T3.0.

Live adapters may establish trusted context for this process. Reports and journals remain unsigned whole-run historical candidates. Individual COMMIT and backup signatures bind bytes under the private setup key, not honest sensors or external key identity. Offline replay always reports INCONCLUSIVE even after an attacker regenerates every hash and embedded key. No T4 whole-bundle signing or attestation service is introduced.

See [PostgreSQL recovery](../postgres-recovery.md) for implementation details,
limits, commands and validation. These decisions authorize no production use.
