# Public historical evidence fixtures

These are curated synthetic observations from the actual reviewed T3.3 local
PostgreSQL runs and T2.3 owned Kind experiments. They are retrospective inputs,
not tests that rerun infrastructure or independent whole-run attestations.

PostgreSQL run IDs `96930b7d...` (healthy) and `8bf1fa4f...` (timing violation)
were executed in T3.3 and retained before baseline commit `7e4e7bd`. The public
plan is a T4 projection; it excludes the original private ownership inventory,
actor, filesystem directory and Docker socket. Its original plan/inventory
digests remain opaque references, explicitly reported as unavailable for full
private-plan recompilation. Receipts are collected from the retained preparation
journal without changing their signed message values. The reports/journals remain
historical source bytes; signatures authenticate only their original scopes.

Kubernetes inputs come from T2.3's retained
`TestOwnedKindCoordinatedMeasuredVerdicts` A/B/C/D records and matching journals.
The proposal and live report were projected with their existing concrete JSON
types from the public coordination record. No private capability, kubeconfig or
embedded signing secret is included. A publication key is generated independently
inside each test and never stored. The old embedded public keys are not trust roots.

Tests explicitly distinguish original source outcomes, supported consistency
checks, publisher signature trust and unproven execution. Keep these legitimate
fixtures in source control. All data is the fixed synthetic application workload;
there are no raw database files, backups, WAL, credentials or private state here.

`witness-*` directories retain six actual T4.1 histories from the newly owned
Kind cluster `themis-t41-76922dae33bd`: healthy, buggy FAIL, no-op, actual witness
process interruption, cleanup pending and the healthy basis for a controlled
public phase-disagreement test. Each has the unchanged original runner artifacts,
signed registration and exact witness journal in a lossless bounded base64 JSON
wrapper. Public policies are explicit test pins, not authority for arbitrary
imports. They contain no private keys or grants. The disagreement test changes
only a public report copy; actual runner and witness histories remain unchanged.

These fixtures exercise signatures and consistency offline. They are not fresh
experiments during ordinary unit tests, production guarantees, trusted timestamps
or proof of independent administrators/machines. Full live tests are opt-in and
produce their own newly registered sessions and public execution evidence.
