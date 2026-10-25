# T079: A separate process signs its own bounded application observations

Use one concrete observer for the existing owned Kind latency fixture. A dedicated
key signs registration, durable session start/readiness, nonce-bound HTTP samples
and a terminal record. Each record binds process/session, run/plan/invocation,
exact cluster/namespace/Pod/fixture identity, sequence/previous hash, monotonic
offsets and claimed UTC. JSONL records have explicit version/domain and strict
canonical typed JSON. The witness measures requests itself; it never copies the
runner's client timings or receives control/cleanup capabilities.

The operator approves the exact digest and provisions external exact-session trust.
Neither a fixture key, embedded witness key nor publisher signature supplies that
trust. Witness key generation emits public identity only, not an invented policy.
See [protocol and limitations](../live-observation.md).
