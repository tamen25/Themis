# T091: Sign independent measurements and preserve incomplete prefixes

The witness is a separate process/key and dedicated read-only Kubernetes principal.
It generates its own nonce for every direct, proxy, application and invocation
receipt request and signs actual response codes, elapsed times and nested fixture
replies. Original unsigned source observation remains another process with disjoint
nonces; its timings are never promoted into signed observations.

Canonical versioned Ed25519 JSONL has fixed limits, sequence/previous hash and
process/session/target bindings. Every write is synced; short/sync failure poisons
the writer. Key-local bounded consumed-session claims prevent session resumption
through a copied registration. Preserve complete prefixes and torn final bytes.

An API outage signs identity uncertainty while fixed data probing continues.
Proxy death/replacement records real disruption and cannot prove recovery. Witness
and runner liveness never control local fault expiry. Own monotonic measurements,
proxy-local epochs and claimed UTC are different clock domains. Shared admin,
filesystem stalls and arbitrary host/kernel failures remain explicit limitations.
