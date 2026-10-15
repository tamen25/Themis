# Security policy

Themis is pre-release software. No stable release or production fault execution
is supported. Use synthetic data in isolated local/test environments.

## Report a vulnerability

Use the repository's [private vulnerability reporting form](https://github.com/tamen25/Themis/security/advisories/new)
if enabled. If private reporting is unavailable, contact the repository owner
through a private channel listed on their GitHub profile before sharing details.
Do not post credentials, private workloads or exploit details in a public issue.
There is currently no guaranteed response time or published support window.

## Current trust boundary

Contracts are untrusted data. T0 accepts one YAML/JSON document up to 1 MiB,
rejects unknown fields, duplicate keys, aliases, anchors, merge keys and unsupported
tags, and bounds nesting and node count. The embedded schema is loaded offline;
contract data cannot select a schema resource to fetch. Files are explicitly
chosen by the CLI caller and are read without writing to the target or workload.

T0 accepts only literal loopback HTTP(S) targets with an explicit port. DNS
names, non-loopback addresses, credentials, queries and fragments are rejected.
T0 validation, planning and replay send no requests. Explicit `run` invocation sends
bounded status-only GETs to the declared endpoint; no provider or shell payload
is executed. The private transport disables proxies, redirects, compression and
connection reuse. Requests are sequential, bounded to one second and the phase
deadline; headers are capped at 16 KiB and bodies are not collected.
This URL restriction is an input constraint, not proof of workload ownership or
isolation. A privileged or sensitive service can also listen on loopback.

Contract and plan hashes identify deterministic bytes; they do not establish
authenticity, authorization, safety or reliability. Plans may contain owner,
labels and endpoint metadata; review them before sharing. T0 has no signatures,
runtime credentials or redaction service. No telemetry uploads or external
integrations exist.

## Execution and evidence limits

The local runner enforces a versioned policy, exact literal endpoint, approval
bound to the plan digest when required, request/sample budgets and cancellation.
It records unsigned local observations and fails closed on incomplete coverage.
Local files inherit OS access controls; POSIX modes do not replace Windows ACLs.
Anyone able to rewrite an entire unsigned journal can forge observations and
recompute digests. Replay checks consistency, not authenticity or physical truth.
Reports contain normalized metadata and endpoint paths; review before sharing.
Disk I/O can outlast request deadlines. No interrupted requests are resumed.

## Experimental T1.1 boundary

Fault-capable v1alpha2 contracts use the separate `experiment` namespace and
trusted deny-by-default policy. Only a synthetic service and proxy created by
Themis may be affected. Allocated IPv4 loopback listeners, exact random runtime
IDs, a fresh identity proof, owner/host context and a single-use 20s approval
capability bind the scope. T0's approval flag never grants fault permissions.

Private fixture/run state uses actual owner-only protected Windows DACLs or
Unix owner/mode checks. Credentials and authorization seals are not included in
journals or reports. Do not share fixture directories or authorization files.
The control key never travels over HTTP: control requests and responses carry
scoped nonce-bound HMAC proofs, with bounded replay protection. Separate read
tokens permit only fixed synthetic data paths. Ed25519 signatures bind response
identity, request ID, kind and HTTP status. A replacement listener cannot forge
responses using only public instance IDs or a captured data token.

The independent fixture process enforces a monotonic fault cap of 3s and its own
lifetime cap of 2m. It touches no persistent host networking state. Journal I/O
and parent cancellation cannot extend fault timers. Cancellation cleanup uses an
independent timeout. Cleanup requires actual refused connections for all owned
listeners; timeouts or replacement listeners remain pending (exit 7). No
reconciler kills a PID. Dead proxies do not count as successful app recovery.

Same-user processes can read local capabilities, alter artifacts or mint their
own approvals; administrators can bypass access controls. OS user identity is
not independent human authentication. These protections do not isolate mutually
distrusting processes under one account. Signed fixture responses do not sign
client clocks or authenticate whole journals; forged consistent histories remain
possible. Paired latency observations do not establish causal certainty.

Disk operations may still block beyond CLI timeouts; independent fault expiry
limits the intervention. Process termination tests do not prove power-loss disk
durability. Use tested local filesystems with real private ACL/mode and hard-link
support. See [experiment guarantees and limitations](docs/experiments.md).
Production execution, general recovery providers and end-to-end evidence
attestation require separate implementations and reviews.

## T1.2 operation and provenance boundary

Cross-process cancellation requires a private inventory with matching local
owner/host, plan and exact claimed handle. Actions are persisted before control
mutation. A worker-side permanent fence rejects first application after accepted
cancellation. Concurrent commands do not kill PIDs, extend leases or replace
historical verdicts. Damaged inventory denies mutation; a damaged journal alone
does not invalidate an otherwise usable protected inventory.

Status performs read-only signed inspection and fresh TCP observations. It
separates a saved historical claim from a strictly replayed result, and both from
current resource state. A listener disappearing establishes cleanup, never
application recovery. An OS lock reports runner liveness without PID reuse
assumptions. A held lifecycle lock during blocked disk I/O can prevent timely
external action acceptance; independent worker expiry is still enforced.

New reports explicitly classify local collection, unsigned replay and imported
evidence. Signed fixture messages authenticate their response bytes only.
Client timing, journal authenticity and complete execution remain unverified;
these artifacts must not authorize remote release gates. HTTP control v2 also
authenticates response status, preventing an unsigned status change from being
treated as a verified denial. Old live fixture controls are not migrated in place;
allow their bounded expiry and create a new fixture with the new binary.
