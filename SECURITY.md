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

## Experimental Kubernetes dry-run boundary

T2.0 accepts one namespaced VerificationRun API in a separately created owned
Kind environment. Closed bounded specs, fail-closed namespace admission, trusted
UID pins and independent policy precede planning. Local fixture capabilities are
never Kubernetes authorization. Runtime permissions allow only status writes,
run reads, Deployment get and exact-name Namespace identity reads. No pod deletion,
target patch, fault resource or execution Job is permitted by its service account.

Preview verdicts are NOT_RUN or INCONCLUSIVE; the status schema excludes PASS and
executionAllowed=true. Previews are unsigned, subject to cross-object read races
and not execution attestation. Invalidated runs require a new request. Namespace
allowlisting alone is not future fault authorization. Installer privileges, Docker
operator access and status forgery risks are documented in the
[Kubernetes threat model](docs/kubernetes-security.md). That controller has no
execution authority. Production fault execution remains unsupported.

## Owned Kind experiment boundary

T2.1 uses a separate restricted local operator runner and preinstalled non-root
fixture. Explicit execution grants bind Kubernetes actor/cluster/namespace/run/
workload/Pod/container/image and proxy boot identity, parameters, short expiry,
one-time invocation and a separate cleanup key. A preview or unsigned status is
never such a grant. The runner cannot patch workloads, delete Pods, create Jobs,
read Secrets, execute in containers or provision resources. The fixture has no
API credentials and only a fixed loopback synthetic upstream.

Response latency expires inside the Pod within three seconds, independently of
runner/controller survival, observations and journal storage. Signed per-request
proxy hold measurements and independent paired client timing establish bounded
intervention evidence. Normal post-removal observations and complete cleanup
are required for PASS. Unsigned replay cannot establish trusted PASS; current
resource state and historical outcome remain separate. This is not production
authorization or complete execution attestation. Administrators and the local
approval-key holder remain trusted. See [the experiment guide](docs/kubernetes-experiments.md)
and ADRs T029–T035 for limits, private-state handling and the explicit test scope.

T2.2 adds coordinated cross-process cancellation without broadening those
permissions. Durable stop and fixture fencing are distinct: unavailable control
leaves cleanup uncertainty explicit. Cleanup requires intact protected identities
even with corrupt historical evidence. Status never authenticates old claims
using a fresh response. Failed receipt publication is cleanup pending.

The versioned offline verifier rechecks structure, signatures, correlations and
assertions while keeping timing, phase placement, the embedded public-key trust
root and complete execution unauthenticated. Candidate verdicts are not trusted
remote execution verdicts. The fixture key does not sign the historical bundle.
No production support or T4 evidence signing is implied. Adversarial Kind setup
operations are opt-in installer tests only; the controller cannot execute them.
See [Kubernetes lifecycle](docs/kubernetes-lifecycle.md).

T2.3's [operator coordination](docs/kubernetes-coordination.md) is an unsigned
operational index. A resource event cannot approve or start a fault. Explicit
approval independently recompiles the preview body/digest and exact execution
identity; a durable once-only claim prevents ambiguous retries. A stop before
inventory publication still fences coordinated Apply/finalization. Public records
carry no private capabilities; copied or missing private inventory cannot authorize
cleanup. Offline candidate PASS remains unauthenticated execution. Separate
4096-entry status/mutation nonce budgets prevent polling from starving cleanup,
while rejecting replay across both budgets and retaining independent expiry.
