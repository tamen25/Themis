# Operator coordination in owned Kind

T2.3 connects the existing safe VerificationRun planner and separately authorized
synthetic runner. It adds no Kubernetes permissions, fault type or execution
controller. Only the dedicated, installer-owned `themis-t21` Kind environment and
preinstalled latency fixture are admitted. Kubernetes status is untrusted input.

## Workflow

Create the environment with `./scripts/kind-experiment.ps1 -Action up`. Use the
existing example VerificationRun from `examples/kubernetes-experiment`. All output
below is JSON. Choose a **new**, private coordination directory for each request.

```powershell
$runner = '.cache/themis-kube.exe' # Linux/macOS: .cache/themis-kube
& $runner coordinate preview --state .themis/kind-t21 --run latency-request
& $runner coordinate prepare --state .themis/kind-t21 --run latency-request --directory .themis/operator-review-1
```

Review `proposal.json`: frozen requested specification/contract, request UID and
generation, controller preview/document/digest, independently reconstructed plan,
operator, exact workload owner chain, Pod/container/image/boot and public evidence
key, parameters and bounds. `preview` does not save state. `prepare` saves a new
owner-only inventory and immutable public snapshot; neither issues a capability.

After reviewing, paste the **executionPlanDigest** into the explicit approval:

```powershell
& $runner coordinate approve --directory .themis/operator-review-1 --approve-digest 'sha256:<reviewed executionPlanDigest>'
& $runner coordinate start --directory .themis/operator-review-1
& $runner coordinate status --directory .themis/operator-review-1
& $runner coordinate verify --directory .themis/operator-review-1
```

Approval independently resolves the request/preview/target again, then uses the
existing Ed25519 Kubernetes approver and restricted operator identity. Apply is
valid for 20 seconds from issue; cleanup for 90 seconds. Each approval has fresh
invocation and cleanup keys. The fixture lease remains at most three seconds,
bounded by Apply expiry. These clocks and grant/protocol formats are unchanged.
Start immediately after approval. Expiry never renews on retry.

From another process, using the **original protected directory**:

```powershell
& $runner coordinate cancel --directory .themis/operator-review-1
& $runner coordinate reconcile --directory .themis/operator-review-1
& $runner coordinate status --directory .themis/operator-review-1
```

Cancellation is durably ordered with Apply and finalization. An accepted stop
before finalization prevents PASS; a late cancel is labeled AFTER_FINALIZATION
and preserves completed history. A stop before approval fences future approval;
a stop after approval but before execution fences the unused fixture invocation.
If application outside the coordination claim is observed, the index explicitly
labels UNINDEXED_APPLICATION_OBSERVED instead of inventing an execution history.

## Durable state and uncertainty

`coordination-inventory.json`, signing/command capabilities in `authorization.json`,
and the original setup are private operator state. Never upload the directory.
`proposal.json`, `approval.json`, immutable `record-*.json`, journals, measurement
reports and separate cleanup receipts are publishable after checking their target
metadata. No private key or bearer token is in the public records. Public evidence
references are canonical relative paths; private inventories bind the original
absolute directory and setup. Copying a directory is not recovery authority.

Start writes one immutable execution claim **before** calling the existing engine.
The claim is consumed even if admission fails or the process dies before writing
execution inventory. Duplicate Start never retries, resumes Apply or issues a new
grant. An observed failed approval check latches invalidation. Drift followed by
reversion cannot revive that proposal or consumed invocation; create a new
proposal and explicitly approve its freshly resolved digest.

If a claim exists but original execution inventory is missing/corrupt, status is
EXECUTION_UNCERTAIN/UNKNOWN and cancel/reconcile stay CLEANUP_PENDING. They never
rebuild cleanup authority from a proposal, resource name or journal. Restore the
original protected inventory if available. Independent fixture expiry remains the
safety bound. Incomplete approval publication also requires a new proposal; no
replacement lease is minted. An approval that was never started can be fenced
using its protected original coordination inventory.

Status is read-only: it projects existing historical verification and fresh
signed fixture state without publishing new local records or mutating targets.
Active versus interrupted execution is deliberately uncertain without a complete
journal; no distributed liveness/leadership claim is made. API unavailability,
replacement targets, expired cleanup authority and broken local state stay
explicitly unknown/pending. Controller restart cannot schedule or resume anything.

## Versions and trust

The public envelope is `themis.kubernetes-coordination/v1alpha1`. Proposal,
approval, protected state, execution claim, cancellation action, invalidation and
engine-return bookkeeping each have distinct `themis.kubernetes-coordination-*/v1alpha1`
versions. An inventory-open failure uses the separate failure envelope version,
with UNKNOWN, NOT_ACCEPTED and CLEANUP_PENDING. Public decoding checks supported
versions, exact fields, duplicate keys, 1 MiB/depth/node limits, digests, bindings,
approval windows and canonical evidence paths. Validation is shape validation;
the operational index is unsigned and never grants execution.

The index has no independent verdict. `locallyCollectedExecutionResult` is the
existing live engine report; `historicalAndCurrent` uses the existing inspection;
`verify` calls the T2.2 offline verifier against the exact plan/invocation. A
candidate PASS with individually valid fixture signatures and unsigned client
timing remains **trusted execution INCONCLUSIVE** offline. Credible signed FAIL
remains visible. An index cannot authenticate an entire past experiment, even if
its bytes are signed later. No Kubernetes status publication or release gate is
implemented. Historical journals/reports are never rewritten by later cleanup.

Start exit codes match the existing runner: 0 measured live PASS, 2 FAIL, 3
INCONCLUSIVE/cancelled, 5 admission denied, 6 operational/invalid evidence, 7
cleanup pending (takes precedence). Invalid arguments are 4. Prepare/approve/status
exit 0 means the command succeeded, **not** that an experiment passed. Offline
verify never returns 0 for historical PASS: it returns 2 for credible signed FAIL,
3 for unauthenticated execution and 6 for invalid bindings. Cancel/reconcile use
7 for unconfirmed cleanup; successful unused cancellation can return 0/NOT_REQUIRED.

## Polling and tests

The fixture now retains separate bounded budgets of 4096 status and 4096 mutation
nonces, checking replay across both. Exhausted status polling denies further reads
but cannot consume cleanup capacity. No nonce is evicted or reused. Apply/Remove
authentication, freshness, one-time invocation fence and independent deadline are
unchanged. Mutation abuse or the separate 256-invocation capacity still fails
closed; status is not an unlimited monitoring endpoint. Fixture restart creates a
new boot identity and requires a fresh plan/approval.

```powershell
go test -count=1 ./...
./scripts/kind-experiment.ps1 -Action test-lifecycle
./scripts/kind-experiment.ps1 -Action test-coordination
./scripts/kind-experiment.ps1 -Action down
```

The new tests require `THEMIS_KIND_COORDINATION=1` and explicit existing lifecycle
opt-in; ordinary unit runs label them NOT EXECUTED. The script sets both. Live
cases cover measured healthy/buggy/noop, denied cleanup/expiry, request and Pod
drift, duplicate CLI, runner kill, controller restart, separate cancellation,
actual status-capacity exhaustion, API pause and missing inventory. Only trusted
test setup with exact owned cluster/namespace/workload identities replaces the
synthetic Pod, restarts its container or pauses the owned API task. These are
adversarial setup operations, never runner fault primitives or controller powers.
Set `THEMIS_KIND_EXPERIMENT_EVIDENCE` to retain public logs and signed observations.
See [lifecycle](kubernetes-lifecycle.md) for unchanged evidence and cleanup semantics.
