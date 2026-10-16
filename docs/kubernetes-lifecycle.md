# Kubernetes experiment lifecycle and evidence

T2.2 retains the owned synthetic Kind boundary. One separate operator runner
executes the preinstalled response-latency fixture. The dry-run controller, API
and RBAC have no new execution authority. Production clusters are unsupported.

## CLI

```powershell
$runner = '.cache/themis-kube.exe' # .cache/themis-kube on Linux
& $runner cancel --run-directory $runDirectory
& $runner status --run-directory $runDirectory
& $runner reconcile --run-directory $runDirectory
& $runner verify -f (Join-Path $runDirectory 'events.jsonl') --expect-plan-digest $approvedDigest
```

New protected inventories contain the absolute private setup path. An explicit
`--state` must match it. Legacy T2.1 inventories require the original `--state`
when it differs from `.themis/kind-t21`. No ambient Kubernetes config is searched.

Cancellation works in a second process, during execution or after runner death.
It verifies owner-only inventory, original approval signature, key pairs and
plan/authorization bindings, then persists an action intent and canonical stop
request. It authenticates cluster/namespace/operator, original Pod/container,
owner chain and boot before using the separate cleanup credential. It never
kills a PID, resolves a Service, adopts a replacement or provisions work.

The stop request fences the cooperating runner. Authenticated Remove permanently
fences first Apply at the fixture. With unreachable control that remote fence is
unconfirmed: the action returns CLEANUP_PENDING/7, while the durable local stop
and independent expiry remain effective. This is not network-atomic revocation
against a malicious capability holder. Repeated calls create separate receipts,
never renew grants/deadlines and preserve historical events/reports.

Reconciliation refuses an active runner; use cancel for T2.2. A live legacy runner
lacks the protocol and cannot be cancelled safely across processes. Allow bounded
expiry and reconcile after death/completion. Execution is never resumed.

## Cancellation ordering

`runner.lock` expresses liveness. `lifecycle.lock` serializes action acceptance
with durable intent/fresh admission/Apply/acknowledgment and FINAL/report
publication. The runner checks the stop between samples and under this gate.
Acceptance before FINAL prevents PASS, even after assertions passed. A later
action does not rewrite the completed verdict. The fixture's own mutex orders
first Apply against Remove and owns its monotonic deadline independently.

External actions release the gate before control I/O. The runner holds it across
admission/Apply so an accepted stop cannot race an unchecked first Apply. A sync
stall in that section can delay acceptance. Filesystem calls are not forcibly
interruptible; a timed-out lock request is not accepted. The fixture still expires
independently. File locks never authorize Kubernetes actions.

## Historical facts and current observations

Status writes no files and sends no mutation command. It separates strict offline
historical verification, journal completeness, unsigned saved report/verdict and
cancellation from current signed state. Current fields describe original-fixture
reachability, confirmed/absent/unknown residual intervention, deadline passage,
cleanup-authority expiry, prior receipt and reconciliation availability. Status
uses bounded control nonces for replay protection without changing fault state.

An unreachable/replaced Pod remains UNKNOWN regardless of elapsed time. A signed
inactive reply cannot authenticate old journal bytes. Observed expiry establishes
absence of delay; normal application probes independently establish recovery.
Prior receipts are unsigned historical claims, not fresh resource observations.
Expired cleanup authority can prevent status control even when identity is reachable.

Cleanup uses intact inventory despite a corrupt journal. It verifies the exact
original Pod/boot twice around forwarding and preserves history. Run/Deployment
generation drift can forbid execution while safe removal on the unchanged
original Pod remains possible. Replacement/missing identities deny connection.
The 90-second cleanup grant is never refreshed or widened.

Receipt publication is part of success. Signed inactivity with failed publication
reports current INACTIVE, operational CLEANUP_PENDING, `receiptPersisted:false`
and exit 7. Missing/corrupt inventory or failed admission/coordination also returns
UNKNOWN/CLEANUP_PENDING without claiming acceptance or guessing identities.
Invalid status inventory returns a command failure. A later receipt never upgrades
cancelled, incomplete or historical INCONCLUSIVE execution to PASS.

## Offline verification and versions

`verify` emits `themis.kubernetes-evidence-verification/v1alpha1`. Checks include
regular file <=16 MiB, <=256 records, <=64 KiB per record, strict JSON, newline
termination, supported versions, sequence/hash chaining, recomputed plan digest,
actor/run/target/invocation bindings, control/data signatures, nonces, request
correlation, duplicate observations, phase transitions, timing and coverage.
Assertion predicates reuse the live pure evaluator.

The output separates candidate verdict, trusted execution verdict, signature
counts, missing observations, credible scoped signed failures and provenance.
`trustedExecutionVerdict` always remains INCONCLUSIVE offline. Exit 3 denotes an
internally consistent unsigned candidate, including candidate PASS; exit 2 preserves
a credible signed zero-error violation; exit 6 denotes corrupt/contradictory
evidence. Missing finalization/measurements remains visible. Client timing and
phase assignment are unauthenticated.

Signatures are checked against the fixture key embedded in the plan, not an
independent execution trust root. Replacing the whole plan/key and signing
invented responses can create an internally consistent candidate but never trusted
PASS. A caller-retained `--expect-plan-digest` detects that substitution; it does
not sign history. T4 signing/Sigstore remains deferred. Imported journals are not
remote release gates.

New inventory/journal/report/inspection/receipt versions are v1alpha2. Actions and
verification envelopes start at v1alpha1. Plans, contracts, policy, grants and
fixture protocol retain T2.1 versions. Legacy replay preserves its published
interpretation and report shape. The new verifier audits it explicitly. New
lifecycle assessment preserves correctly scoped signed zero-error violations
when other observations are damaged; invalid evidence never produces PASS.

## Reproduce live tests

Follow [setup](kubernetes-experiments.md), then:

```powershell
./scripts/kind-experiment.ps1 -Action up
$env:THEMIS_KIND_EXPERIMENT_EVIDENCE = Join-Path $PWD '.cache/public-kind-evidence'
./scripts/kind-experiment.ps1 -Action test-lifecycle
./scripts/kind-experiment.ps1 -Action down
```

The test action enables `THEMIS_KIND_LIFECYCLE=1` and executes the real journal
process-death test then the full Kind suite sequentially. Ordinary Go tests skip
live work. Administrative helpers require bootstrap ownership, live cluster,
namespace/workload UIDs and Kind node labels. They may replace only the synthetic
Pod, change its generation, stop its exact container, restore exact-name forwarding
RBAC and briefly pause/resume only this owned API task. These are setup/test
operations, not new runner/controller capabilities. Drift tests verify zero Apply
on replacement invocations and restore a ready fixture/fresh preview; an actual
measured experiment checks restoration.

| Coverage | Actual boundary |
| --- | --- |
| Cancel at baseline, intent, Apply, Remove, recovery, FINAL | Separate Kind CLI processes and controlled local writes for exact ordering |
| Duplicate cancel/Remove/Apply; cleanup denied or bad key | Real HTTP and Kind; retained deadlines/counts |
| Generation, Pod replacement, container/boot restart | Live owned synthetic changes, stale plans/grants rejected |
| Expired approval against unchanged target | Original real T2.1 fixture-negative suite |
| Runner death, partial journal write, forwarding loss | Real OS processes/files/SPDY, independent expiry and recovery |
| API unavailable during cleanup | Owned API task paused; pending cancellation, then reconciliation |
| Controller restart | Original T2.1 real runner-death/controller-restart suite |
| Corrupt journal; missing/corrupt protected inventory | Actual files/CLI/Kind and local storage tests |
| Rehashed forgery, key substitution, invalid lifecycle | Offline adversarial tests with actual signed HTTP observations |

Record exact commands, outputs, exits and platforms. Hosted CI/macOS/ARM are not
executed because workflow definitions exist. Windows race needs a C toolchain;
use actual WSL Linux race testing when native CGO is unavailable. See T036–T042.
