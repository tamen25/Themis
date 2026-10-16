# Experimental T2.0 Kubernetes dry-run foundation

T2.0 resolves a real Kubernetes Deployment and records a deterministic preview.
It executes no verification assertion and no fault. A planned run has verdict
`NOT_RUN`, never PASS. Local T0/T1.2 commands remain independently usable.

## Boundaries

```mermaid
flowchart LR
    Author[Untrusted VerificationRun author] --> API[Kubernetes API: CRD and scope admission]
    API --> Reconcile[Namespaced controller reconciliation]
    Pins[Trusted operator cluster and namespace UID pins] --> Safety[Kubernetes safety policy]
    Reconcile --> Read[Fresh namespace and Deployment API reads]
    Read --> Safety
    Safety --> Plan[Immutable dry-run planner]
    Plan --> Status[Controller-owned status: NOT_RUN or INCONCLUSIVE]
    Status -. No execution path in T2.0 .-> Future[Future separately authorized runner]
```

The Kubernetes API is the Control Plane's request/status store. One controller
process contains reconciliation, target resolution, safety and planning. It does
not need another deployed service, provider registry, database or workflow engine.
The Verification Runner and operational Assertion Engine are deliberately not
invoked. Status contains API-derived planning information, not measurement or
intervention evidence. Existing pure result/provenance principles apply without
importing Kubernetes into the local compiler, result aggregator or fault runtime.

`api/kubernetes/v1alpha1` defines this projection; `internal/kube` owns policy,
canonical plans and reconciliation; `cmd/themis-controller` is its separate entry
point. No local fixture capability is accepted. No Chaos Mesh adapter exists.

## API and trust

`VerificationRun.verification.themis.dev/v1alpha1` is namespaced and experimental.
The API group is provisional, not a claim of registered domain ownership.
There is no separate ReliabilityContract CRD: each request contains the complete
small versioned contract snapshot needed now. No arbitrary URL, selector, shell,
patch, pod template, approval token or fault field exists in this API.

The spec requires its schema version, `kind-dry-run` profile, contract and exact
Deployment reference: namespace, name, UID and desired generation. The contract
declares `DeploymentAvailable` and one minimum replica, but T2.0 only plans that
assertion. It does not evaluate it. Target resolution checks observed generation,
records the pod-template and ownership digests, and captures declared image
references. Every image must have a SHA-256 digest. These are desired image
identities, not observed container image IDs or software attestations.

Trusted policy is configured outside the CR using exact cluster (`kube-system`)
and `themis-test` namespace UIDs. Startup verifies both before watching runs; each
plan checks them again. Only `themis-test` and dry-run are supported. The synthetic
label is an additional filter, not proof of ownership or future fault authority.
Host networking/PID/IPC, privileged containers, hostPath and unpinned images are
denied. No more than four containers/init containers are planned.

The structural CRD preserves unknown spec fields until validation and uses all
required keys plus exact `maxProperties` counts at each execution-bearing object.
This rejects unknown input rather than silently pruning it, even when a client
does not ask for strict field validation. The controller also rejects unknown,
duplicate, case-mismatched, oversized and trailing JSON. The built-in validating
admission policy rejects VerificationRuns in other namespaces and cross-namespace
targets. It matches only this experimental resource and fails closed. Neither
component grants fault execution authority.

Unknown root fields are preserved and explicitly denied by the controller's
envelope check; they cannot disappear through API pruning and yield a preview.
Reserved Kubernetes metadata follows native API validation.

## Status and reconciliation

| Phase | Verdict | Meaning |
| --- | --- | --- |
| PLANNED | NOT_RUN | Preview generated; no assertion or intervention executed |
| DENIED | NOT_RUN or INCONCLUSIVE | Unsupported request, scope or target identity |
| WAITING | INCONCLUSIVE | Missing target or target generation not observed |
| INVALIDATED | INCONCLUSIVE | Previously frozen inputs changed; create a new run |
| ERROR | INCONCLUSIVE | API permission/read failure; no action attempted |

Status records observed run generation, reason codes, conditions, an execution
denial, provenance and the first immutable preview. PlanReady/TargetResolved
indicate a valid current frozen identity, not application health. The preview's
hash binds run UID/generation, contract/spec digests, cluster/namespace identities,
Deployment UID/generation/observed generation, pod template, ownership, images and
planner/policy versions. Resource versions and timestamps do not enter plan hashes.
Returned plan snapshots are independent copies of canonical bytes.

A changed spec, target generation/UID, ownership or pod template invalidates the
first preview. Its history is retained, `planDigest` is cleared, and a candidate
digest is shown when possible. Invalidation is latched; reverting inputs cannot
readmit that run. Status updates use the resourceVersion read with the spec, so
concurrent run edits cause a conflict and retry. Unchanged reconciliation produces
no status update or new transition timestamp. A five-second poll notices target
changes without granting Deployment list/watch permissions.

Cross-resource reads are not an atomic Kubernetes transaction. A target can
change after a read; the preview is informational and may remain stale until the
next poll. T2.0 has no actuator to exploit that interval. Future execution must
revalidate at its own trusted admission/application boundary.

No execution Job, fault resource, finalizer or target annotation is created.
Deleting a VerificationRun requires no target cleanup and cannot strand a fault.
Controller restart reconstructs state from API objects. Status is unsigned and
can be forged by an authorized status writer/administrator; it is not a release
gate or authenticated execution attestation. T0/T1.2 journals are unchanged.

## Permissions and limits

The controller's namespaced Role permits VerificationRun get/list/watch,
VerificationRun **status update only**, and Deployment get. It cannot create or
edit runs, patch targets, delete pods, create Jobs, read Secrets or change RBAC.
A narrowly named ClusterRole additionally gets exactly two Namespace identities:
`kube-system` and `themis-test`. Namespaces are cluster-scoped; this read exception
is necessary for UID pins and grants no list/watch or write permission.

The installer, not the runtime service account, installs the CRD, validating
admission policy/binding, RBAC, quota, synthetic workload and controller. Run it
only in the disposable cluster it creates. No production installation is supported.
The namespace quota caps runs at 32, Deployments at four, pods at eight, and
ConfigMaps/Secrets at eight each. Controller requests have a five-second deadline,
QPS 10/burst 20; the spec is capped at 8KiB. The controller container is non-root,
has a read-only filesystem, drops capabilities and has CPU/memory limits.

Namespace allowlisting, these UID pins and a dry-run policy are **not** a complete
future Kubernetes fault authorization mechanism. See the
[threat model](kubernetes-security.md) and ADRs T023-T028.

## Reproduce in an owned Kind cluster

Tested development baseline: Go 1.26.9, Kind 0.32.0, Kubernetes 1.35.5, Kubernetes
Go modules 0.35.5 and controller-runtime 0.23.3. The node and synthetic image are
pinned by digest. The synthetic target is HashiCorp's tiny HTTP echo application;
its image is a demo fixture, not a production image recommendation.

Prerequisites: Docker running Linux containers, kubectl compatible with Kubernetes
1.35, Go, and PowerShell (Windows PowerShell 5.1 or PowerShell 7 on Linux). On
Windows use `kind.exe`; on Linux use `kind` in the same `.cache/tools` directory.

```powershell
New-Item -ItemType Directory -Force .cache/tools | Out-Null
$env:GOBIN = (Resolve-Path .cache/tools).Path
go install sigs.k8s.io/kind@v0.32.0
./scripts/kind-up.ps1
$env:THEMIS_KIND_KUBECONFIG = (Resolve-Path .themis/kind-t20/kubeconfig).Path
go test -count=1 -v ./test/kubernetes
kubectl --kubeconfig .themis/kind-t20/kubeconfig --context kind-themis-t20 -n themis-test get verificationruns -o yaml
./scripts/kind-down.ps1
```

Windows execution policy may require a process-local invocation:
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/kind-up.ps1`.
It does not change machine policy. Setup refuses existing `themis-t20` clusters
or state directories. It writes only a dedicated private kubeconfig, never the
global kubectl configuration. Teardown checks its recorded cluster UID before
deleting exactly that Kind cluster. Other clusters are never adopted or deleted.
Private ownership/config files are retained for diagnosis; after teardown,
explicitly inspect and remove that exact state directory before fresh setup.

The example run UID is filled from the real target by setup. The checked-in YAML
placeholder is deliberately invalid. Runtime controller updates can be rebuilt
with `scripts/kind-controller.ps1`; this only rolls the owned controller and
never reapplies the target manifest. Local image tags include the compiled binary
hash. The scratch image needs no registry login or build-time network image.

Normal `go test ./...` explicitly skips Kind tests without the dedicated env var;
a skip is not a Kind pass. The real suite covers planning, missing targets,
expected UID/generation mismatches, unsafe namespace/spec admission, controller
rollout restart, VerificationRun deletion, changed contracts, RBAC and unchanged
target state. External target replacement/rollout and ownership drift are tested
with controlled API-client fixtures; the live suite never mutates the synthetic
target to manufacture those failures. It restarts only the owned controller via
its rollout annotation; no direct pod deletion or fault is issued.

If startup fails, inspect only the dedicated cluster:

```powershell
kubectl --kubeconfig .themis/kind-t20/kubeconfig --context kind-themis-t20 -n themis-test logs deployment/themis-controller
kubectl --kubeconfig .themis/kind-t20/kubeconfig --context kind-themis-t20 -n themis-test get verificationruns -o yaml
```

Check Docker Linux mode, the exact UID pins, API/CRD installation, controller
image loading and quota status. A denied request must be corrected/newly submitted;
there is no force flag, local authorization fallback or fault capability.

Primary references: [controller-runtime compatibility](https://github.com/kubernetes-sigs/controller-runtime#compatibility),
[Kind 0.32.0 release and node digests](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0),
[Kubernetes CRD validation/pruning](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/),
[HTTP echo publisher](https://github.com/hashicorp/http-echo).

## Separate T2.1 runner

The controller described here remains non-destructive. The separate [owned Kind experiment guide](kubernetes-experiments.md) documents T2.1 execution grants, exact-Pod identity, the preinstalled fixture and its independent expiry. The v1alpha1 preview API and this controller's target permissions are unchanged.
