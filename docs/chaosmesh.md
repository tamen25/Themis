# Chaos Mesh planning and safety gates (T2.4)

**External fault execution is disabled. T2.4's external execution gates remain closed.**

The separately authorized [T3.0 PostgreSQL workstream](postgres-recovery.md)
does not change the provider findings or enable Chaos Mesh execution.

This implements the milestone's explicit planning/admission fallback. The audited
NetworkChaos API does not enforce Themis's approved Pod UID through selection,
and an independently bounded provider-side removal mechanism has not been
implemented or demonstrated. No external approval, Apply, fault observation or
cleanup actuator is shipped. Existing synthetic providers remain usable.

## Audited release and exact semantics

The actual upstream release API reported **v2.8.5**, published 2026-10-16 at
03:22:15Z; search results still described v2.8.4. The selected immutable source is
[`e020a2df5a69e99e49d2a3dda9e6be22237fd0d8`](https://github.com/chaos-mesh/chaos-mesh/tree/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8).
The source tag was unsigned; TLS retrieval and SHA-256/OCI digest pins are not
publisher-signature verification. Full audited-file hashes, chart/source URLs,
OCI indexes and platform manifest digests are in
[`upstream.lock.json`](../internal/chaosmesh/upstream.lock.json).

Exactly one candidate is researched: namespaced `chaos-mesh.org/v1alpha1`
`NetworkChaos`, action `delay`, mode `one`, one explicit `themis-test` Pod name,
device `eth0`, direction `to`, duration `2500ms`, latency `200ms`, jitter `0ms`,
correlation `0`. No target selector, remote cluster, external target, alternate
device, command, arbitrary YAML or additional fault parameter is admitted by
Themis. These are proposed packet-delay parameters, distinct from the existing
synthetic HTTP response-delay mechanism.

The [selector code](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/pkg/selector/pod/selector.go)
uses namespace/name Get for explicit Pods, bypassing the generic selector chain.
The [traffic controller](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/controllers/chaosimpl/networkchaos/trafficcontrol/impl.go)
and [PodNetworkChaos controller](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/controllers/podnetworkchaos/controller.go)
fetch the current Pod by name again. The daemon RPC receives that later Pod's UID
and container identity; it does not compare them to Themis's approved snapshot.
An admission check on the initial NetworkChaos object cannot make later provider
reconciliation atomic with the approved Pod UID. A resource name, label or one-Pod
selector is not an immutable targeting fence.

The [desired-phase controller](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/controllers/common/desiredphase/controller.go)
interprets duration and writes stopped state through Kubernetes. The
[TcsRequest protocol](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/pkg/chaosdaemon/pb/chaosdaemon.proto)
carries traffic controls, container, namespace-entry flag and current Pod UID, with
no effect-expiry field. The [daemon](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/pkg/chaosdaemon/tc_server.go)
modifies kernel traffic control. RPC timeout cancels command execution, not the
lifetime of an already installed qdisc. **Our source-based inference:** provider
controller/API loss can outlast the declared duration; it is not a demonstrated
fault-side hard deadline. No real fault was activated to test an unsafe bound.

## Trust and permissions

Provider installation is separate trusted administration. Upstream default
[daemon deployment](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/helm/chaos-mesh/templates/chaos-daemon-daemonset.yaml)
uses host PID, privileged execution/SYS_PTRACE, runtime socket access and host
system/module mounts. Disabling privileged mode still requires powerful
capabilities; it does not create Themis's missing safety fence. Kind/containerd
requires the appropriate runtime socket; upstream defaults are Docker-oriented.

The upstream [controller RBAC template](https://github.com/chaos-mesh/chaos-mesh/blob/e020a2df5a69e99e49d2a3dda9e6be22237fd0d8/helm/chaos-mesh/templates/controller-manager-rbac.yaml)
includes broad chaos-resource authority and Pod/ConfigMap/Secret access, plus
additional control-plane permissions. Those grants and provider workloads are
**not installed** here. No claim is made that Chaos Mesh is unprivileged or that
namespace RBAC alone authorizes a safe fault.

The fresh T2.4 environment installs only the exact upstream NetworkChaos CRD
schema, the unchanged safe Themis controller and a restricted read-only planner.
The planner can Get the named run/Deployment/ReplicaSet, Get/List namespaced Pods,
Get the two named Namespace identities and create SelfSubjectReview for identity.
It has no provider-resource writes, target mutation, Secrets, exec, forwarding,
Jobs or RBAC administration. The T2.0 controller Role is byte-for-byte unchanged.
There is no cleanup/runner role because neither external execution nor its
authority is implemented. Since no fault operation is enabled, no validating
webhook is claimed as an execution boundary; a future enabled design needs one
or an equally constrained pre-provisioned mechanism plus effective UID fencing.

## Artifacts and CLI

`themis.chaosmesh-plan/v1alpha1` is an unsigned, non-executable planning artifact.
It freezes the independently resolved request/spec/contract/preview and exact
workload/Pod/container/image identities, provider pins, one invocation ID, proposed
independent approver public key, fixed candidate resource name/parameters and
requested Apply/hard-stop/cleanup windows. The resource is UNCREATED_UID_UNBOUND.
The proposed public key is a declaration, not authenticated approval or a signer
trust root. No private key is generated or exported and no grant is minted.
The provider-specific required authorization domain is separate from every old
synthetic authorization format. Old grants are rejected, never reinterpreted.

The required windows (20-second start, hard stop by 22.5 seconds after planning,
90-second cleanup) are **requirements**, not enforced provider leases. A complete
external application contract/probe protocol, effective resource UID and actual
cleanup authority are still prerequisites for a future executable format.
Whole-document domain-separated hashing uses compact typed Go JSON, as existing
plans do. Compilation copies input snapshots; validation rejects altered versions,
pins, selector scope, parameters, deadlines, unsafe identities and unknown fields.
Public decoding is bounded to 1 MiB with duplicate/case/unknown-field rejection.
No parser field can turn `executionAllowed` true.

```powershell
go build -trimpath -o .cache/themis-chaosmesh.exe ./cmd/themis-chaosmesh
./scripts/kind-chaosmesh.ps1 -Action up
.cache/themis-chaosmesh.exe provider
.cache/themis-chaosmesh.exe plan --state .themis/chaosmesh-t24 --approver-public-key <proposed-separate-public-key>
```

Save plan JSON to a file, inspect its digest, and run:

```powershell
.cache/themis-chaosmesh.exe admit --state .themis/chaosmesh-t24 -f <plan.json> --expect-digest <reviewed-digest>
```

Plan/provider exit 0 means output succeeded. Admission always returns exit **5**,
DENIED / NOT_RUN / `mutationAttempted=false`, with explicit UID, expiry, cleanup,
grant, resource identity and observation blockers. Optional `--state` adds a fresh
identity comparison; altered/expired plans remain denied offline too. There are no
approve/run/apply/cleanup commands and no API mutation hook in the planner.
There is no fault journal or intervention evidence to export for this provider.
T2.3 coordination and historical formats retain their original semantics.

## Reproduction and evidence boundaries

```powershell
./scripts/kind-chaosmesh.ps1 -Action test
./scripts/kind-chaosmesh.ps1 -Action down
```

On Linux use pwsh and omit `.exe`. Kind 0.32.0 and the existing digest-pinned
Kubernetes 1.35.5 node are required. Setup chooses a fresh random
`themis-t24-<12 hex>` name and a private explicit kubeconfig. It refuses old state
and existing clusters. After initial creation it records the cluster UID before
any Kubernetes installation mutation; subsequent operations check cluster and
namespace pins. Teardown deletes only that owned cluster. Credentials are private
and never written to evidence. Do not upload `.themis`.

`THEMIS_KIND_CHAOSMESH_PLANNING=1`, `THEMIS_CHAOSMESH_STATE` and
`THEMIS_CHAOSMESH_BINARY` explicitly gate the new live suite; the script sets them.
`THEMIS_CHAOSMESH_EVIDENCE` optionally retains public command outputs. The live
tests cover real planning, upstream CRD schema and strict **server dry-run only**,
zero persisted NetworkChaos resources, actual RBAC, wrong environment and target
replacement negatives. UID-precondition deletion is installer test setup against
the exact owned synthetic Pod, never a runtime fault primitive. Unit tests use
controlled Kubernetes clients; they do not establish real provider behavior.

Real Chaos Mesh A-D experiments and active-fault runner/controller/API/cleanup
failure tests are **NOT EXECUTED: safety gates closed**. No schema acceptance,
provider status or mock acknowledgement is counted as measured intervention,
recovery or PASS. Existing synthetic live suites run separately and cannot stand
in for a second provider. Full Chaos Mesh installation/Kind runtime compatibility,
image execution/signature verification and provider image vulnerability scans
remain unproven. CRD-schema compatibility on Kind is a narrower result.

Before enabling faults, review an approved-UID enforcement mechanism through the
provider's final actuator and a pre-established independently bounded expiry and
exact-resource cleanup path. Then define scoped approval/cleanup capabilities,
durable one-use mutation intent, actual correlated traffic/app measurements,
recovery/residual predicates and adverse real-provider tests. Do not extract a
generic plugin engine while those concrete requirements remain unresolved.
