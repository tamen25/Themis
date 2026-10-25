# T5.2-R-II local qualification boundaries

The corrective scope is native lifecycle test transport, disposable T2.0
installation, and local HTTP test timing. Production contracts, plan versions,
slot boundaries, coverage requirements, recovery ceilings and intervention TTLs
are unchanged. Whole-execution trust remains
`NOT_INDEPENDENTLY_ATTESTED / INCONCLUSIVE`; Chaos Mesh execution stays disabled.

## Native integration transport

Set an explicit local `DOCKER_HOST` and leave `DOCKER_CONTEXT` empty. Native Kind
installation no longer selects an ambient context. The supported sockets follow
the existing PostgreSQL local-engine endpoint policy: the Docker Desktop Linux
engine pipe on Windows; standard local Unix sockets or the user's Docker Desktop
Unix socket on Linux. A reachable socket is not sufficient authority.

New private bootstrap records pin that endpoint, engine ID, Kind context and
full original control-plane container ID in addition to Kubernetes cluster and
namespace UIDs. Integration-only `test/ownedtask` uses the existing endpoint
validator. It verifies the Linux engine, original node ID/name/Kind labels,
original Pod UID/container ID and task PID before each pause, resume or SIGKILL.
Commands have explicit hosts, fixed argument vectors, bounded diagnostics and
deadlines, with Docker environment variables removed. Resume uses the original
binding even while the Kubernetes API is paused. A failed restore remains a
failure; there is no replacement task selection or deletion fallback.

For the two fixed `kube-system` control-plane static Pods, retain the original
API mirror Pod UID separately from the kubelet/CRI Pod UID. The latter must be
the equal, nonempty `kubernetes.io/config.mirror` and `kubernetes.io/config.hash`
values from a `file` source on the original node. Ordinary workload Pods use
their API UID and cannot acquire this exception. See the Kubernetes
[annotation reference](https://kubernetes.io/docs/reference/labels-annotations-taints/#kubernetes-io-config-mirror).

Old bootstrap records without these pins are deliberately rejected by the new
controls. Do not edit old records to manufacture authority. Retain the matching
original installer and its cleanup records for old retained environments.

## Custom-resource quota readiness

The installer establishes the CRD and admission policy before quota admission.
It requires the exact configured quota limits in both spec and status, all
usage counters including `count/verificationruns.verification.themis.dev`, and
an unchanged quota UID. Pod usage alone is insufficient. API errors, replacement
or timeout abort setup before a VerificationRun can be created.

Kubernetes v1.35.5 discovers quota resources every 30 seconds but performs full
quota usage recalculation every five minutes. In a fresh cluster the evaluator
can appear before usage is initialized for an already-created quota. The former
90-second wait did not cover that cycle. The bounded 360-second monotonic wait
covers one cycle plus a minute; each polling API call has a ten-second timeout.
No quota, admission policy or controller RBAC is relaxed.

Sources: [controller wiring](https://github.com/kubernetes/kubernetes/blob/v1.35.5/cmd/kube-controller-manager/app/core.go),
[quota defaults](https://github.com/kubernetes/kubernetes/blob/v1.35.5/pkg/controller/resourcequota/config/v1alpha1/defaults.go),
[quota controller](https://github.com/kubernetes/kubernetes/blob/v1.35.5/pkg/controller/resourcequota/resource_quota_controller.go).

A server-side dry-run can test admission at that instant without persisting a
run. It does not guarantee future quota availability, controller state, or
future authorization. Readiness is rechecked by actual API admission on create.

## HTTP timing tests

Live HTTP tests retain the declared 100- or two-slot contract and inspect the
actual report, request counts, coverage, verdict and offline replay. Missing
observations must remain INCONCLUSIVE. A normal operating-system scheduler is
not required to dispatch every slot to make these consistency tests valid.
Controlled-clock tests independently require the fixed 100-slot schedule;
explicitly synthetic unsigned journal tests require 100/100 for PASS and
99/100 for INCONCLUSIVE, including missing first, interior and final slots.
These unit fixtures are never represented as live observations.

Timing investigation uses a separate instrumented source copy, initially with
unchanged execution semantics. It records slot dispatch/skip reasons, HTTP and
fixture timing, append/Sync durations, scheduler histograms, CPU sampling,
package concurrency and total budget. A controlled Sync delay demonstrates the
late-slot mechanism without attributing historical missing samples to an
unmeasured cause. Production scheduling is unchanged, so no policy/hash or
scheduler ADR migration is introduced.

## Preview exclusions and remaining gates

The Windows Administrators-owned positive ownership path and ownership
correction path remain NOT RUN because no authorized privileged runner is
available. The preview excludes that elevated-owner configuration. Current-user
protected state remains separately testable; ownership enforcement is retained.

Linux Go and race tests do not qualify real Linux Docker/Kind experiments. Those
require an authorized Linux Docker client and an admitted local Unix socket.
An unavailable runner is NOT RUN; a Windows socket alias is not Linux evidence.
Hosted Windows/Linux/macOS workflows, native macOS qualification and container
OS/package scanning remain separate release gates. Local success alone does
not approve T6, publication, committing or pushing.
