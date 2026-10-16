# T2.0 Kubernetes threat model

This model covers an owned disposable Kind cluster and one dry-run controller.
Kubernetes authentication/RBAC and trusted setup replace local OS capability
assumptions. Local fixture HMAC keys, approvals and locks are never cluster grants.

| Threat | T2.0 boundary | Remaining requirement before fault execution |
| --- | --- | --- |
| Untrusted CR author | Closed bounded spec, CRD validation, independent policy, no actuator | Authenticate approver separately from request authors |
| Broad/malicious selector | No selector field; exact Deployment name/UID/generation | Bind selected pod UIDs and cap blast radius |
| Namespace escalation | Fail-closed admission, fixed watch/Role, same namespace and UID pin | Recheck namespace identity at action boundary |
| Excess service-account authority | Status-only writes; target get only; no Secrets/Jobs/pod deletion | Separate execution identity with action-specific permissions |
| Tenant separation | Single dedicated namespace; outside requests denied | No multi-tenant security claim; design isolation separately |
| Workload replacement / UID drift | Exact UID/generation comparison; invalidation latch | Never act on a replacement object or expanded set |
| Mutable tags | Only digest-pinned target images; template digest | Attest/verify actual running identity where required |
| Ownership changes | Hash owner references and pod template | Bind cleanup scope and revalidate full owner chain |
| Spec mutation after preview | Run generation/spec/contract included; old preview invalidated | Approval binds exact immutable digest and run identity |
| Controller compromise | RBAC cannot mutate workloads or mint execution resources | Dry-run status forgery remains possible; independent executor authorization |
| Accidental production context | No ambient config; dedicated local Kind context, trusted UID pins and owned setup | Strong environment admission beyond names/labels; production still excluded |
| Unsafe cleanup finalizer | No finalizer or execution resources in T2.0 | Independent bounded cleanup authority, TTL and residual checks |
| Cluster-scoped RBAC mistake | Exact-name read-only Namespace exception; no wildcard grants | Review every new action/permission independently |
| Stale informer / racing edits | Fresh decision reads, resourceVersion status update and polling | Revalidate immediately before any future mutation; no cross-object transaction claim |
| False PASS / forged evidence | Status schema permits only NOT_RUN/INCONCLUSIVE and executionAllowed=false | Signed execution/evidence provenance remains separate work |
| Resource exhaustion | 32-run quota, bounded specs/containers/requests and controller resources | Expand quotas/budgets only through trusted policy review |

The installer is trusted local administration and can create cluster-scoped CRDs,
validation configuration and the narrow RBAC binding. It refuses to adopt an
existing named cluster. An administrator/Docker operator can bypass this model;
the namespace and image pins are not an isolation boundary against that operator.
An author allowed to change the controller, RBAC, pins or validation policies is
outside the untrusted-run-author role. No external release gate may trust status.

Future T2.1 authorization must bind an authenticated actor/approver, run UID,
approved plan digest, cluster and namespace UIDs, workload and selected pod UIDs,
action/adapter and immutable parameters, issue time/expiry, budgets and independent
cleanup authority. Admission must check trusted policy and live authorization,
not a self-declared `approved` field. Spec or target changes invalidate the grant.
Execution and cleanup require distinct bounded permissions, durable intent,
idempotent resource identity and expiry enforcement independent of the controller.
This document designs those binding requirements; none is implemented as a fault
capability in T2.0. Do not reuse local fixture grants or expand the dry-run Role.
