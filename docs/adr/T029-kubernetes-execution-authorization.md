# T029: Separate operator runner and Kubernetes execution grant

Status: Implemented for owned Kind T2.1; pending independent review.

Keep the T2.0 controller, v1alpha1 CRD and target-read-only Role unchanged. A new
operator-invoked executable resolves a run and independently recompiles its
preview. Preview status never grants execution. The runner uses an explicit
owned Kind kubeconfig with a dedicated service-account identity, fresh
SelfSubjectReview, named Namespace reads, namespaced workload reads and exact-Pod
port-forwarding. It cannot install workloads, patch targets, delete pods, create
Jobs, read Secrets or change security policy.

Trusted setup creates an approval signing key and installs its public key and
the permitted Kubernetes actor in the fixture. Explicit approval of the complete
new versioned plan issues a 20-second Apply grant, a unique invocation and two
distinct per-invocation command keys. Cleanup has a separate 90-second lifetime.
The grant binds operator, cluster/namespace/run/workload/Pod identities, running
container/image, boot-specific proxy identity, contract, parameters and duration.
Possession of a preview or public grant cannot sign an Apply command.

The fixture checks signed commands, its Downward API Pod UID, boot identity and
hard limits. The runner freshly revalidates Kubernetes inputs at the Apply
boundary. A new Pod, container restart, spec/generation change, expired grant or
different plan is denied. Distinct domain-separated signatures cover approvals,
commands and fixture responses. Local private-file helpers protect keys; OS actor
semantics and local fixture authorizations are not Kubernetes grants.

This is a single trusted local operator model. The approver key holder and cluster
administrator can bypass it; it is not independent human approval, production
authorization, cross-resource atomicity or remote execution attestation. A future
production boundary needs separate design. The owned setup may provision the
fixture before experiments; the runner has no provisioning interface.
