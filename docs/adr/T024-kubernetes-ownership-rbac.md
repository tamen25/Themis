# T024: Namespaced status ownership and least privilege

Status: Accepted for T2.0.

Watch themis-test only. Runtime permissions are run get/list/watch, run status
update and Deployment get. No target write, pod deletion, Job, Secret or RBAC
permission exists. An exact-name read-only ClusterRole gets kube-system/themis-test
Namespace identities because those UID resources are cluster-scoped.

Trusted installation owns CRD/admission/RBAC/quota and demo deployment setup in a
new disposable Kind cluster. These privileges are separate from the runtime
service account. Real API tests inspect effective permissions. No finalizer,
execution Job or target annotation exists, so run deletion needs no target cleanup.
Teardown verifies the recorded cluster UID and never adopts another cluster.
