# T080: Independent Kubernetes principal with an explicit same-host limitation

Install only into a newly named owned T4.1 Kind with UID-pinned local ownership.
The witness has its own ServiceAccount and explicit protected kubeconfig. Named
Namespace, VerificationRun, Deployment, ReplicaSet and Pod reads resolve the exact
target independently; forwarding is allowed only for that Pod. No broad list,
workload mutation, exec, Secrets, privileged Pod or host mount is granted. Ordinary
controller and runner RBAC are unchanged. A new ownership version admits only the
fresh T4.1 name prefix; legacy T2.1 ownership retains its original name restriction.

The demonstrated processes share one OS user and administrator. Protected files
do not isolate them against that user/admin. A separate Kubernetes principal and
separate randomly generated signing keys improve provenance within this trust
boundary; they do not provide Byzantine, hardware or machine independence.
