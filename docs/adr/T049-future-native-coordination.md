# T049: Defer Kubernetes-native execution ownership

Status: Accepted design boundary; no native execution implementation.

The operator CLI meets T2.3 requirements without a scheduler, execution CRD, Job
or controller privilege. Preserve read-only target and status-only controller
RBAC exactly. Any future native execution needs independent approver/runner trust,
distributed ownership fencing, durable cancellation and authenticated evidence
publication with conservative partition semantics. T2.3 local claims and OS locks
are not that design. Reuse contracts/plans/evidence principles without widening
fault types, workloads, tenancy or cloud scope through this milestone.
