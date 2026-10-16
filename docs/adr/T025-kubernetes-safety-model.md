# T025: Kubernetes authorization is separate from local grants

Status: Accepted for dry-run T2.0; future fault grants are not implemented.

Local SID/UID, HMAC grants and file locks do not authorize Kubernetes operations.
Use CRD validation, fail-closed scope admission, narrow RBAC and independent
controller policy. Only dry-run in the dedicated test namespace is admitted.
Operator cluster/namespace UID pins are checked at startup and planning. An
untrusted CR cannot relax bounds or provide an execution approval field.

Allowlisting and pins are not full fault authorization. Future design must bind
authenticated approver/actor, exact run/plan, cluster/namespace/target/pod UIDs,
action/parameters, expiry, budgets and cleanup authority. Changed inputs invalidate
the grant. The Kubernetes threat model describes the required separate boundary.
