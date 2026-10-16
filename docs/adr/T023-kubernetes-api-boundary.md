# T023: One controller and a separate Kubernetes projection

Status: Accepted for non-destructive experimental T2.0.

Use Kubernetes as the request/status store and controller-runtime for reconciliation.
Policy, resolution and planning remain modules in one controller process. A separate
binary/API projection keeps Kubernetes dependencies out of local domain/runtime
packages. The only CRD is VerificationRun with a complete small contract snapshot;
a second contract resource provides no concrete value now.

The provisional verification.themis.dev/v1alpha1 group and versioned run/contract/
plan formats do not change published local artifacts. Exact required-key counts
plus maxProperties/preserved unknown input reject extra executable fields without
a webhook service. Optional fields need an explicit schema/version decision;
raising maxProperties alone would reopen unknown-field input. This is not a stable
public SDK or claim of domain ownership.

Unknown root fields are preserved and denied by controller admission; reserved
metadata retains native Kubernetes semantics. They are not silently ignored.
