# T019: Separate fault-capable contract and runtime formats

Status: accepted for experimental T1.1 only.

Introduce `themis.contract/v1alpha2`, `themis.plan/v1alpha2`, planner
`themis.planner/t1.1-v1`, policy `themis.owned-local/t1.1-v1`, adapter
`themis.latency-proxy/v1`, report `themis.experiment/v1alpha1` and journal
`themis.experiment-journal/v1alpha1`. Strict required sections describe identity,
owned target, environment, baseline, intervention, evidence minima, assertions,
recovery, execution budgets and cleanup. Unknown values/fields are rejected.

Keep T0 validated types, normalization, hashes, planner/policy, journal enum,
replay and CLI behavior unchanged. Shared bounded YAML syntax handling is
factored without changing accepted T0 semantics. Fault commands live under
`experiment`; T0 approval flags cannot authorize them.

V1alpha2 exact decimal normalization avoids a new float64 rounding dependency;
equivalent exact values hash identically, and near-boundary values stay distinct.
Golden T0 artifact hashes and replay remain regression checks. Future changes
to these predicates, scheduling or approval semantics require explicit format
and policy decisions, rather than broadening existing meanings silently.
