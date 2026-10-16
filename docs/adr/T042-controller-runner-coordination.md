# T042: Future controller and runner coordination

Status: Design boundary only; no new CRD, Job or scheduler in T2.2.

The VerificationRun remains an untrusted request and safe planner. A future
protocol must keep these stages distinct:

1. Compile an immutable plan binding request UID/generation, policy, contract,
   environment/workload/Pod/container/boot identity and budgets.
2. Independently authenticate approval of the full digest and bounded Apply/
   cleanup authority. Preview/status/annotation is never approval.
3. Schedule the exact invocation to an authenticated runner. Claim ownership,
   independently validate policy/identities and establish cancellable identity
   before Apply.
4. Publish versioned execution events bound to invocation/plan/target, ownership
   generation and per-writer sequence. Repeated delivery cannot renew effects.
5. Assign fault lease/cleanup independently of scheduler/runner/controller life.
   Order accepted cancellation with finalization; expose partition uncertainty.
6. Collect immutable evidence references/digests and declared provenance, keeping
   current cleanup separate from historical execution. Digests are not attestation.
7. Publish a historical result once with conservative assertions/cleanup state.
   Later recovery receipts remain new observations, never rewritten success.

The CLI lifecycle and versioned inspection/verification envelopes meet today's
need. Distributed ownership fences, durable cancellation storage, independent
approvers and authenticated publication need separate design/review. OS locks
are not distributed leadership. The T2.0 Role/API stays unchanged and cannot
execute faults, create Jobs or acquire target-write permissions.
