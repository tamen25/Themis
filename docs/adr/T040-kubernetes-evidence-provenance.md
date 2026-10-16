# T040: Offline auditing does not create execution attestation

Status: Implemented for T2.2; T4 signing deferred.

Version a verifier for bounded strict journals, digests/bindings, lifecycle,
signatures, correlations and coverage. Reuse pure live assertion assessment.
Separate candidate result, scoped signed violation and trusted execution verdict.
The last stays INCONCLUSIVE for all unsigned offline journals. Individual
signatures prove only response bytes under the embedded key. Client timing,
phase placement and whole-history authorization remain unverified. A separately
retained expected digest detects key/plan substitution.

Tests recompute every unkeyed hash after changing observations, and replace the
whole key/plan. None creates trusted PASS. New lifecycle assessment preserves
scoped signed zero-error violations despite other missing/damaged observations.
Legacy replay retains published semantics. Inventory/journal/report/inspection/
receipts are v1alpha2; contract/plan/policy/grant/fixture versions stay unchanged.
No second assertion engine, Sigstore, trust service or remote gate is introduced.
