# T1.1 negative and interruption matrix

Admission denial before a claim/application returns no verification report
(NOT_RUN), normally CLI exit 5; invalid schema/flags use 4. Administrative calls
are not experiments. Execution and verification remain separate. An interrupted
offline journal stays CLEANUP_PENDING until independent reconciliation. A
credible application FAIL is retained alongside incomplete checks.

| Case | Expected safety/resource state | Execution / verification | Coverage |
| --- | --- | --- | --- |
| 1. Unauthorized target | No fault mutations | Denied / NOT_RUN | `safety.TestTrustedPolicyCannotBeRelaxedByContract`; actual unsigned control denial in `TestAdmissionDuplicateAndExpiry` |
| 2. Stale approval | No new claim/application | Denied / NOT_RUN | Changed digest and expired unused real 20s authorization tests |
| 3. Plan digest mismatch | No fault mutation | Denied / NOT_RUN; edited replay errors | Safety authorization checks, actual authorize mismatch, replay wrong digest |
| 4. Instance mismatch | Fresh identity proof fails | Denied / NOT_RUN | Actual changed client identity proof; authorization/manifest target tests |
| 5. Expired lease | Fault absent; duplicate does not restart | Original run unresolved unless fully observed / no PASS from expiry alone | Actual guardian expiry and post-expiry proxy request in `TestAdmissionDuplicateAndExpiry` |
| 6. Excessive duration | Trusted policy denies schema-valid request | Denied / NOT_RUN | Safety cap test (4s fault versus 3s hard limit) |
| 7. Unsupported fault | Strict schema rejects | Invalid config / NOT_RUN | Contract `unsupported action` |
| 8. Concurrent faults | Exclusive claim rejects second run | Denied / NOT_RUN for second run | Actual concurrent/reused authorization claim |
| 9. False adapter success | No observed latency effect | SUCCEEDED / INCONCLUSIVE | Real `noop-adapter` scenario |
| 10. No proxy traffic | Independent proxy evidence absent | INCONCLUSIVE; cleanup still required | Replay removes proxy traffic observations from real journal; actual process death removes all traffic |
| 11. Missing independent proof | Never substitute receipt/counter | SUCCEEDED / INCONCLUSIVE | Replay removes intervention samples from actual healthy journal |
| 12. Cancellation in fault | Independent cleanup removes fault and listeners | CANCELLED / INCONCLUSIVE | Actual network run with context cancellation after observed activation |
| 13. CLI crash | Guardian remains alive and expires fault; inventory supports cleanup | Interrupted replay CLEANUP_PENDING / INCONCLUSIVE | `TestActualCLIProcessDeath` uses OS process kill, real post-expiry traffic and reconciliation |
| 14. Proxy process crash | All owned listeners disappear; no recovery claim | SUCCEEDED collection with missing evidence / INCONCLUSIVE | `TestActualProxyProcessDeath` uses OS process kill |
| 15. Cleanup retry | Same exact inventory, no new fault | Cleanup completed; recovery not inferred | Actual repeated `Reconcile`, including already stopped fixture |
| 16. Cleanup denied | Fault removed but listeners remain until independent lifetime expires | CLEANUP_PENDING / INCONCLUSIVE, exit 7 | Real `cleanup-denied` run, owned child termination and subsequent reconciliation |
| 17. Corrupt/truncated journal | Replay rejects; inventory-only cleanup permitted | Infrastructure error; no PASS | Partial JSON, wrong ordering/run/digest/adapter; actual corrupted crash journal reconciled via inventory |
| 18. Duplicate application | Original receipt only; apply count remains 1, including after expiry | No new execution/effect; verdict still needs observations | Actual duplicate apply before/after expiry |
| 19. Wrong adapter version | Plan/handle rejected | Denied or corrupt replay / NOT_RUN | Fixture validation, actual wrong-handle apply, replay adapter mismatch |
| 20. Recovery samples missing | Resource cleanup does not imply app recovery | SUCCEEDED / INCONCLUSIVE | Replay removes recovery samples from actual healthy journal |

Additional tests cover exact decimal normalization, immutable/deterministic new
plans, owner-only Windows DACL/Unix mode rejection, malformed/duplicate JSON,
control-proof replay/tampering, replacement-listener response forgery,
request/response signatures, timeout, missing terminal event and actual journal
write failure after application. The write-failure test closes the real journal
file, verifies a failed append, observes independent expiry and reconciles.

The matrix distinguishes live tests from offline evidence-loss mutations. The
latter check replay/false-PASS resistance; they do not claim to simulate every
possible real network failure. Process-kill tests cover actual Windows and Linux
executables when their respective full suites execute. Power loss, a hung kernel,
privileged adversaries and macOS runtime behavior remain unverified.
