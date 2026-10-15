# T1.2 validation matrix

Tests use real owned workers, local files and HTTP observations. Controlled IO
boundaries inject specific write/sync/response failures without replacing the
worker. The external handoff contains actual logs, exits and coverage limits.

| # | Requirement | Test in internal/experiment unless indicated |
| --- | --- | --- |
| 1 | Healthy PASS | TestRealScenariosAndReplay/healthy |
| 2 | Buggy FAIL | TestRealScenariosAndReplay/buggy |
| 3 | No-op INCONCLUSIVE | TestRealScenariosAndReplay/noop-adapter |
| 4 | Cleanup denied / exit 7 | TestRealScenariosAndReplay/cleanup-denied; CLI demo |
| 5 | Baseline rejected before intent | TestBaselineAndRevalidationBeforeIntent |
| 6 | Target revalidation fails before Apply | Same test, fenced claim and stopped target |
| 7 | Journal fails before Apply | TestJournalFailureBeforeApply, TestTornIntentNeverApplies |
| 8 | Apply acknowledgment ambiguous | TestAmbiguousApplicationAcknowledgment; processed real request, response dropped |
| 9 | Cancel baseline | TestExternalCLICancellation/BASELINE_STARTED |
| 10 | Cancel active fault | TestExternalCLICancellation/INTERVENTION_STARTED |
| 11 | Cancel recovery | TestExternalCLICancellation/RECOVERY_STARTED |
| 12 | Cancel after completion | TestStatusAndCancelAfterCompletion |
| 13 | Repeated cancel | Same test and external phase tests |
| 14 | CLI death after Apply | TestActualCLIProcessDeath; actual OS kill |
| 15 | Fixture death | TestActualProxyProcessDeath; actual OS kill, no recovery inference |
| 16 | Concurrent cancel/cleanup | TestConcurrentCancelAndCleanup; separate CLI processes |
| 17 | Corrupt journal, valid inventory | TestDamagedJournalInventoryAndReplacement; torn-intent and crash tests |
| 18 | Missing/corrupt inventory | Same test; denied mutation |
| 19 | Replacement listener | Same test; real rebound port, zero control POSTs |
| 20 | Expired authorization | TestExpiredUnusedAuthorization; actual expiry wait |
| 21 | Expired fault lease | TestExpiredClaimLease waits unused claim expiry; TestAdmissionDuplicateAndExpiry and TestJournalFailureLeavesIndependentExpiry check applied-fault expiry |
| 22 | Stalled writer | TestStalledWriterCannotExtendFault; active fault expires while sync blocked |
| 23 | Failed receipt persistence | TestCleanupReceiptPersistenceFailure; runner/external writes and retries |
| 24 | Repeated status, no mutation | TestStatusAndCancelAfterCompletion; fixture.TestReadOnlyInspectionDoesNotConsumeControlState |
| 25 | T0 hashes/replay | Existing contract/plan/run goldens and archived binary CLI comparison in handoff |
| 26 | T1.1 report compatibility | testLegacyCompatibility, DecodeReport and published journal old/new CLI comparison |

TestCleanupCommandCancellation covers external command context expiry. Localstate
lock tests cover actual file-handle exclusion and lock acquisition deadlines.
FuzzReplayExperiment checks malformed input, PASS prerequisites and unsigned trust.

Process-kill tests run on Windows and Linux where supported. Linux race tests
also build an instrumented CLI/worker. Some child tests use
`GORACE=atexit_sleep_ms=0` to remove the artificial exit delay; race detection
remains enabled. Tight baseline admission is unchanged and rejects noisy runs.

Coverage does not prove arbitrary blocked OS I/O responsiveness, power-loss
durability, same-user adversary isolation, suspend timing, macOS runtime behavior
or safety for external/production targets.
