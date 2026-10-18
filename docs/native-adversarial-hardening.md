# Native lifecycle hardening (T4.4)

This slice keeps the owned disposable Kind target and the native HTTP adapter.
It adds no provider, Kubernetes mutation privilege, execution trust upgrade or
production target. Chaos Mesh remains planning-only. The current external review
handoff contains actual command results, including unsuccessful reproductions;
test names below describe checks, not an assertion that a hosted CI run passed.

## Threat model

Imported bundles, unsigned histories, publisher-selected policies and messages
are untrusted. A publisher may possess its own legitimately trusted publisher key
and still falsify source claims. Witness and original execution signatures must
retain their own authority. Trust policies, current verifier time, installer,
pinned images, local administrator, kernel, runtime and Kubernetes control plane
remain explicit trusted inputs. Key separation under one OS account is not
protection from that administrator or independent machine attestation.

Processes may die after performing an effect but before acknowledging it.
Concurrent operations may race cancellation, expiry, identity changes and export.
Storage may reject, truncate or stall writes. Same names do not imply same Pod,
container, process boot or file identity. Missing acknowledgements establish
uncertainty, never absence or successful completion.

The original source candidate, signed observation corroboration, current cleanup
and whole execution trust are distinct. For all supported outcomes:

- executionAttestation = NOT_INDEPENDENTLY_ATTESTED
- trustedExecutionVerdict = INCONCLUSIVE

## State and authority

[native-lifecycle-matrix.json](native-lifecycle-matrix.json) records 24 transitions
with preconditions, exact authority, durable claims, possible effects, receipts,
crash outcomes, retry rules, reconciliation and historical verdict disposition.
It includes competing processes and lost acknowledgements.

Operation not attempted, attempted with unknown effect, independently observed
effect, inactive/expired actuator, measured recovered traffic and cleaned
resources are separate facts. In the actual native runner grammar, original
cleanup confirmation precedes FINAL; later reconciliation never rewrites it.

The final proxy authenticates signed original installer/approver bindings,
exact immutable target and boot identity, invocation and one-use Apply authority.
A successful durable intent consumes that attempt even if cancellation happens
before mutation. A retained ambiguous attempt is fenced rather than automatically
retried. An existing applied epoch keeps its original monotonic deadline.
Fresh proxy boots generate new keys and cannot inherit old capabilities.

Runner finalization takes the same lifecycle gate used by cancellation. A stop
accepted before FINAL forces CANCELLED/INCONCLUSIVE. The gate stays held through
the final journal append/Sync and exclusive report publication. A later stop is a
current-state action and cannot change completed report or signed assertion bytes.
Failure to obtain the final gate cannot produce PASS.

Proxy persistence checks the actual open writer identity against its protected
path as well as size and hash, and checks the name again after Sync. Short writes,
Sync errors, identity replacement or capacity failures poison future mutation.
The expiry timer and request-side deadline checks do not wait for journal IO or
the control mutex. A stalled Remove must not hold a delay beyond its original
supported deadline. This is not a real-time guarantee across kernel failure,
machine suspension or host power loss.

## Reproducible checks

| Boundary or adversary | Relevant tests |
| --- | --- |
| Protected approval, registration, claim, INTENT, FINAL and cleanup file publication | internal/localstate: TestPrivateRecordPublicationActualProcessCrashCuts; 35 real subprocess deaths through the common primitive, seven semantic representatives, not 35 full Kubernetes workflows |
| Competing protected publishers and filesystem locking | internal/localstate: TestConcurrentPrivatePublishersExposeOneCompleteRecord and existing lock tests |
| Proxy durable interrupted intent and exact journal file identity | internal/dependencyhttp: TestInterruptedDurableProxyIntentCannotBeAppliedAgain, TestProxyJournalRejectsIdenticalBytesAtReplacementFileIdentity |
| Actual file short write, Sync on closed handle, read-only descriptor | internal/dependencyhttp: TestProxyActualShortWriteAndSyncFailurePoisonAdmission, TestProxyReadOnlyHandleReportsActualWriteError; internal/nativewitness: TestNativeWitnessActualFileFailuresCannotResume |
| Delayed IO, expiry and application recovery | internal/dependencyhttp: TestProxyDiskStallCannotHoldExpiryOrRecoveredTraffic |
| Apply/Remove/expiry concurrency, reused invocation, response loss | internal/dependencyhttp: TestConcurrentProxyApplyRemoveExpiryRetainsOneEpoch, TestLostApplyAndDelayedRemoveAcknowledgementsDoNotRenew |
| In-flight expiry, duplicate after expiry, fresh boot | internal/dependencyhttp: TestExpiryInterruptsInflightDelayAndRestartHasFreshAuthority, TestRealHTTPDependencyPathAndIndependentExpiry |
| Journal, registry, signing-session and real HTTP handler caps | TestProxyBoundedRegistryAndControlJournalExhaustion, TestProxyActualHTTPHandlerCapacityIsBounded, TestNativeWitnessActualRecordAndByteCapacity, TestWitnessKeyCannotResumeCopiedSessionOrGrowWithoutBound |
| Actual torn private journal and proxy process death | internal/dependencyhttp: TestActualNativeProxyProcessDeathRetainsTornJournalWithoutResumption |
| Exact target and signing-authority substitution | TestActuatorDeniesIdentityAndAuthoritySubstitution; dependencyexperiment and original Kind authorization-negative suites |
| Original late cancellation false PASS and post-final immutability | test/nativewitness: TestOwnedKindLateCancellationCannotBecomePass, TestOwnedKindLatePostFinalCancellationPreservesHistory |
| Competing actual runner processes, 1,000 signed polls, active export and competing publishers | test/nativewitness: TestOwnedKindConcurrentStartsPollingAndPublication |
| Actual runner death before Apply and live concurrent inspection | test/nativewitness: TestOwnedKindRunnerDeathBeforeApplyAndConcurrentInspection |
| Actual death after Apply and actual witness death | test/nativewitness: TestOwnedKindActualWitnessAndRunnerDeath |
| Actual exact proxy container kill and UID-preconditioned Pod replacement | test/nativewitness: TestOwnedKindWitnessRecordsProxyCrashAndPodReplacement |
| Proxy replaced after signed READY before Apply | test/nativewitness: TestOwnedKindProxyReplacementAfterReadyBeforeApply |
| API outage and controller-manager restart | test/nativewitness: TestOwnedKindSignedWitnessAcrossAPIOutage, TestOwnedKindSignedWitnessControllerManagerRestart |
| Actual dependency outage versus inactive actuator | test/nativewitness: TestOwnedKindSignedWitnessActualDependencyOutage |
| Real healthy PASS, application FAIL, no effect, withheld cleanup | test/nativewitness: TestOwnedKindWitnessedNativeVerdicts and original test/nativedependency suite |
| False source PASS/cleanup, hidden cancellation, replayed signature/nonce, phase/plan/boot/session substitution, incomplete terminal | pkg/nativeobservation tests; internal/evidencesource: TestNativeOfflineMappingsRejectAlteredClaimsChainsAndCrossRunRecords, TestPublisherCannotHideActualSignedCancellation; real Kind fabricated-source case |
| External policy replacement during verification | internal/evidencecli: TestNativeVerificationUsesOneExternalPolicySnapshotDuringRotation |
| Unsupported mapping exit classification | internal/evidencecli: TestNativeUnsupportedMappingKeepsUnsupportedExit |
| Revocation, validity, role reuse, scope, malformed/duplicate policy and unknown keys | pkg/evidence, pkg/liveobservation, pkg/nativeobservation trust tests and real Kind adversePolicies |
| ZIP budgets, paths, duplicate entries, altered signatures, source swap and exclusive output | pkg/evidence tests, including real publisher death before final link |
| Historical bytes and offline isolation | Explicit review harness compares actual committed T4.3 binaries with current binaries, and runs a Linux-built static verifier in a fresh network namespace and public-input-only chroot |

## Interpretation and limits

The private publication primitive writes and Syncs a temporary file, closes it,
then publishes an exclusive hard link and Syncs the containing directory where
supported. A pre-link crash exposes no final record; a post-link lost response
may leave one complete final record. Existing immutable records are not resumed
or overwritten. Crashed private temporary files remain operator-managed retained
state; they do not authorize effects or constitute discovered final evidence.

Linux permits the demonstrated same-byte rename/replacement journal adversary.
The Windows filesystem denied the attempted rename of the open writer. The
tests record that observed OS difference; Windows denial is not reported as a
successful Linux-style replacement. Successful Sync and process-kill tests are
not proof against host power failure.

Journal and capacity faults use bounded real files/HTTP requests and explicitly
controlled wrappers, not filling a host disk or exhausting shared Docker.
Record-count tests invoke the actual writer directly; they do not claim valid
independent timing coverage or a live network observation session.

The normal witness writer has one serial owner and emits one terminal record.
Imported records after END/INTERRUPTED are rejected by the independent analyzer.
No exported journal, embedded key or bundle-supplied policy can grant itself
execution or signing authority. Individual verification calls decode their
external policies once; concurrent policy replacement affects later snapshots
and does not create a live global revocation oracle for a call already in flight.

Resource teardown uses exact installer ownership and Kubernetes UID guards.
The harness faults only tasks inside its newly created cluster. Shared Docker
and preexisting Kind resources are inventoried, never pruned or faulted.

T5.0 is the separate comprehensive Cloudflare security-audit skill operated by
Codex. It is not installed or run in T4.4. T5.1 addresses independently confirmed
findings, T5.2 consolidates APIs/CI/security docs/release readiness, and T6 is the
developer preview.
