# Experiment lifecycle, status and recovery

T1.2 retains one owned synthetic application, one fixed dependency proxy and one
bounded response-latency fault. Admission thresholds and limits remain in the
[experiment guide](experiments.md). No remote or production execution is supported.

```sh
themis experiment status --run <private-run-directory>
themis experiment status --run <private-run-directory> --output json
themis experiment cancel --run <private-run-directory>
themis experiment cleanup --run <private-run-directory>
```

## Recorded execution and current resources

Status reads protected records, probes the existing runner lock, obtains a signed
read-only worker snapshot when possible and checks the three frozen TCP endpoints.
It creates no files and consumes no mutation nonce. It never extends expiry,
removes a fault or stops a worker. File-content and directory-entry tests exclude
ordinary access-time updates, transient TCP sockets and connection counters.

Typed JSON separates `journal`, `history`, `live`, `faultApplication`,
`faultApplicationSource`, `lastRecordedCleanup` and `executionDisposition`.
Historical results distinguish strict replay from an unverified saved report.
The latter remains a recorded claim without a matching complete journal.
Last-valid state and operation describe only the validated prefix. Torn records,
corruption, missing journals and interrupted valid journals remain distinct.

Live observations report the runner lock, authenticated claim/fault, listeners,
expected fault expiry and whether that displayed wall-clock deadline passed.
Unknown fault expiry stays unknown rather than being inferred from a lease.
Snapshots can span different instants. Closed listeners establish cleanup only;
they never establish application recovery or intervention.

A historical `CLEANUP_PENDING` can coexist with
`FINALIZED_WITH_RECONCILED_CLEANUP`; an interrupted journal can coexist with
`INTERRUPTED_RESOURCES_RECONCILED`. The original report, journal and verdict are
preserved. Status exit 0 denotes no resource reconciliation requirement, not PASS.

## Intent and cancellation ordering

The runner completes baseline collection and admission before fault intent.
Under the lifecycle lock it checks external stop requests, revalidates the actor,
authorization and exact live target/claim, syncs intent, calls Apply directly and
records acknowledgment. No extra resolution or storage call intervenes. Worker
Apply checks the grant again atomically. Known pre-send rejection is false,
transport uncertainty after intent is null, matching authenticated acknowledgment
is true. Separate scoped failure records can preserve known application state
when journal publication fails; those records are not authenticated evidence.

The runner holds `runner.lock` throughout execution. OS process exit releases it;
status does not guess liveness from a reusable PID. `lifecycle.lock` orders action
acceptance against intent/Apply/acknowledgment and finalization. An external
cancel/cleanup publishes an immutable action intent under that lock. If accepted
before finalization it also publishes a canonical `stop-request.json`; repeated
actions validate the existing request. The runner checks it during collection
and before finalization. Accepted pre-finalization requests prevent PASS.

After releasing the lock, the command authenticates the exact worker and quiesces
the exact claimed handle. A permanent fence rejects first Apply and removes any
active fault under the worker mutex. Scoped shutdown follows. Concurrent/repeated
actions never recreate a fault or extend its lease. Each writes a fresh receipt.
Actions accepted after finalization preserve the historical result.

After runner death another CLI uses this same inventory/protocol. There is no
resume, replacement fixture, identity reconstruction or reapplication. Bad or
missing inventory denies mutation. Journal damage alone does not invalidate
protected inventory. Replacement listeners cannot authenticate, receive no control
mutation and keep cleanup pending. No cleanup/cancel code kills a PID.

## Deadlines and storage failures

| Bound | Meaning |
| --- | --- |
| Authorization | 20s freshness, rechecked before intent/Apply |
| Experiment | Frozen budget starting at the manifest's start time |
| Claim lease | Claim-issued cap, including when the runner stalls |
| Fault | Worker-monotonic duration and lease cap, at most 3s |
| Fixture | Independent worker lifetime, 15s–2m |
| Cleanup/cancel | Separate context, at most 2s per attempt; external cancellation honored |

Each journal append is synced. Partial/short writes or failed sync poison the
writer, preventing later records from hiding damage. Strict replay rejects torn
or corrupt bytes; status alone uses the valid prefix. Cleanup gets an independent
context after run cancellation. Receipt publication failure stays pending/exit 7
even with all listeners closed; retry can publish evidence once storage recovers.
Failure to publish an external action intent prevents that command's mutation.

Filesystem calls can block beyond context deadlines. A sync stalled in the locked
Apply section can prevent external action acceptance within two seconds. The CLI
does not forcibly interrupt arbitrary OS I/O. Independent worker timers and
per-request expiry checks still bound the fault; a real stalled-writer test checks
this. If diagnostics also cannot be written, existing durable state retains
conservative uncertainty.

Immutable records use private temporary files, sync and atomic no-replace hard
links. Linux syncs directory entries; Windows flushes file data without a POSIX
directory-fsync claim. Process-kill tests do not prove power-loss durability.
Filesystem rollback, failed-sync persistence, lost writes, clock changes, suspend
and delayed OS scheduling remain limitations. Suspended workers cannot serve
requests; resumed requests check expiry. No hard real-time or suspend-inclusive
timer guarantee is claimed.

Runtime validation covers Windows/NTFS and Linux/WSL with private state on Linux
`/tmp`. WSL mounts without Unix permission enforcement fail closed for private
state. macOS has lock/mode support but requires CI/runtime validation. Other OS
lock implementations deny. Shared/network filesystems without verified private
ownership, locking and hard-link semantics are unsupported.

## Versions and provenance

| Artifact | Compatibility |
| --- | --- |
| T0 formats and hashes | Unchanged |
| Fault contract / resolved plan | Existing v1alpha2, unchanged hashing and bounds |
| T1.1 journal/report | v1alpha1 legacy transitions and published report shape |
| T1.2 journal/report/inventory/cleanup | v1alpha2 lifecycle/provenance/diagnostics |
| Action, failure, status and import envelope | Separate named v1alpha1 formats |
| Fixture/control proof | v2; old workers expire, create a fresh fixture |

New report sources are `LOCALLY_COLLECTED`, `UNSIGNED_LOCAL_REPLAY` and
`IMPORTED_EXTERNAL`. Signed, missing/unverified fixture responses and
unauthenticated client timing are distinct. Journal authentication is always
`UNSIGNED`; execution attestation is always `UNVERIFIED`.

```sh
themis experiment replay -f <events.jsonl> --output text
themis experiment replay -f <external-events.jsonl> --provenance imported
```

The imported envelope retains the recorded verdict while labeling source/trust
limits. Historical PASS is a computed claim, not authenticated execution.
Same-user processes can read capabilities or forge consistent journals/plans/keys.
Response signatures authenticate bytes, not client clocks, causal intervention,
global network conditions or the complete run. Reports cannot authorize remote
release gates. No Evidence Service or Sigstore implementation is present.
