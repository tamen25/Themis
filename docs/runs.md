# Local HTTP run semantics

`themis run -f <contract>` explicitly requests local status-only GET probes.
Validation, planning and replay perform no network I/O. The runner consumes an
immutable validated contract and compiles the current plan. It checks feasibility
and approval before creating files or sending requests. When `requireApproval`
is true (the default), `--approve-plan` must equal the current plan digest. This
records caller intent; it is not a multi-user identity or authorization service.

## Versioned policy

The plan binds `themis.local-http/t0-v1`. Each phase starts a sequential schedule
at offsets 0, 100ms, 200ms, ... less than its duration. Phase offsets concatenate
in declared order. A request may start within its slot, never after the slot or
phase ends. Slow requests and delayed journal writes leave missing slots; there
are no concurrent requests, retries, catch-up bursts or early success exits.
The complete scenario is observed, even after readiness passes.

There are at most 6015 slots across the schema's 16 phases and 10-minute budget.
Impossible `minSamples`, including optional assertions, are denied before I/O.
Each request has a one-second timeout capped by the phase and run deadlines.
Ctrl+C/SIGTERM cancels collection and records a terminal cancellation when the
process can still write. File synchronization itself is subject to OS/storage
latency; these deadlines do not guarantee a process hard-stop during blocked I/O.

The private transport ignores environment proxies and does not follow any
redirect, reuse connections, send cookies or request compression. Only the exact
declared literal endpoint is contacted. Headers are limited to 16 KiB. Bodies
are closed without collection; these checks assess HTTP status, not payload
correctness. HTTPS uses normal certificate verification. No ownership or process
identity is inferred from an address, name or label. A loopback service can still
be sensitive.

## Observations and verdicts

A completed 2xx response is successful. Other final HTTP statuses, transport/TLS
errors and request timeouts are observed unsuccessful probes. An externally
cancelled request or a request cut off at a phase boundary supplies no completed
observation. Such a gap cannot improve an error fraction.

`Samples` counts completed observations, including unsuccessful probes. Coverage
is sufficient only when every scheduled slot has an observation and collection
completed the full scenario. Zero observations means missing coverage; other
gaps mean insufficient coverage. The policy is deliberately conservative: a slow
target can produce INCONCLUSIVE instead of a fully measured error-rate FAIL.

Readiness counts successful responses completed by its deadline. Enough successes
establish PASS for that assertion. FAIL requires the deadline to have elapsed and
all slots starting before it to have observations. Otherwise readiness is
INCONCLUSIVE. The rate assertion requires full coverage and its minimum sample
count; it compares unsuccessful/total observations against the normalized
threshold. Ratios and the canonical threshold decimal are compared exactly, with
equality permitted and no epsilon. See [ADR-T013](adr/T013-threshold-semantics.md)
for the existing schema's float64 normalization boundary.

Required assertions determine the verdict. Credible required FAIL dominates
partial evidence; missing coverage or interrupted execution blocks overall PASS.
Optional results are retained. Execution status is independent of verdict:
`SUCCEEDED` means collection completed, including a collection that measured
FAIL. Cancellation and expiration remain visible even when an earlier readiness
window already established FAIL.

## Journal and unsigned report

Each run has a fresh `run-<random>` directory, restricted to its creating user
where supported by the OS. On Windows, inherited ACLs still determine access.
The journal is created exclusively, opened append-only, and synchronized after
every event. The `started` event freezes normalized contract bytes, plan bytes
and their digests, policy version, approval digest and wall-clock start time.
Samples carry a slot index, phase, monotonic start/completion offsets, outcome
and status. `finished` records execution status and elapsed time. Offsets share
the same local monotonic clock, started after the manifest is durable. Wall time
records run preparation and is informational, not an exact sampling-clock anchor
or an attested timestamp. Preparation does not consume the observation window.

No request precedes the durable start event. An in-flight request lost in a
crash leaves missing evidence. Journals never resume external actions. Offline
replay revalidates the contract, recompiles the exact versioned plan, checks
digests and admission, validates record sequence, phase and slot timing, then
recomputes assertion evidence and verdicts. Persisted PASS flags are not input.
Readers reject unknown versions/fields, corrupt or truncated JSON, invalid
ordering and records after termination. A crash between complete records yields
an interrupted report; it cannot establish PASS. Journal input is capped at
16 MiB.

The runner derives `report.json` through this same replay path, syncs a temporary
report and renames it into place. A crash may leave the temporary file; replay
uses the journal. Reports include contract/plan/policy identity, target, expected
and actual samples, execution status, assertion reasons, verdict, journal SHA-256
and `signed: false`. Report ordering is assertion type then ID. No raw headers,
bodies, network error messages or credentials are stored.

Unsigned digests check consistency against supplied bytes. A person able to
rewrite an entire journal can forge observations and recompute digests. Replay
does not authenticate evidence, verify workload ownership or prove that the
physical endpoint experienced the alleged responses. Signing, external proof,
recovery, destructive-action restart and cleanup need later milestone designs.

## Compatibility

Contract v1alpha1 normalization is unchanged. Planner `themis.planner/t0-v2`
adds execution policy identity and describes the implemented runner. Its plan
digests deliberately differ from the original planning-only v1 fixtures, so old
approvals cannot authorize the new behavior. Pre-runner plans/journals are not
migrated. Changing sampling, collection or assessment semantics requires a policy
and planner version decision, with reviewed fixtures and new approval digests.

## Experimental experiment journals

T1.1 uses `themis.experiment-journal/v1alpha1` and a separate `experiment` CLI
namespace. It does not extend the T0 event enum, policy or replay parser. Its
private resource inventory, fault intent, explicit state machine, independent
observer, cleanup reconciliation and process-death behavior are documented in
[experiment semantics](experiments.md). An experiment's response signatures do
not authenticate whole journals or client measurements. T0 journals and golden
artifacts retain the exact historical behavior described above.
