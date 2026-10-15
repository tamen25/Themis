# ADR-T012: Bounded local observations and journal replay

Status: Accepted — 2026-10-15

## Context

T0 requires measured local checks, an append-only lifecycle journal and unsigned
reports. The previous slice only described checks. A runner must not infer PASS
from declarations or silently expand a reviewed plan's behavior.

## Decision

Implement one sequential status-only HTTP collector and a local runner, with
shared immutable policy constants. Explicit `run` invocation authorizes bounded
GETs to the declared literal loopback endpoint. Enforce exact plan approval when
requested by the contract, and deny infeasible sample requirements before I/O.
Target ownership is not verified. T1's fault admission and runtime identity remain
separate requirements.

Bind execution policy `themis.local-http/t0-v1` into planner `t0-v2`; change plan
fixtures and digests deliberately. Contract v1alpha1 bytes remain compatible.
Keep plans non-mutating previews; admission is a separate runtime decision.

Schedule one request slot per 100ms, sequentially, for the entire scenario.
No retries, redirects, proxies, body retention, concurrency or catch-up bursts.
Limit requests to one second and the remaining phase/run window, and headers to
16 KiB. Require every scheduled observation for sufficient full-run coverage.

Persist the immutable start record before requests. Start the monotonic sampling
clock after durable preparation, so startup disk latency is not an HTTP gap.
Append and sync observations and a terminal status. Offline replay revalidates
frozen inputs, bounds and event order, then computes results from observations.
Use the same path for report
generation; never accept persisted assertion verdicts. Retain interrupted
evidence without resuming requests. Publish an unsigned report via a synced
temporary file and rename. Bound journal reading to 16 MiB.

## Consequences

A real healthy endpoint yields measured PASS; 503 fixtures yield FAIL. Missing
slots, interrupted collection and corrupt journals cannot establish PASS. Slow
targets may yield INCONCLUSIVE under conservative coverage. No fault resources
exist, so no destructive cleanup or resumption protocol is implemented. Storage
I/O can outlast request deadlines. Local digests cannot authenticate forged
observations; signed evidence and physical provenance remain future work.

Maintainer review of the complete diff, decisions and test evidence is still
required before introducing fault injection.
