# ADR-T003: Four verdicts and evidence-aware aggregation

Status: Accepted — 2026-10-15

## Context

A successful tool invocation does not establish a reliability claim. Missing
data, absent checks and provider failures can otherwise become false PASS.

## Decision

Keep typed execution statuses and execution errors separate from PASS, FAIL,
INCONCLUSIVE and NOT_RUN. Aggregation accepts trusted required assertion IDs
separately from results. Omitted required results, invalid IDs, duplicate results,
unknown verdicts and unsupported outcomes cannot yield PASS. No required IDs
means NOT_RUN.

A required FAIL with sufficient credible evidence dominates; then required
INCONCLUSIVE, then explicit NOT_RUN. PASS requires all declared required results
to pass with sufficient evidence, no collection error, met preconditions and
independently observed intervention when requested. Optional checks stay visible
without affecting the overall verdict. A tool error does not provide credible
evidence for either PASS or measured FAIL.

## Consequences

The pure aggregator is independently table/property/fuzz tested. It is not an
evidence evaluator: callers must substantiate sufficiency. Future operationally
unsafe cleanup status must be shown independently and block safe run completion,
even if assertion evidence passed. ADR-T012 adds local execution and reports;
this aggregation boundary remains independent of the collector.
