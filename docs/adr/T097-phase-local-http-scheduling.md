# T097: Document the existing per-phase HTTP schedule

Status: Accepted clarification; no scheduler or format change.

The implemented T0 schedule starts at offset zero in each phase and uses 100 ms
slots within that phase. The expected count is `sum(ceil(duration_i / 100ms))`,
not `ceil(sum(duration_i) / 100ms)`. Phase boundaries can therefore be less than
100 ms apart. Sixteen 1 ms phases mathematically schedule offsets 0 through
15 ms; this describes the intended grid, not an observed request burst.

Sequential requests, durable journal writes, phase/run bounds, skipped expired
slots and no catch-up remain unchanged. Under the existing 16-phase/10-minute
limits there can be at most 6015 slots, 15 more than a scenario-wide grid.
Readiness and sample minima use the implemented grid. Missing slots never pass.

ADR T012's phrase "for the entire scenario" did not describe this boundary
precisely. This record corrects that prose; `themis.local-http/t0-v1`, the planner,
contract normalization, plan digests and replay bytes stay unchanged. A future
grid change needs a separate compatibility/reliability review and version decision.
