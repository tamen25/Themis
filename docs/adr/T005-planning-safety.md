# ADR-T005: Bounded planning does not authorize execution

Status: Accepted — 2026-10-15

## Context

User YAML is untrusted input. Offline planning cannot verify live identity,
ownership, isolation or approval, and must remain non-mutating.

## Decision

Accept only literal loopback HTTP(S) endpoints with explicit ports, no credentials,
query, fragment or DNS. Require a local profile, 1ms–10m duration bounds,
phase/deadline budgets, bounded samples and zero concurrent faults. Default
`requireApproval` to true. Reject fault declarations and unsupported features.

Every plan records `executionAllowed: false`, admission `not-requested`, a
declared-only identity and supported checks requiring separate admission. Neither explicit approval false
nor a digest grants execution. The CLI reads one contract and emits streams;
the compiler has no I/O or execution hooks.

## Consequences

Loopback is a scope constraint, not a proof of safety. ADR-T012 adds bounded
local GET admission; ownership and runtime identity remain unverified. Leases, target
selection, cleanup and deny-by-default fault admission are later work, not
implemented safety-controller claims.
