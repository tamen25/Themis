# ADR-T001: Independent core and optional integrations

Status: Accepted — 2026-10-15

## Context

Themis owns reliability experiment orchestration and empirical evidence. Arete
owns general distributed correctness checking. Argus supplies optional diagnostic
context; CloudOps is a possible reference environment.

## Decision

Use `github.com/tamen25/themis` as the module path. Build and test the core with
no code, binaries, credentials or infrastructure from those projects. Do not
import another product's internal packages or add placeholder provider APIs.
Any future adapter needs a versioned portable exchange and explicit failure and
coverage semantics.

## Consequences

The core remains independently useful and testable. No integration is delivered
by this slice. Optional diagnostic failures must not manufacture or mask core
verification evidence when adapters eventually arrive.
