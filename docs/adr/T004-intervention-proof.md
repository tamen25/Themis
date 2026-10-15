# ADR-T004: An intervention claim requires observation

Status: Accepted — 2026-10-15

## Context

An adapter can report success without affecting its target. Healthy responses
alone cannot establish resilience to an unobserved fault.

## Decision

Model intervention-required and intervention-observed as separate run evidence
inputs. A proposed PASS becomes INCONCLUSIVE if the intervention is required but
unproven. A baseline with no intervention claim does not require fault evidence.
Keep credible measured FAIL precedence, as specified by the guide.

## Consequences

This invariant is tested now without an adapter. T0 rejects fault declarations
and produces no intervention evidence. T1 must supply independent observations;
an adapter's successful return will never suffice on its own.
