# ADR-T013: Preserve v1alpha1 normalization and compare ratios exactly

Status: Accepted — 2026-10-15

## Context

The existing contract compiler validates numeric bounds at decimal precision,
then stores accepted thresholds as float64. Distinct high-precision YAML decimals
can therefore normalize to the same threshold and digest. An evaluator must not
silently claim to enforce more precision than the normalized contract contains.

## Decision

Preserve the documented v1alpha1 normalization and existing contract digests.
The normalized JSON decimal is the contract's effective threshold. For example,
`0.0299999999999999999` and `0.0300000000000000001` both normalize to `0.03`.
This is specified quantization, not a SHA-256 collision or preservation of the
original decimal. Review normalized plan output when precision matters.

Parse the canonical normalized decimal into a standard-library rational and
compare the integer unsuccessful/total count ratio exactly. Do not round the
measured ratio, convert it to a float, or add a comparison epsilon. Thus 3/100
meets 0.03, 4/100 fails, and 1/33 fails. Values that normalize below 0.03 do not
admit 3/100. The execution policy version binds this comparison behavior.

## Consequences

Existing contracts retain their documented float64 precision limitation, while
measurement comparison introduces no additional rounding. Raw decimals near a
boundary may quantize across it during normalization. Users needing exact input
decimal semantics require a new schema/compiler version; silently replacing
v1alpha1 with arbitrary-precision thresholds would change existing identities.
Boundary and adjacent-float tests guard the chosen behavior.
