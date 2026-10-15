# ADR-T011: Strict contracts and immutable deterministic plans

Status: Accepted — 2026-10-15

## Context

Plans and approvals must identify exact intended behavior. YAML comments,
equivalent defaults and duration spellings should not change that identity;
meaningful configuration changes must.

## Decision

Embed a Draft 2020-12 JSON Schema and validate untrusted syntax before typed
decoding. Reject unknown/duplicate fields, multiple documents, aliases, anchors,
merge keys and unsupported tags. Bound input size, traversal and numeric literals.
Preserve numeric precision until schema validation completes. Apply explicit
defaults and Go semantic validation; sort assertion sets, preserve phase order,
normalize durations/endpoints and signed zero.

Hash compact typed `encoding/json` output with SHA-256. Contract digests cover
all normalized fields; plan digests cover the complete plan payload excluding
its digest envelope. Document encoder ordering/escaping and version the schema
and planner. This is not RFC 8785 canonical JSON or a signature protocol.

Keep snapshots private and return deep copies or fresh bytes. Exclude timestamps,
random IDs, machine paths and mutable discovery from deterministic planning.
Reject unvalidated zero values at the planner boundary.

## Consequences

Reviewed fixtures, equivalence/change tests and normalization round trips guard
compatibility. The plan snapshots intended configuration, not live environment
truth. Future signatures, provider versions, discovery and execution need their
own versioned artifact design. The local implementation guide remains outside
Git through its exact path in `.git/info/exclude`.
