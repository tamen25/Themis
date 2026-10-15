# T0 contract rules

`themis.contract/v1alpha1` is the local HTTP observation subset.
The proposed Kubernetes/fault contract is not implemented. The
[schema](../api/schemas/contract-v1alpha1.json) is the wire-format authority;
Go adds the cross-field and safety checks described here. An editor's JSON Schema
check alone does not establish that a contract is valid.

## Shape and defaults

| Field | Rule / default |
| --- | --- |
| `schemaVersion` | Required, exactly `themis.contract/v1alpha1` |
| `metadata.name`, `metadata.owner` | Required, bounded nonempty identifiers |
| `metadata.labels` | Defaults to `{}`; at most 32 bounded string entries |
| `spec.target` | Required `kind: local-http`, name and URL |
| `spec.execution.maxDuration` | Required, between 1ms and 10m inclusive |
| `spec.execution.profile` | Only `local`; defaults to `local` |
| `spec.execution.maxConcurrentFaults` | Only `0`; defaults to `0` |
| `spec.execution.requireApproval` | Boolean; defaults to `true` |
| `spec.scenario.id` | Required identifier |
| `spec.scenario.phases` | 1–16 ordered phases with unique names and durations |
| `spec.assertions` | 1–64 unique IDs; at least one required assertion |
| `assertions[].required` | Defaults to `true`; explicit `false` is optional |
| `assertions[].minSamples` | Integer 1–100000; readiness defaults to 1; success-rate requires it |
| `spec.evidence.includeRawTraces` | Only `false`; defaults to `false` |
| `spec.evidence.requireSignature` | Only `false`; defaults to `false` |

Names/IDs are lowercase ASCII letters, digits and interior hyphens, up to 63
characters. Owner and label syntax is defined in the schema. Labels carry
metadata; they never authorize execution.

Durations use Go `time.ParseDuration` syntax (`250ms`, `30s`, `1m`), bounded to
1ms–10m. Durations with day units, nonpositive values, overflow and non-string
values are invalid. The phase duration sum must not exceed `maxDuration`.

The URL must use `http` or `https`, a literal loopback IP (`127.0.0.0/8` or `::1`)
and explicit port 1–65535. Credentials, queries, fragments and scoped IPv6 zones
are rejected. `localhost` is intentionally rejected to avoid DNS resolution and
rebinding ambiguity. URL paths are preserved. Validation and planning do not test
connectivity or TLS. The runner contacts the exact endpoint; it does not discover
a process or verify who owns it.

## Assertions

`http-ready` requires a deadline no later than the total scenario duration. It
describes obtaining at least `minSamples` successful responses by that deadline,
measured from scenario start.

`http-success-rate` requires an explicit `minSamples` and
`maximumErrorFraction` in [0, 1]. It describes measuring the error fraction over
the scenario, with insufficient samples yielding INCONCLUSIVE. A zero error
threshold is valid; an absent threshold is invalid.

The runner uses status-only GETs with 2xx counted as success and no redirects.
[Run semantics](runs.md) define fixed 100ms slots, one-second request bounds,
coverage, admission, cancellation and reports. Planning remains side-effect-free;
a valid contract does not establish approval, feasibility or a verification PASS.

## Strict input handling

Exactly one YAML or JSON document is accepted, at most 1 MiB. Syntax-tree
traversal is limited to depth 32 and 10000 value nodes. Mapping keys must be
strings. Duplicate fields are rejected at every depth; there is no last-key-wins
behavior. Unknown properties, explicit null values for fields, YAML anchors,
aliases, merge keys, timestamps and non-core tags are rejected. Boolean fields
accept booleans, not `yes`, `no`, or quoted strings. Nonfinite numeric values are
invalid. Numeric scalars use JSON number syntax, at most 64 characters and
exponents from -400 to 400; hex, underscores and leading-dot fractions are
unsupported. Exact numeric values are preserved through schema validation, so
floating-point rounding cannot make a fractional sample count an integer or
bring an out-of-range threshold within its bounds. Accepted values are then
represented by the typed Go integer/float64 fields. Files are neither included
nor fetched from contract content.

Threshold precision is that of the normalized float64 value. Distinct raw
decimals can normalize to the same JSON decimal and digest. Assessment compares
integer count ratios exactly against that canonical decimal, without rounding
the ratio or adding an epsilon. [ADR-T013](adr/T013-threshold-semantics.md) records
this compatibility choice and its high-precision input limitation.

Unsupported fields are rejected rather than retained or silently ignored. These
include target namespaces/identity selectors, fault declarations, arbitrary shell
or SQL, intervention checks, provider configuration, retention, signatures and
raw trace collection. A newer schema version must be deliberately introduced
when the accepted model changes; existing artifacts must not silently acquire
different meanings.

## Normalization and digest format

After schema validation, the compiler explicitly inserts the defaults above,
normalizes duration spellings with `time.Duration.String()`, normalizes the
literal IP/port and an empty URL path to `/`, and sorts assertions by ID. Phase
order is preserved. Negative-zero error thresholds become zero. Metadata and all
accepted configuration participate in the contract digest.

The normalized bytes use Go `encoding/json.Marshal` on the typed contract:
compact UTF-8 JSON, struct fields in declaration order, map keys sorted by the
encoder, its default escaping and number formatting, and no trailing newline.
This is a versioned deterministic encoding, **not a claim of RFC 8785
canonicalization**. Comments, YAML formatting, mapping order, explicit equivalent
defaults, duration units and assertion order do not affect the digest. Phase
order, target, metadata, approval flags and assertion thresholds do.

`contractDigest = "sha256:" + lowercaseHex(SHA256(normalizedBytes))`.
The validated value exposes copies, never mutable internal maps or slices.
Normalized JSON is valid input to the same compiler and normalizes identically.

## Plan digest and immutability

A plan has the envelope `{"planDigest":"sha256:...","plan":{...}}`. The digest
covers the compact JSON `plan` value before adding the envelope. CLI indentation
and its final newline are display formatting and are not included. The payload
contains the normalized contract, its digest, planner/schema and execution policy versions, declared
target, bounds, safety requirements, planned checks and explanation. It has no
clock, random ID, absolute source filename or mutable provider discovery.

`planDigest = "sha256:" + lowercaseHex(SHA256(compactPlanPayload))`.
Hash the original canonical payload, not arbitrary reordered/pretty JSON.
The reviewed fixture is [plan.json](../internal/plan/testdata/plan.json).
Compatibility changes require an explicit version/ADR decision and fixture
review. Plans expose fresh byte copies and have no setters.

A digest identifies input and planning semantics. It neither authenticates an
author nor authorizes execution. The target identity is declared only; the
runtime ownership is unverified. The runner performs its bounded local admission
and exact-plan approval independently. Fault policies and runtime identity checks
remain T1 requirements. There is no evidence verdict in the plan. Planner t0-v2
deliberately changes plan digests to bind the implemented execution policy; the
contract normalization and its existing digests remain unchanged.

## Experimental fault-capable contracts

`themis.contract/v1alpha2` has a separate strict
[schema](../api/schemas/contract-v1alpha2.json), immutable validated type and
planner `themis.planner/t1.1-v1`. The
[owned latency example](../examples/owned-latency/experiment.yaml) requires
identity/owner metadata, an owned fixture name, `owned-local-test` profile,
maximum duration/concurrency, baseline, one latency fault, observation minima,
recovery, an exact decimal maximum error fraction, independent evidence and
required bounded cleanup. Every section is required; unknown and unsupported
values are rejected. Trusted safety caps are evaluated separately from schema
validity and cannot be relaxed by contract fields.

The new compiler freezes the authenticated resolved runtime identity and public
response key. Its policy is `themis.owned-local/t1.1-v1`; its plan envelope version
is `themis.plan/v1alpha2`. Compiling remains pure given that resolved value; the
experimental CLI performs explicit read-only instance resolution first. The
digest uses compact typed JSON and SHA-256, as documented for T0, with its own
versioned payload. Equivalent duration/decimal spellings normalize identically;
decimal thresholds retain their exact input value rather than converting to
float64. Literal length/exponent bounds still apply. T0 normalization, defaulting,
threshold semantics, plans and replay fixtures are unchanged.

Fault authorization is a separate capability issued after review of the exact
resolved plan, not a planning attribute. See [experiment semantics](experiments.md)
and [CLI reference](cli.md).
