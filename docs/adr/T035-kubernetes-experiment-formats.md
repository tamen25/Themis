# T035: New experiment artifacts preserve the dry-run API

Status: Implemented for owned Kind T2.1; pending independent review.

Keep verification.themis.dev/v1alpha1, the T2.0 controller/status semantics and
its RBAC unchanged. The VerificationRun remains a preview with executionAllowed
false and NOT_RUN/INCONCLUSIVE; a separate local experiment artifact references
its UID/generation and independently recomputed preview digest.

Introduce versioned Kubernetes experiment contract/plan/authorization/journal/
report/inventory/cleanup formats, each explicitly named v1alpha1, and policy
themis.owned-kind/t2.1-v1. A new binary is the CLI projection. Plans use
SHA-256(domain + newline + compact concrete Go JSON), with a digest envelope on
CLI output. All fields are copied values; approval signs the complete digest.
Unknown/duplicate/case-mismatched fields, trailing values, invalid digests and
unsupported versions are rejected. This is not RFC 8785 or a stable SDK promise.

No T0/T1 format or runtime package gains Kubernetes dependencies. Existing
published contracts, hashes and replay remain compatibility checks. The default
T2.0 Kind test still requires its original owned cluster. Its explicit T2.1
compatibility option accepts only the adjacent true bootstrap ownership record
and verifies both live namespace UIDs; it never fabricates T2.0 ownership.
