# T096: Preserve adversarial evidence and conservative verification semantics

Status: Accepted

T4.4 retains the reviewed T4.3 formats and trust boundaries. Keep failed baseline
reproductions and corrected regressions with exact child exits, source manifests,
signed public records, immutable historical bytes and independently supplied
public policies. Separate actual live faults, real local IO/process deaths and
bounded controlled tests. Never count an opt-in skip as a live integration run.

An unsupported native source mapping returns unsupported exit 7 after publisher
trust is established. An unevaluated witness identity under an unknown mapping
must not mask that result as trust exit 5. Supported mappings retain existing
publisher/witness trust, contradiction and incompleteness dispositions.

Audit protected publication at real process-death cuts without production
failpoint configuration. Record OS-specific file and lock semantics. A
successful Sync is not a power-loss proof. Offline isolation on the same host
does not imply a separate trusted administrator or hardware attestation.

The whole-execution classification remains NOT_INDEPENDENTLY_ATTESTED and
INCONCLUSIVE. T5.0 is the separate Cloudflare security-audit skill operated by
Codex; no installation or audit run is part of T4.4.
