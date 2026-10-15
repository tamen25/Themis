# T014: Trusted local authorization

Status: accepted for experimental T1.1 only.

T0 digest approval is not authentication and cannot enable faults. A separate
owned fixture authority recompiles the resolved immutable plan, checks trusted
policy, and issues a sealed 20s authorization after explicit digest approval.
It binds OS actor/host, fixture/service/proxy IDs, action and adapter version.
An in-memory registry enforces single-use claim and one run per fixture.
Contracts cannot disable approval or relax trusted bounds.

Control requests/responses use domain-separated nonce-bound HMAC proofs; the key
never travels over HTTP. This avoids disclosing it if a loopback port is reused
between identity resolution and a control request. Nonces are bounded to 4096
per fixture, then fail closed. Scoped read tokens cannot authorize mutations.
Protected owner-only Windows DACLs use `x/sys/windows`; Unix checks actual UID
and private modes. Unsupported storage permissions disable the path.

Same-account processes and administrators are trusted. This is not independent
human authentication, distributed policy, or production authorization. Denial
must cause zero fault applications, as checked by actual adapter apply counts.
