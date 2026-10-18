# Reviewed implementation roadmap

Milestones describe implemented scope, not production or independently attested
execution. The current review handoff records actual tests, skips and limitations.

| Milestone | Scope | Status |
| --- | --- | --- |
| T0-T3.3 | Local/Kubernetes synthetic execution and disposable PostgreSQL recovery | Reviewed historical foundations; formats retained |
| T2.4 | Chaos Mesh research and fail-closed planning | Execution remains disabled: final-actuator UID and independent-expiry gates unresolved |
| T4.0 | Signed public evidence bundles and offline verification | Complete |
| T4.1 | Independently signed live witness observations | Complete; whole execution remains unverified |
| T4.2 | Native bounded HTTP dependency-latency actuator | Independently reviewed within owned disposable Kind boundary |
| T4.3 | Native signed-witness/evidence integration | Implemented slice; current handoff records actual review evidence |
| T4.4 | Combined fault-execution adversarial hardening | Planned; mandatory T4.2 safety tests are not deferred |
| T5.0 | Comprehensive Cloudflare security audit using the security-audit skill, operated by Codex | Planned for Stage 5; not installed or executed during T4.3 |
| T5.1 | Remediate confirmed security findings and rerun regression/adversarial checks | Planned after the audit |
| T5.2 | Release-readiness, stable APIs, CI and documentation | Planned after remediation |
| T6 | Developer-preview release and broader integration | Planned |

Themis owns the provider-safety contract and a small native L7 fault mechanism.
It does not fork Chaos Mesh or implement a general privileged chaos engine.
Production support, automatic trusted-execution gates, provider marketplaces,
unified frontend and unrelated project integrations remain outside these slices.

The Cloudflare audit belongs in Stage 5 after T4.4, not immediately after T4.2.
It does not replace any required safety, lifecycle or adversarial milestone test.
