# Reviewed implementation roadmap

Milestones describe implemented scope, not production or independently attested
execution. The current review handoff records actual tests, skips and limitations.

| Milestone | Scope | Status |
| --- | --- | --- |
| T0-T3.3 | Local/Kubernetes synthetic execution and disposable PostgreSQL recovery | Reviewed historical foundations; formats retained |
| T2.4 | Chaos Mesh research and fail-closed planning | Execution remains disabled: final-actuator UID and independent-expiry gates unresolved |
| T4.0 | Signed public evidence bundles and offline verification | Complete |
| T4.1 | Independently signed live witness observations | Complete; whole execution remains unverified |
| T4.2 | Native bounded HTTP dependency-latency actuator | Concrete implementation; restricted real-execution review required |
| T4.3 | Full native authorization, signed witness and evidence correlation | Planned; not implemented by T4.2 |
| T4.4 | Combined fault-execution adversarial hardening | Planned; mandatory T4.2 safety tests are not deferred |
| T4.5 | Security, API and release-readiness consolidation | Planned |

Themis owns the provider-safety contract and a small native L7 fault mechanism.
It does not fork Chaos Mesh or implement a general privileged chaos engine.
Production support, automatic trusted-execution gates, provider marketplaces,
unified frontend and unrelated project integrations remain outside these slices.
