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
| T4.4 | Combined fault-execution adversarial hardening | Implemented hardening slice; external handoff records actual adversarial tests and remaining limits |
| T5.0 | Cloudflare source audit and bounded isolated adversarial validation of committed T4.4 | Complete: 124 units/140 checks, 29 selected tests, no confirmed or unresolved source-grounded findings; finite scope and trust limits retained in the external handoff |
| T5.1 | Remediate independently confirmed security findings | No confirmed remediation backlog at audit closure; future findings still require review |
| T5.2 | Release-readiness, CI reliability, portability and build provenance | Candidate engineering changes; external handoff records actual qualification, failures and outstanding release gates |
| T6 | Developer-preview release and broader integration | Planned |

Themis owns the provider-safety contract and a small native L7 fault mechanism.
It does not fork Chaos Mesh or implement a general privileged chaos engine.
Production support, automatic trusted-execution gates, provider marketplaces,
unified frontend and unrelated project integrations remain outside these slices.

The Cloudflare audit belongs in Stage 5 after T4.4, not immediately after T4.2.
It does not replace any required safety, lifecycle or adversarial milestone test.
