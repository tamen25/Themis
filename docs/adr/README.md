# Architecture decisions

Records describe accepted decisions for the implemented foundation. Future
requirements in a record do not imply an existing execution component.

| Record | Decision |
| --- | --- |
| [T001](T001-optional-integrations.md) | Themis is independent of Arete, Argus and CloudOps |
| [T002](T002-local-first-scope.md) | Local modular monolith and explicit first-slice boundary |
| [T003](T003-verdict-integrity.md) | Four verdicts and independent evidence prerequisites |
| [T004](T004-intervention-proof.md) | Intervention proof is necessary for fault PASS |
| [T005](T005-planning-safety.md) | Bounded local input and no execution authorization |
| [T011](T011-deterministic-artifacts.md) | Strict schema, immutable snapshots and specified digests |
| [T012](T012-local-execution.md) | Bounded local observations, durable journals and unsigned replay |
| [T013](T013-threshold-semantics.md) | Preserve v1alpha1 normalization and compare count ratios exactly |
| [T014](T014-trusted-local-authorization.md) | Fresh plan-bound local capability and trusted ownership boundary |
| [T015](T015-owned-local-proxy.md) | One independent owned service and fixed dependency proxy |
| [T016](T016-independent-fault-expiry.md) | Independent monotonic leases and bounded process lifetime |
| [T017](T017-independent-client-evidence.md) | Paired client measurements, signed identities and evidence limits |
| [T018](T018-journal-and-cleanup-recovery.md) | Durable intent, conservative replay and idempotent reconciliation |
| [T019](T019-versioned-experiment-contracts.md) | Separate fault-capable formats preserving T0 artifacts |
| [T020](T020-intent-and-artifact-versions.md) | Prerequisites before durable intent and version-aware replay |
| [T021](T021-local-cancellation-protocol.md) | Cross-process action coordination and permanent worker fence |
| [T022](T022-provenance-and-operation-diagnostics.md) | Explicit provenance, bounded recovery and storage diagnostics |
| [T023](T023-kubernetes-api-boundary.md) | Namespaced Kubernetes projection and separate controller |
| [T024](T024-kubernetes-ownership-rbac.md) | Status ownership and narrow RBAC |
| [T025](T025-kubernetes-safety-model.md) | Kubernetes dry-run safety and future authorization |
| [T026](T026-kubernetes-target-identity.md) | Immutable target identity and deterministic plans |
| [T027](T027-kubernetes-reconciliation-status.md) | Idempotent status and latched invalidation |
| [T028](T028-kubernetes-dry-run-only.md) | No Kubernetes assertion or fault execution |
| [T029](T029-kubernetes-execution-authorization.md) | Separate operator runner and Kubernetes execution grants |
| [T030](T030-in-cluster-synthetic-fixture.md) | Preinstalled bounded application-path fixture |
| [T031](T031-pod-identity-and-port-forward.md) | Exact Pod, owner chain, image and boot binding |
| [T032](T032-kubernetes-fault-expiry.md) | Independent monotonic expiry and retained invocation receipts |
| [T033](T033-kubernetes-intervention-evidence.md) | Signed request holds, independent measurements and conservative verdicts |
| [T034](T034-kubernetes-cleanup-and-crashes.md) | Cleanup inventory, crash recovery and immutable history |
| [T035](T035-kubernetes-experiment-formats.md) | New experiment artifacts preserving the dry-run API |
| [T036](T036-kubernetes-cancellation.md) | Protected cross-process cancellation and exact invocation fence |
| [T037](T037-kubernetes-finalization-order.md) | Cancellation acceptance ordered with Apply and finalization |
| [T038](T038-kubernetes-current-status.md) | Separate historical evidence and fresh current status |
| [T039](T039-kubernetes-reconciliation-trust.md) | Inventory-based cleanup, immutable history and publication failure |
| [T040](T040-kubernetes-evidence-provenance.md) | Strict offline verification without execution attestation |
| [T041](T041-kubernetes-live-drift.md) | Owned live adversarial setup and target restoration |
| [T042](T042-controller-runner-coordination.md) | Minimal future coordination protocol without new orchestration |
| [T043](T043-operator-coordination.md) | Explicit operator boundary and independent preview reconstruction |
| [T044](T044-immutable-coordination-invocations.md) | Immutable invocation and consumed duplicate/crash claims |
| [T045](T045-coordination-approval-expiry.md) | Independent approval, half-publication and unchanged expiry |
| [T046](T046-coordination-crash-cancel.md) | Ordered cancellation before inventory and conservative recovery |
| [T047](T047-coordination-index-provenance.md) | Versioned operational index without historical attestation |
| [T048](T048-status-polling-replay-budgets.md) | Bounded separate polling/mutation replay protection |
| [T049](T049-future-native-coordination.md) | Deferred native execution ownership and unchanged controller RBAC |
| [T050](T050-chaosmesh-hard-gates.md) | Research findings block external activation; planning/admission fallback |
| [T051](T051-external-provider-artifact.md) | Separate versioned external intent without synthetic authority reuse |
| [T052](T052-chaosmesh-installation-separation.md) | New owned schema-only cluster and read-only runtime permissions |
| [T053](T053-external-evidence-and-expiry.md) | Effect, recovery and independent expiry remain hard prerequisites |
| [T054](T054-defer-provider-framework.md) | Concrete blocked provider boundary without rewriting working engines |
