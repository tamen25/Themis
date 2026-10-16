# T050: External provider research can require stopping activation

Status: Accepted for T2.4 planning/admission fallback; execution blocked.

Audit Chaos Mesh v2.8.5 at commit e020a2df5a69e99e49d2a3dda9e6be22237fd0d8.
Select only NetworkChaos delay as a candidate. Provider name-based Pod lookup does
not enforce the approved Pod UID; the traffic-control RPC carries no hard-expiry
deadline. Independent effective cleanup has not been demonstrated. Follow the
milestone's explicit hard gate: no external fault, grant issuer or actuator.
Implement only immutable planning, unconditional denial and negative tests.
Record NOT READY FOR T3.0 rather than broadening authority to manufacture a demo.
See [source audit](../chaosmesh.md) for pinned sources and precise inferences.
