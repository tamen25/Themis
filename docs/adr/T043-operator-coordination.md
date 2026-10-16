# T043: Explicit operator coordination

Status: Accepted for T2.3 owned synthetic Kind only.

Implement T042 as a small `themis-kube coordinate` workflow in the existing runner
package. Preparation freezes the requested specification and actual planner preview
beside an independently reconstructed execution plan. Recompile and compare the
entire preview body and digest, then independently resolve Pod/container/boot.
Preview is never authority. The existing Kubernetes Ed25519 grant, operator
identity and restricted runner execute the actual experiment. No local HMAC is
Kubernetes authority. No controller change, execution event handler or new engine.
