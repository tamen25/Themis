# T048: Bounded status polling must preserve mutation capacity

Status: Accepted; regression reproduced against T2.2.

The old shared 4096-nonce registry could reject legitimate Remove after status
polling. Retain separate status and mutation maps, each capped at 4096. Reject a
nonce already present in either map, including re-signed cross-action reuse. Do
not evict old nonces or change authentication, command freshness, grant versions,
invocation fences or deadlines. Exhausted status reads fail closed while mutations
retain their independent capacity. Independent expiry still works if control
fails. Actual HTTP tests and owned Kind cover the active boundary and removal;
HTTP tests also verify expiry and cross-action replay. This is bounded monitoring,
not an unlimited status service; mutation/invocation capacity remains finite.
