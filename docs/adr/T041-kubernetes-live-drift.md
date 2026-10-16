# T041: Live drift tests require installer ownership

Status: Implemented for T2.2 test infrastructure only.

Runner/controller RBAC remains unchanged. Opt-in tests use installer credentials
only after bootstrap and live cluster/namespace/workload UID checks. They change
generation, UID-precondition-delete the disposable fixture Pod, restart its
container and briefly pause its owned API-server task. Docker operations also
verify Kind node labels. Unrelated contexts/clusters are never modified.

Reject stale plans/old grants, restore exact-name forwarding, create a fresh
preview after invalidation and verify actual application recovery. Real SPDY
closure and runner/journal-writer death exercise expiry. API restoration uses the
exact identified task even during API loss. These operations do not add a fault
adapter, production capability or controller permission.
