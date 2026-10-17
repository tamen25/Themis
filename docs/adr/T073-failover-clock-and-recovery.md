# T073: Failover uncertainty, one-use effects and historical cleanup

Status: Implemented for disposable local T3.3; independent review required.

Termination/fencing and promotion require separate keys and reviewed prepared
state. Durable once-only claims and verified append-only intent precede effects.
Observe original stopped state, then remove that exact stopped container and
independently verify absence before promotion. Revalidate the original standby,
receipt coverage, journal and scoped promotion approval immediately before its
one-time request. Ambiguous effects are never retried or resumed.

One runner clock bounds failover-to-write-readiness. Upper-bound compliance passes;
lower-bound violation fails; straddling uncertainty is inconclusive. Track exact
acknowledged loss separately from unknown elapsed RPO. A read-only standby or a
successful promotion command is insufficient application recovery.

Independent inventory-based cleanup survives process death and journal damage,
but not lost original identity or expired cleanup authority. Reconciliation keeps
historical bytes unchanged and publishes new receipts. Cleanup remains an
independent operational disposition; offline evidence never authenticates PASS.
No automated leader election, janitor or general HA control plane is introduced.
