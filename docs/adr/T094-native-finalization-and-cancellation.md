# T094: Serialize original finalization with accepted cancellation

Status: Accepted

A real owned-Kind reproduction accepted cancellation after cleanup but before
the original runner FINAL while it awaited its separate observer. The reviewed
runner could then publish SUCCEEDED/PASS. Cleanup had not made finalization
immune to a still-accepted stop.

Take the original lifecycle gate again before final journal/report publication,
recheck the durable cancellation record and caller context, and hold that gate
through append/Sync and exclusive report publication. A pre-final accepted stop
forces CANCELLED/INCONCLUSIVE; inability to acquire the gate cannot produce PASS.
Later current-state cleanup/cancellation preserves the completed history.
The signed runner wrapper and all historical source wire formats remain unchanged.

Test both orderings with actual runner/cancel processes, real independent signed
observations and public bundles in newly owned disposable Kind clusters.
