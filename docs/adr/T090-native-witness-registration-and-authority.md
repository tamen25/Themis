# T090: Bind native live readiness to the actual retained authority

Use a separate native registration, not the old Kubernetes synthetic witness plan.
The existing approver privately delivers the unchanged native grant to the runner
and signs a public reference over the complete frozen plan, invocation, original
grant digest, authority-key fingerprints and windows. Neither witness nor publisher
opens the operational authorization file.

Signed live READY follows three real healthy baseline samples. The integrated
runner signs its run-scoped intent under its original Apply authority and commits
that signature plus registration/READY/grant digest into the existing command nonce;
the proxy signs that nonce in its Apply reply. A distinct versioned read-only
authority receipt additionally signs the **actual retained** grant digest and key
fingerprints. This closes the gap where an old reply identified plan/invocation
without explicitly attesting the original grant commitment. Unknown-invocation
reads allocate no state, and polls never persist or renew. Existing fault mutation,
target binding, expiry, replay, cleanup and old wire fields remain unchanged.

A distinct final runner statement commits to original report/journal digests,
execution, candidate and cleanup, preventing a publisher from hiding cancellation
or changing a previously recorded uncertain result. This is an authority-holder
assertion, not code or complete execution attestation; a crash may omit it.

Compare epoch/deadline values only within the same signed proxy boot. No global
clock or independently proven intent durability follows from the nonce link.
See [protocol and limits](../native-witness.md).
