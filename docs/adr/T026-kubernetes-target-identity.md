# T026: Freeze identity rather than selectors

Status: Accepted for T2.0 previews.

Resolve one exact namespaced apps/v1 Deployment using fresh reads. Require its
expected UID and generation and matching observed generation. Freeze namespace/
cluster UIDs, digest-pinned declared images, pod-template digest and sorted owner
reference digest. A synthetic label is only an extra filter, not authorization.

Canonical plan bytes bind these facts, contract/spec digests, run UID/generation
and policy/planner versions. Timestamps/resourceVersions are excluded; snapshots
are independent copies. Running pod image IDs are not observed or attested.
Cross-object reads are not atomic. Future mutation requires trusted live
revalidation at its own admission/application boundary.
