# T082: Add a witness mapping and result without upgrading execution trust

Keep T4.0 envelope bytes, old mappings and old verification output unchanged.
`kubernetes-synthetic-witness/v1` includes unchanged runner artifacts, registration
and exact witness journal bytes. Publication remains RETROSPECTIVE_PUBLICATION;
the records separately claim LIVE_OBSERVER_REGISTRATION and actual live samples.
A bounded JSON base64 wrapper preserves original JSONL bytes, including a torn
last write, without repairing or discarding that evidence during publication.

`VerifyObserved` and new-mapping CLI output separate normal evidence results from
observationCorroboration. External witness policy is independent of publisher
policy. Corroboration never changes the original candidate verdict, cancellation,
cleanup or whole-execution classification. Trusted execution is always INCONCLUSIVE
and NOT_INDEPENDENTLY_ATTESTED; schema tests enforce this even for valid samples.
