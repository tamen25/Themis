# T081: Infer phases from nonce-bound fixture responses and preserve disagreement

Three independently measured healthy baseline samples produce a durable signed
readiness record before the operator starts the existing runner. Signed fixture
responses identify no active invocation, the exact registered active invocation,
then no active invocation again. Mixed responses are transition uncertainty. A
session seeing intervention before readiness cannot corroborate that run.

The witness signs its client timing; the fixture signs only response values and
its existing proxy hold. Offline checks require their nonce/identity bindings,
bounded timing, phase ordering and supported predicates. Witness nonces must not
be runner request IDs. Source contradictions and conflicting effect/application
observations are explicit. UTC does not align trustworthy clocks across processes;
correlation uses the exact plan/invocation and authenticated response identity,
not claimed absolute time or an assumption of causal certainty. Proxy hold alone
does not corroborate application effect: require a degraded response plus the
witness's own application delay of at least 50 ms and 40 ms above baseline.
Recovery must return within the approved ceiling and baseline margin.
