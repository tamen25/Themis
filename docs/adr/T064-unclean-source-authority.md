# T064: Exact-source unclean failure requires new authority

Status: Accepted for T3.1's disposable local synthetic scope.

Preparation and SIGKILL have separate signed scopes and durable one-time claims.
The second grant binds the actual published backup digest/size/identity, original
engine/socket/actor/directory/plan/source/system ID, independent restore target,
operation, execution expiry and cleanup deadline. T3.0 or preparation grants
cannot authorize this effect. Sync intent, recheck identity, then invoke exactly
one `docker container kill --signal KILL FULL_ID`. Ambiguous acknowledgement is
not retried and cannot establish PASS. No daemon or host failure is induced.

Cleanup has a separate key/capability over the sealed original inventory. It uses
an independent deadline and durable intent, exact owned IDs, successful absence
observations and no execution-journal authority. Missing/corrupt inventory denies
cleanup; no plan fallback or discovery adoption is allowed. Cleanup may remove
the exact original container after a restart, while execution refuses that boot.
Container/volume/network identities are preflighted before the first deletion.
Local actor and Docker admin remain trusted; no atomic Docker volume-UID fence
is claimed. A killed runner must be reconciled rather than resumed.
