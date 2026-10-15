# T021: Scoped cancellation across local CLI processes

Status: Accepted for one owned fixture, one claimed run and one fault.

A runner-held OS file lock expresses liveness and is released by process death.
A second, short-lived lifecycle lock orders external action acceptance against
the runner's intent/Apply/acknowledgment section and terminal finalization.
An action accepted before finalization publishes a private immutable action
intent and one canonical stop request before releasing the lock or mutating the
fixture. Finalization rechecks the stop request under that lock. Accepted stop
requests prevent PASS; a later action preserves an already-finalized verdict.

The exact authenticated worker claim is quiesced permanently before shutdown.
The same worker mutex protects quiescence and first Apply. Once fenced, first
application is denied; duplicate Apply can inspect the prior receipt without
reapplying or extending a fault. Repeated cancel/cleanup commands are safe and
record separate immutable receipts. No PID is killed by cancellation or cleanup.

Only the protected inventory, local actor and fresh instance proof authorize
mutation. Journal validity is not a cleanup authority. Missing/corrupt inventory
denies mutation rather than guessing identity from events or network ports.
Authenticated control never goes to a replacement listener. Actual refused
connections to all inventoried listeners establish cleanup independently of
worker responses; they do not establish recovery.

Control and residual checks use a separate two-second context. The local
lifecycle lock can remain held across a blocked filesystem sync in the critical
Apply section. External acceptance then times out rather than bypassing the
protocol. The fault and fixture still expire inside the independent process.
This limitation is explicit; no general workflow controller is added.
