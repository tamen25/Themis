# T022: Provenance without execution attestation

Status: Accepted for T1.2 local reports and inspection.

New reports classify locally collected observations, unsigned local replay and
imported external evidence. Fixture-response signatures and unauthenticated
client timing are separate fields. The journal is always UNSIGNED and execution
attestation UNVERIFIED. Import uses a versioned envelope so even a legacy report
can retain its exact published fields while gaining an explicit source label.
No Evidence Service, Sigstore integration or remote release gate is implemented.

Read-only status reports the last validated journal prefix, original historical
report/verdict, live fixture/runner/fault state and last cleanup receipt separately.
A torn/corrupt journal never becomes a complete replay merely because a valid
prefix exists. A saved report without matching complete journal is an unverified
recorded claim. A later cleanup receipt can resolve resources while the original
CLEANUP_PENDING or canceled result remains unchanged.

Operation labels and scoped immutable failure records identify the attempted
step and known application state. Experiment budget, claim lease, acknowledged
fault expiry, fixture lifetime and cleanup limit are distinct. Journal failures
poison the writer; receipt publication failure remains pending/exit 7 even if
listeners are closed. Test boundaries wrap actual local writes and HTTP calls.

Synchronous filesystem calls are not made forcibly interruptible. Tests prove
bounded independent fault expiry while a CLI writer is stalled, not guaranteed
CLI responsiveness under arbitrary OS I/O failure, suspend or power loss.
