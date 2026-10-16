# T046: Crash-aware coordination and ordered cancellation

Status: Accepted.

Use existing owner-only durable files and local OS locks. The outer coordination
gate precedes the run lifecycle gate; legacy cancellation takes only the inner
gate. Coordinated Apply and finalization read both stop records under those gates.
This orders cancellation even before execution inventory is published. Never hold
the outer gate during remote cleanup. Missing inventory after a claim remains
unknown/pending; do not reconstruct it from the proposal. Before any claim, an
approved stop can fence the unused invocation using original private approval.
Controller restart never executes. Local locks assert no distributed leadership.
Late cancellation preserves immutable completed history and separate receipts.
