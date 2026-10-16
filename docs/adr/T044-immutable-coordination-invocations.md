# T044: One durable claim per approved invocation

Status: Accepted.

A new proposal binds a random proposal identity, request UID/generation/spec and
contract digests, preview, full independently resolved plan, operator and approver.
An approval binds exactly that proposal/plan and one invocation. Start writes an
immutable claim before calling the existing engine. Any duplicate, ambiguous or
failed start consumes that invocation permanently; it cannot renew or resume.
Observed approval admission failure latches invalidation even after reversion.
Recovery requires a new proposal and explicit operator approval, never guessed
identity. Private inventory also binds its original directory and setup.
