# T027: Idempotent status and latched invalidation

Status: Accepted for T2.0.

Keep the first immutable preview and current conditions in the status subresource.
Use fresh API reads and resourceVersion-guarded updates. Unchanged reconciliation
does not rewrite status or timestamps. Five-second polling avoids Deployment
list/watch privileges. Restart reconstructs state from API objects.

Changed plan inputs invalidate the first preview: preserve its history, clear the
current digest and show a candidate where possible. Latch invalidation so reverted
inputs cannot revive that run; create a new VerificationRun. Missing reads remain
explicit, never PASS. Status is unsigned and grants no execution authority. No
finalizer is needed because this controller creates no execution resources.
