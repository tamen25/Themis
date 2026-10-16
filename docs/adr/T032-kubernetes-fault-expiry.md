# T032: Fault-side monotonic expiry and retained invocation receipts

Status: Implemented for owned Kind T2.1; pending independent review.

Approval permits first Apply for 20 seconds. A fault lasts at most three seconds,
bounded by both the exact approved duration and the remaining Apply grant.
Cleanup uses a different command key and expires 90 seconds after approval.
Each command has an authenticated nonce and freshness bound. Capacity limits
fail closed instead of evicting invocation or replay records.

The fixture retains a monotonic deadline, independent timer and request-path
deadline check. Removal closes the wait channel. No disk, HTTP or runner journal
operation occurs under the fault mutex. A runner crash, controller restart,
disconnected port-forward, missing Remove or blocked journal cannot renew it.
Repeated Apply returns the original receipt, including after removal/expiry;
Remove before Apply permanently fences that invocation. Lost acknowledgements
remain ambiguous and are never retried as a fresh invocation.

Expiry assumes an operating scheduler/monotonic clock while serving traffic. A
suspended process serves no requests and checks deadlines on resumption. Process
death leaves no persistent kernel/network mutation. Neither death nor expiry
alone proves that normal application responses have recovered.
