# T095: Consume interrupted durable attempts and pin the actual journal writer

Status: Accepted

A successful durable proxy intent consumes the original attempt before its
post-persistence cancellation/validity check. If the effect has not begun,
interruption leaves a retained fenced epoch. It cannot create a later first
intervention by automatically retrying the original invocation. Applied epochs
retain their existing one-use behavior and original monotonic deadline.

The protected control journal's name, length and hash alone do not establish
the identity of an open writer. Linux permits replacing a name with an identical
private file while the original writer remains open. Compare writer.Stat with
the opened path before writing and revalidate the named file after Sync.
Poison future control mutations on uncertainty. Preserve independent local expiry.

Use a small private file interface for actual IO-fault tests. No runtime flag,
environment backdoor or new execution authority selects the faults.
This checks a local durability invariant, not resistance to a malicious trusted
administrator. Windows denied the demonstrated rename; Linux exercised it.
