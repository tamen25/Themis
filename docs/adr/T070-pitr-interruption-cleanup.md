# T070: Interruption consumes execution but preserves cleanup

Status: Implemented for disposable local T3.2; independent review required.

Keep preparation and failure one-use claims. Sync intent before the exact SIGKILL;
observe the original stopped process independently. Partial backup/WAL publication,
ambiguous effect, missing target proof, canceled context or incomplete journal
cannot produce PASS. No invocation resumes after process death.

Separate cleanup authority covers the sealed original inventory, not execution
history or backup availability. Preflight every object, remove only exact owned
IDs and observe absence with successful Docker calls. Later receipts preserve
historical bytes. Docker volumes lack an atomic immutable UID deletion fence;
trusted local Docker administration remains an explicit assumption. Host private
backup/WAL retention remains visible and separate from Docker cleanup.
