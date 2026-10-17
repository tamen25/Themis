# T069: Target fidelity does not erase acknowledged loss

Status: Implemented for disposable local T3.2; independent review required.

Create the generated named restore point after base backup completion. Recovery
must pause on the exact target replay LSN and prove expected rows, payloads, XIDs,
schema and invariants before promotion. Require actual completion and a timeline
history branch at that LSN, then committed application write/read readiness.
Physical recovery preserves the source system identifier; independent container,
volume and boot identities establish a distinct destination.

Compare all externally acknowledged receipts, including later commits. Correct
recovery to an earlier point can still violate zero acknowledged loss. Retain
in-flight uncertainty and unknown cross-session loss time. Offline reports and
embedded keys cannot authenticate whole execution or establish trusted PASS.
