# T037: Cancellation acceptance and finalization share a gate

Status: Implemented for T2.2.

Separate runner liveness from a lifecycle gate serializing action acceptance with
intent/fresh admission/Apply/acknowledgment and FINAL/report publication. Check
the stop under that gate and between samples. Acceptance before finalization
forbids PASS; later actions preserve the historical result. The fixture mutex
orders Apply/Remove and owns monotonic expiry independently of both CLI locks.

External actions release the gate before network I/O. A sync stall while the
runner owns it can delay acceptance; a timed-out contender is not acknowledged.
Actual-write pause tests and separate real CLI processes exercise ordering.
There is no distributed transaction, forced OS I/O deadline or execution resume.
