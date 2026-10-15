# T016: Independent monotonic expiry

Status: accepted for experimental T1.1 only.

The detached fixture process retains monotonic authorization, experiment lease
and fault deadlines. Fault expiry is the earlier of the lease deadline and the
bounded requested duration. A timer removes the active fault and closes its
delay channel. Requests additionally check the deadline and select cancellation,
removal and expiry. An independent process context closes all owned listeners
within the fixture's configured 15s–2m lifetime.

No disk or network I/O occurs while holding the fault mutex. Journal stalls,
CLI death and cleanup failure cannot extend the fault. Applied handles retain
their original receipt after removal/expiry: duplicate calls never recreate or
extend the intervention. There is no persistent host networking state.

Guarantees assume a functioning OS scheduler/clock and apply while the process
can serve traffic. A suspended process serves no requests; elapsed deadlines are
checked on resumption. Process-kill integration tests run against actual CLI and
fixture executables. Power-loss storage durability and macOS crash behavior are
not established by those tests.
