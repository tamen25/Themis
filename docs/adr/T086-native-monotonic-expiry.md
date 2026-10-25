# T086: Keep expiry inside the response-delay process

Cap response delay at 200 ms and fault-active lifetime at two seconds. Convert the
remaining approval window once into a monotonic deadline. A timer, request-path
check and interruptible/clipped in-flight waits enforce expiry without runner,
controller, API, cleanup, disk or lease renewal. Disk/control gates do not hold
the fault-state mutex. At restart use a new boot/key, no binding and no fault;
never replay a control journal into active behavior.

An in-path crash can break dependency availability. Expired injection is distinct
from recovered application traffic. Supported scheduler/clock/network assumptions
are explicit; arbitrary host/kernel/filesystem failure and power loss have no
absolute availability or wall-clock guarantee.
