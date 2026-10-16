# T030: Preinstalled synthetic application, proxy and dependency

Status: Implemented for owned Kind T2.1; pending independent review.

Install one digest-pinned, non-root Go fixture before admitting an experiment.
One process owns an application endpoint, a user-space response-latency proxy and
a fixed loopback synthetic dependency. Application requests call the proxy; its
only upstream is that process's direct endpoint. A healthy variant returns a
bounded fallback after 75ms. The deliberately buggy variant returns 503 instead.
The explicitly approved no-op and cleanup-denied scenarios test evidence and
cleanup handling. They do not broaden the permitted fault primitive.

The fixture has no Kubernetes API credentials, host networking, privileges,
shell, arbitrary destination, resource patch or installation interface. Its
server caps accepted connections, concurrent handlers, headers, bodies and request
duration. The Deployment has CPU/memory limits, read-only root filesystem,
seccomp and dropped capabilities. No Service or host port exposes it.

This is an instrumented application-path latency experiment, not a packet-level
network fault, production proxy or independent distributed dependency. The
synthetic target and proxy share a process and trust domain. Fixture death stops
the application too, which cannot establish successful recovery.
