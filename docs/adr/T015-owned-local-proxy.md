# T015: One owned service and user-space proxy

Status: accepted for experimental T1.1 only.

One independent executable process allocates three distinct IPv4 loopback
listeners: synthetic service, fixed dependency proxy and control authority.
The service's application path calls the proxy; the proxy can only forward to
the same process's allocated dependency endpoint. No contract-controlled URL,
script, host networking operation, privileged adapter or provider framework is
accepted. Random instance IDs and a response public key bind the resolved plan.

The sole fault adds 150–300ms of response latency for at most 3s. HTTP clients,
headers, bodies, server connections and concurrent handlers are bounded.
Demo modes expose a deliberately buggy application, an ineffective adapter and
denied cleanup without expanding the target boundary.

Keeping service and proxy together makes whole-fixture termination safe and
removes persistent external mutations. It does not model a real distributed
dependency or prove isolation between arbitrary applications. Proxy-process
death also kills the owned service and cannot establish application recovery.
