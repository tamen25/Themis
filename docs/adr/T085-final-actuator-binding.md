# T085: Bind authority at the actual proxy boot

A separately signed trusted installation binding relates freshly read exact
cluster/namespace/workload/Pod/container/image identities to application, proxy and
dependency boot keys. The proxy itself checks its Downward API UID, random boot,
key and complete latched binding, then challenges the fixed application/dependency
identities before mutation. The runner independently checks the Kubernetes chain
at Apply and completion. Replacements cannot inherit original grants, including
after explicit fresh binding. No selector or Service routing transfers authority.

Installer binding and Downward API are trusted claims, not external container or
hardware attestation. Shared administrators and malicious images remain outside
the demonstrated boundary. This does not resolve Chaos Mesh's different actuator.
