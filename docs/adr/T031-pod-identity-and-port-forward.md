# T031: Bind one Pod and one fixture boot

Status: Implemented for owned Kind T2.1; pending independent review.

Resolve a fixed Deployment through its ReplicaSet to exactly one ready Pod.
Freeze cluster/namespace UIDs, VerificationRun UID/generation/recompiled preview,
Deployment UID/generation/template, ReplicaSet UID, Pod name/UID/spec, running
container ID, declared image and observed runtime image ID. Trusted setup pins
both image identities: an OCI index digest need not equal containerd's selected
platform-manifest digest. Do not compare those hashes as though they were the
same object.

Port-forward through client-go to that exact Pod name on port 8080, with a
random allocated IPv4 loopback listener. Runner RBAC allows forwarding only to
the installed Pod name. There is no Service forwarding or automatic reconnection
to a replacement. Authenticate a nonce-bound boot identity and response public
key, bind it into approval, and recheck Kubernetes identity before/after opening
the connection and immediately before Apply. Reconnect for cleanup only when
the original identity still matches.

The API's name-based port-forward endpoint offers no UID precondition. Fresh
reads plus the fixture's Downward API UID and boot key detect honest replacement
and restart; they are not an atomic Kubernetes transaction or protection from a
malicious cluster administrator/image. A post-Apply identity check detects drift
and triggers cleanup. An unavailable/replaced endpoint remains explicit unknown,
not evidence of application recovery.
