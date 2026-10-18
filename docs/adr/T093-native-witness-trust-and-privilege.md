# T093: Pin native witness scope independently from publisher trust

External current, unrevoked policies independently pin publisher name/key and
witness name/key, exact engine, run/plan/invocation/session, registration/target
digests and fixed routes. Embedded keys and policies packaged by the publisher
never provision trust. Reject fixture, installer, approver, Apply, cleanup,
publisher and witness role-key reuse.

The owned installer adds one ServiceAccount and bindings to the existing named
read/forward Roles, without broadening their rules or existing actors' permissions.
The witness receives neither fault authority nor another actor's private signing
key. Its data Pods still have no API token, privilege or host mutation path.

The demonstration shares one OS user/host/admin. Keys and Kubernetes principals
do not establish hardware or independent-machine attestation or protect against
that administrator's collusion. Trusted policy distribution, verifier clock,
installer images/Downward API and key custody remain operator responsibilities.
