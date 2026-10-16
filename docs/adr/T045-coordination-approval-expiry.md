# T045: Preserve independent approval and expiry boundaries

Status: Accepted.

Revalidate frozen request/preview/workload/boot at approval and Start; keep the
engine's fresh identity and grant checks immediately before Apply. Preserve the
20-second Apply, 90-second cleanup and at most three-second fixture deadline.
Publish private authorization first and public approval reference second using
durable exclusive writes. Either half-existing file prevents replacement. Public
references include expiry and approver public key, never bearer/private keys.
Expired grants are not reissued on retry. The fixture owns independent expiry.
