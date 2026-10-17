# T074: Signatures authenticate publishers, not infrastructure truth

Status: Implemented for retrospective T4.0 publication; review required.

Keep artifact integrity, externally pinned publisher authenticity and execution
claim validity separate. A trusted Ed25519 publisher can sign fabricated PASS.
Every offline result therefore retains NOT_INDEPENDENTLY_ATTESTED execution and
INCONCLUSIVE trusted execution verdict. Original source verdict and recomputed
candidate remain visible, including FAIL and unresolved cleanup. No historical
format, journal, verdict, execution grant or fault boundary changes.

The publisher's name, key fingerprint and engine scope must match an independently
provided current, unrevoked policy. Embedded observation keys never provision
publisher trust. Publication keys are distinct from source authority keys.
Publication time is a signed claim, not a trusted timestamp. Rotation, revocation
and distributing authentic trust policy remain explicit operator responsibilities.
