# Offline scanner gate controls

`GO-2099-0001` is synthetic and makes no security claim about SHA-256. It marks
`crypto/sha256.Sum256` as affected solely to keep the CI gate regression
independent of changing public advisories. The affected program calls that
function; the clean program does not import it. Neither program needs a network,
dependency download, credential, container or fault authority.

Run `python scripts/tests/test_ci_security.py` for orchestration/recorder tests.
With the pinned govulncheck executable and exact Go SDK on PATH, run
`python scripts/tests/security_gate_integration.py --scanner /absolute/path/to/govulncheck`.
The latter runs both programs against this file-based snapshot and checks actual
native exits, retained JSON findings and malformed database failure. Its temporary
raw reports are preserved when `--output` selects a new explicit directory.
