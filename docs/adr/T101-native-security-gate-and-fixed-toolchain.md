# T101: Retain scanner evidence and gate with native scanner semantics

Status: Implemented; qualification is recorded separately from hosted CI.

The T5.2-R candidate ran govulncheck's JSON mode through the honest command
recorder. JSON mode returned zero with reachable vulnerability findings, while
the same source, SDK, scanner and frozen database returned three in native mode.
The recorder must preserve the child status; zero from JSON mode is not a
vulnerability verdict.

Keep a structured scan, validate its JSON framing/configuration/SBOM, and run a
separate native source gate using the same executable, source, environment and
file-based advisory snapshot. The decoder does not decide vulnerability
semantics. The native scanner decides whether reachable findings fail the gate;
launch, database, decoding and tool errors also fail. There is no shell pipeline.
A syntactically complete prefix is not proof of scanner completeness; the native
gate independently recomputes findings even when the JSON report looks valid.

CI freezes official advisories for every selected module plus stdlib/toolchain,
requires a stable database timestamp across capture, and retains snapshot hashes.
Offline positive/clean controls use a clearly synthetic advisory over a harmless
function. They do not depend on a live public vulnerability remaining available.
Raw reports and exact recorder exits remain review evidence after failure.

Pin Go 1.26.10 in go.mod for the upstream urgent crypto/x509 fix GO-2026-6809.
Actions setup-go, preview exact-version checks and installer builds derive their
SDK from go.mod. Scratch images copy those freshly built binaries and contain no
separate builder SDK pin. Verify official distribution checksums for offline SDKs;
old binaries and historical signed fixtures retain their original identities.
This changes no dependency version, runtime authority, fault deadline, sample
threshold, recovery bound or whole-execution trust semantics.

Local scans/rebuilds do not establish hosted CI, macOS execution, elevated Windows
coverage or live Kind/PostgreSQL qualification. Those remain separate gates.
