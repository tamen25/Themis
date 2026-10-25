# Live application observation (T4.1)

## Threat model and trust boundary

An archive importer and a publisher may fabricate reports, recompute unsigned
journals, substitute embedded keys, replay responses, omit samples or lie about
time. A separately provisioned witness key authenticates that witness's own
application requests and client timing, under an external exact-scope policy.
It does not establish an honest administrator, infrastructure, trusted UTC clock,
physical independence or absence of collusion. Whole execution remains
NOT_INDEPENDENTLY_ATTESTED and trusted execution remains INCONCLUSIVE.

The runner retains fault authority and cleanup. The fixture retains independent
expiry and its existing response signing key. A separate witness process receives
only its dedicated key, public experiment registration and dedicated restricted
Kubernetes credentials. It never receives execution/cleanup capabilities and
cannot mutate workloads. The publisher only authenticates the final artifact set.
The offline verifier reads public bytes and two independently supplied policies.

## Concrete protocol

`themis.live-observation/v1alpha1` uses compact typed Go JSON, Ed25519 with an
explicit domain, SHA-256 and newline-delimited individually signed records.
Registration binds one public T2.3 proposal, original run/plan/invocation, exact
cluster/namespace/Pod/fixture boot identity, fresh random session and a bounded
observation window/sample budget. It requires explicit operator digest approval.
Source keys and publisher keys cannot be witness keys.

The observer independently resolves the pinned target through its own credentials
and exact-Pod forwarding stream. A durable signed session start precedes fresh
nonce-bound direct/proxy/application requests. Three healthy baseline samples
produce a durable readiness record before the operator starts the unchanged
runner. Samples infer phase from the fixture's authenticated invocation identity:
empty before the active invocation, the registered invocation during it, then
empty after it. Mixed identities are transition uncertainty, never counted as
confirmed measurements. A request made after intervention cannot produce readiness.

Every record binds signer/session/process, exact registration digest and target,
sequence/previous hash, nonce, phase, independent monotonic offsets and claimed
UTC. The witness authenticates its own timing; fixture signatures authenticate
only response values. Signed end/interruption and bounded coverage remain distinct
from the presence of archive files. A dead process leaves a signed prefix;
recovery never resumes that session or invents an end/sample.

The new explicit Kubernetes witness source mapping includes the unchanged runner
artifacts plus registration and witness journal. T4.0 envelopes and old mappings
remain compatible; publication itself stays RETROSPECTIVE_PUBLICATION. Separate
observationCorroboration findings report trusted correlated observations,
incompleteness, contradiction, invalid signature, untrusted identity or unsupported
source. None upgrades the runner's verdict, cleanup state or execution trust.

The supported boundary is one installer-owned disposable Kind and one synthetic
fixture. No arbitrary endpoint, new fault primitive, PostgreSQL witness, controller
privilege expansion or general monitoring service is introduced. The handoff
distinguishes actual execution evidence from pure tests and unexecuted scenarios.

## Wire bytes, signatures and limits

The normative structures are `pkg/liveobservation/model.go`. Records are compact
typed Go JSON in declaration order with default HTML escaping, UTF-8, no whitespace
and one LF per JSONL record. Optional probe responses are omitted when unavailable;
arrays are nonnull. Strict parsing rejects unknown/duplicate/case-mismatched
fields, noncanonical bytes, invalid versions/domains and resource excess. This is
not RFC 8785. Source-authority fingerprints are sorted, distinct SHA-256 values.

Registration signature: Ed25519 over
`themis.live-observation.registration.v1\n` plus compact registration JSON with
signature null. Registration identity is SHA-256 of its complete signed JSON.
For each record, clear hash and signature (empty string / null), then SHA-256
`themis.live-observation.record.v1\n` plus those JSON bytes. Set hash and sign the
same domain prefix plus JSON with that hash and signature null. Stored signatures
and public keys are standard JSON base64; fingerprints/hashes are lowercase hex.
Each record repeats its registration digest, signer/session/process/PID, immutable
run/plan/invocation and exact target. Sequences start at zero and cannot be dropped,
duplicated, reordered, resumed or followed after a terminal record.

| Resource | Bound |
| --- | --- |
| Registration validity / actual sampling epoch | 20 seconds / 12 seconds |
| Observe must begin | First 8 seconds of its original registration window |
| Samples / minimum phase coverage | At most 100 / three baseline, active and recovery |
| Sample rate | At least 100 ms between starts, no catch-up burst |
| Concurrent HTTP probes per sample | Three fixed direct/proxy/application requests |
| HTTP timeout / body / headers | One second / 64 KiB / 8 KiB |
| Journal records / individual record / total bytes | 128 / 32 KiB / 2 MiB |
| Journal archive wrapper | At most 3 MiB, original bytes base64 encoded |
| External witness policy | 128 KiB, 32 keys, 32 exact scopes per key |

The HTTP transport disables proxies, redirects, compression and keep-alive. Only
the internally allocated IPv4 loopback exact-Pod forwarding endpoint is used.
Identity reads have one-second request deadlines and explicit UID/owner/spec/image
checks, initially and every fourth sample. Every signed response also pins fixture
boot/key identity. No arbitrary URL, shell command, discovery selector or Kubernetes
mutation endpoint is exposed by the observer.

Signed monotonic offsets are local to one process/session; UTC is an untrusted
clock assertion. Stalled filesystem operations or process scheduling can outlast
timeouts. Every observed short/failed append poisons the writer. Recovery inspects
the existing prefix; it never appends guessed samples or resumes the epoch.

## Application predicates and result semantics

Baseline and recovery require valid nonce/identity-bound signed responses, HTTP
success, no degraded application response and the existing paired direct/proxy
latency bounds. Direct time must be below half the approved delay; outside the
intervention proxy-minus-direct must be at most one quarter of that delay.

An active effect requires all of: the registered invocation in proxy/application
responses, at least 70% of approved delay in both signed proxy hold and the
witness's own proxy-minus-direct timing, a degraded application response, and
independently measured application time of at least 50 ms and at least 40 ms above
the maximum baseline application time. A proxy acknowledgment or successful HTTP
request alone cannot satisfy this predicate. A signed hold longer than its measured
client request is contradictory. The fixed 75 ms synthetic fallback explains these
specific thresholds; these are not a general latency-inference framework.

Recovery application time must also return within 40 ms of baseline and the
registered ceiling. That ceiling is an inclusive bound: time strictly greater
than `maxApplicationMillis` is a witnessed timing failure. The healthy demo uses
150 ms. The failing demo uses the existing buggy application (actual HTTP 503)
and a separate 50 ms witness ceiling (actual response about 75 ms). Original source
FAIL remains the existing HTTP requirement failure; the new timing failure is
reported separately, without rewriting the old contract or evaluator.

| Corroboration status | Meaning |
| --- | --- |
| OBSERVED_AND_CORRELATED | Externally trusted witness, valid chain, adequate independent application effect/recovery, matching original evidence |
| OBSERVATIONS_INCOMPLETE | Missing/interrupted coverage, unconfirmed effect or original execution/cleanup uncertainty |
| OBSERVATIONS_CONTRADICTORY | Invalid identities, phase/nonce/order/timing bindings or disagreement with original source evidence |
| WITNESS_IDENTITY_UNTRUSTED | No current exact-scope external key pin or forbidden key-role reuse |
| WITNESS_SIGNATURE_INVALID | Invalid registration/record signature, hash or malformed signed envelope |
| UNSUPPORTED_SOURCE | Unsupported source, record version or signature domain |

`complete` describes observation coverage, while `runnerCorrelation`,
`signatureChain`, `witnessTrust`, and `candidateApplicationVerdict` remain separate.
A fully observed FAIL can be correlated. Complete observations can coexist with
historical cleanup uncertainty; that still blocks successful overall corroboration.
Standalone witness inspection has runnerCorrelation NOT_CHECKED. Full bundle
verification performs the original-source join and never upgrades old verdicts.
The result schema enforces that no corroboration status grants execution PASS.

## Key provisioning and external trust

`themis-witness keygen` exclusively creates an owner-protected witness-key.json
and prints only its public identity. `register` takes an unused APPROVED public
T2.3 record, exact operator-approved digest, public runner/cleanup key fingerprints,
a dedicated witness key and a new session path. The fingerprints are SHA-256 of
the decoded public invocation/cleanup keys, supplied by the approving operator;
the witness process never reads the private grant. Fixture and approver public-key
fingerprints are derived from the public proposal. These commitments are not an
independent derivation proof of withheld authority state. Reusing a declared
authority key as witness is denied, as is publisher/witness key reuse.

Offline witness trust must come from a separate file with version
`themis.live-observation-trust/v1alpha1`, exact witness name/key fingerprint/public
key, algorithm Ed25519, source kubernetes-synthetic-witness, current validity,
revocation flag and exact run ID / execution-plan digest / invocation ID / session
scopes. There are no wildcard scopes or network trust discovery. The accompanying
review policy is not trusted merely because it accompanies a bundle. The operator
must independently pin its expected key and reviewed scope.

Validity is [notBefore, notAfter), evaluated using the verifier's supplied clock.
Revocation rejects old records too. Rotation accepts older artifacts only when
their old key remains explicitly trusted in a current policy. There is no trusted
timestamp, key-compromise recovery service or proof of distinct administrators.

## CLI and reproducible owned Kind tests

```console
go build -trimpath -o bin/ ./cmd/...
themis-witness keygen --key-dir NEW_PRIVATE_KEY_DIR --witness operator-observer
themis-witness register --record APPROVED_PUBLIC_RECORD.json --key-dir PRIVATE_KEY_DIR --session NEW_SESSION_DIR --approve-digest sha256:EXACT_PLAN_DIGEST --runner-key-id PUBLIC_INVOCATION_KEY_SHA256 --cleanup-key-id PUBLIC_CLEANUP_KEY_SHA256 --max-application-ms 150
themis-witness observe --state DEDICATED_WITNESS_STATE --session SESSION_DIR --key-dir PRIVATE_KEY_DIR
themis-witness inspect --session SESSION_DIR --witness-policy EXTERNAL_WITNESS_POLICY.json
themis-evidence export --engine kubernetes-synthetic-witness --record COMPLETED_PUBLIC_RECORD.json --journal ORIGINAL_RUNNER.jsonl --witness-session SESSION_DIR --out NEW_PUBLIC_EXPORT
themis-evidence bundle --engine kubernetes-synthetic-witness --source PUBLIC_EXPORT --key-dir SEPARATE_PUBLISHER_KEY_DIR --publisher operator-publisher --out NEW_BUNDLE.zip
themis-evidence verify --bundle BUNDLE.zip --trust-policy EXTERNAL_PUBLISHER_POLICY.json --witness-policy EXTERNAL_WITNESS_POLICY.json
```

`observe` runs in a separate process. Wait for and verify its signed ready.json
before starting the existing `themis-kube coordinate start`; the observer samples
autonomously and never instructs the runner. Every session is exclusive. Inspection
does not authorize, resume or repair an experiment. The existing T2.3 operator
retains approval, stop, recovery and cleanup commands and separate capabilities.

Witness command exits: 0 successful operation/session closure (not a reliability
verdict), 2 usage, 3 protected-key/I/O/session failure, 5 external policy failure,
6 registration denied, 8 incomplete observation session. A no-op can close its
coverage session with exit 0 yet remain uncorroborated in offline verification.
Evidence verification retains old exits and adds 9 for invalid/contradictory
witness evidence; new-source untrusted witness returns 5 and incomplete coverage
or cleanup returns 8. Old-source JSON output is unchanged.

The Go integration suite performs explicit per-plan approval/registration and
launches actual witness and runner processes. A Windows PowerShell reproduction:

```powershell
$clusterName = 'themis-t41-' + [guid]::NewGuid().ToString('N').Substring(0,12)
./scripts/kind-witness.ps1 -Action up -ClusterName $clusterName
go build -trimpath -o bin/ ./cmd/...
$repo = (Get-Location).Path
$env:THEMIS_LIVE_WITNESS = '1'
$env:THEMIS_WITNESS_RUNNER_STATE = Join-Path $repo ('.themis/' + $clusterName)
$env:THEMIS_WITNESS_STATE = Join-Path $repo ('.themis/witness-' + $clusterName)
$env:THEMIS_WITNESS_RUNNER_BINARY = Join-Path $repo 'bin/themis-kube.exe'
$env:THEMIS_WITNESS_BINARY = Join-Path $repo 'bin/themis-witness.exe'
$env:THEMIS_WITNESS_EVIDENCE_BINARY = Join-Path $repo 'bin/themis-evidence.exe'
$env:THEMIS_WITNESS_EVIDENCE = Join-Path $repo '.cache/live-witness-evidence'
go test -count=1 -v ./test/liveobservation
./scripts/kind-witness.ps1 -Action down -ClusterName $clusterName
```

Use the pinned Kind tool and a local Docker context. Setup never adopts an existing
cluster/state; teardown verifies the original namespace/cluster UIDs. Tests kill
only their actual child process handles and pause/resume only the new owned API
task. Ordinary controller/runner privileges, unrelated Kind clusters and PostgreSQL
resources remain outside the mutation scope. Private files are retained locally
for operator management; only curated public artifacts enter review archives.

The demonstrated runtime uses distinct Kubernetes principals and distinct keys,
but a shared OS account/administrator. OS file protection does not stop that actor
from reading other keys or fabricating records. The trusted witness executable,
key holder and administrator remain assumptions. A consistently fabricated history
signed by compromised trusted actors cannot be excluded by these signatures.
