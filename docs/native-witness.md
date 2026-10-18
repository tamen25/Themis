# Signed native dependency observations (T4.3)

The supported path remains a newly owned disposable Kind application, explicit
native proxy and separate dependency. T4.3 adds signed independent observation
and one concrete evidence mapping. It adds no fault type, privileged agent,
controller execution permission or production support.

Five actors remain distinct: the native runner holds invocation-specific fault
authority; the proxy enforces the original target and its own monotonic expiry;
the read-only witness measures requests using its own key; the publisher signs a
curated completed snapshot; the offline verifier checks public bytes and explicit
external policies. Publishing a bundle never executes or reconciles an experiment.

## Authority and the live boundary

`approve-witnessed` uses the existing approval issuer and unchanged native grant.
It delivers the original private capability file only to the runner. A separate
`themis.native-public-approval/v1alpha1` signature commits to the complete frozen
plan, invocation, actual grant digest, public Apply/cleanup key fingerprints and
admission windows. The reference is not an actuator grant or command capability.
The witness and publisher do not open the operational authorization file.

`themis.native-observation-registration/v1alpha1` binds that reference, all original
cluster/namespace/workload/Pod/container/image/boot/key identities, the exact
application contract, witness key/session/process identity, fixed routes and
observation budgets. Registration lasts twenty seconds; observation must start
with at least seven seconds left. The key and session must be new for that run.

Three actual healthy baseline samples precede durable signed READY. The integrated
runner independently checks the current exact witness policy and signed prefix.
Its Apply nonce commits to the registration digest, READY hash and original grant
digest. The unchanged native command authenticates this nonce; the proxy's signed
Apply reply echoes it. A run-scoped signature additionally binds the runner's
durable intent into this nonce, and a final authority-holder statement commits to
the original journal digest, canonical result, cancellation and cleanup fields.
Those separate signatures prevent a publisher from hiding cancellation or editing
the original source outcome. A killed runner produces no invented final assertion.
They authenticate the authority holder's claims, not software or whole execution.
This relates registration/readiness to the actual receipt
without subtracting different processes' clocks. The original separate unsigned
observer and runner preflight remain active and use different fresh requests.

The new read-only `/receipt/EXACT_INVOCATION?nonce=FRESH_NONCE` route returns
`themis.native-http-authority-receipt/v1alpha1`. It signs the actual retained grant
digest, public authority-key fingerprints, original proxy boot and invocation
state. It exports no grant signature or capability. This closes a correlation gap:
the older Apply reply alone did not explicitly attest its original grant digest.
An unknown invocation returns signed 404 without allocating state. Polling never
persists, renews, claims, removes or changes an intervention. The original
cleanup-unconfirmed scenario also withholds state on this route. All existing
command, Reply, grant and plan formats and fault-state transitions remain intact.

The signed witness checks this actual actuator commitment against the independent
public approval reference. All observed original proxy epoch/deadline values must
agree with the original Apply receipt. Equality is checked within the same proxy
boot; no global monotonic clock or external timestamp is inferred.

## Measurements and journal

The witness has its own Kubernetes ServiceAccount and named read/forward rights.
It receives no Apply/Remove capability and performs no workload mutation. Its
separate process generates a fresh nonce for **every** direct dependency, proxied
dependency, application and invocation-receipt request. It measures its own client
elapsed time and HTTP code, retaining signed nested fixture responses and failed,
timed-out or mismatched-identity outcomes. Unsigned T4.2 timings are never relabeled
as witness measurements. Source and witness request nonces must be disjoint.

Records use `themis.native-observation/v1alpha1` and a distinct signature domain.
Compact typed Go JSON in declared field order, including normal Go HTML escaping,
is the canonical encoding; this is not RFC 8785. SHA-256 chains and Ed25519 bind
the registration, exact plan/invocation/target, process/session, sequence, previous
hash, own monotonic offsets, claimed UTC and measured probes. Unknown, duplicate,
case-aliased, null and noncanonical signed fields are denied.

| Budget | Limit |
| --- | --- |
| Registration / observation | 20 seconds / at most 6 seconds |
| Sampling | At least 150 ms between starts; at most 55 sequential sample groups |
| Records / record bytes / journal bytes | 64 / 32 KiB / 2 MiB |
| Source HTTP transport | Existing 750 ms request deadline, 64 KiB body, no redirects/proxy |
| Consumed sessions per protected signing key | 64, then explicit key rotation |
| External policy | 128 KiB, 32 keys, 32 exact scopes per key |

Every append is written and synced; short writes or sync failures poison further
appends. A signing-key-local exclusive consumed-session claim prevents resuming
the same session even after its registration is copied to another output folder.
Complete signed prefixes and torn final bytes are retained; no END or measurements
are reconstructed. A witness crash cannot control the proxy's timer or cleanup.
Filesystem stalls and power loss have the existing documented limitations.

Identity checks run before observation and periodically. An API outage leaves the
installer-pinned NodePort data path usable, but signs identity UNKNOWN and blocks
complete successful corroboration. Replacement replies are recorded as identity
mismatch, never authenticated as the original proxy. An expired or crashed proxy
does not establish recovered application traffic.

## Predicates and separate findings

The native reliability contract and thresholds are preserved: three baseline,
three active effect and three healthy recovery samples; paired proxy-minus-direct
delay and signed proxy hold at least 70% of approved delay; application latency
increase at least 60% of delay over healthy baseline; inclusive declared application
ceiling; recovered application within the ceiling and baseline plus 40 ms.

The witness separately checks the actual grant commitment, signed active interval,
own application outcomes/timings, retained expiry/inactive state and real traffic
recovery. Credible measured violation remains FAIL. No effect, missing observations,
unknown identity and interrupted coverage remain INCONCLUSIVE. Source and witness
candidate findings stay separate; disagreement is reported as a contradiction.
Healthy witness observations cannot upgrade a canceled/uncertain source execution
or erase its original CLEANUP_PENDING. Later reconciliation contributes a separate
public receipt and does not change the original report or journal.

`NativeObservedResult` separates artifact integrity, publisher signature/trust,
witness signatures/trust, identity and grant correlation, effect, recovery,
original candidate, original cleanup and execution attestation. A zero verification
exit means supported integrity/correlation checks passed; the source may be FAIL.
It is not a reliability PASS or whole-execution verification. Whole-execution
trusted verdict is always INCONCLUSIVE / NOT_INDEPENDENTLY_ATTESTED.

## External trust and offline publication

Use explicit, independently supplied publisher and native witness policies. Native
witness policy pins publisher name/key, witness name/key, exact engine, run, plan,
invocation, session, registration digest, original target digest and fixed routes.
Current validity and revocation are checked at the caller's verification clock.
Fixture, installer, approver, Apply, cleanup, publisher and witness key-role reuse
is denied. Embedded keys and accompanying example policies do not become roots.
Authentic policy distribution and protecting the verifier clock remain operator
responsibilities.

The explicit `native-dependency-witness/v1` mapping contains nine public artifacts:
plan, public approval reference, exact raw runner journal, curated original result,
readiness admission, runner assertion signatures, later reconciliation receipts,
witness registration and exact
raw signed witness journal. JSON base64 wrappers preserve original JSONL bytes,
including tears. The result is a typed public representation of original fields;
original file bytes are separately retained in execution evidence and checked
unchanged during lifecycle tests. A missing runner result is explicit and cannot
be fabricated from witness recovery. No private signing key, original grant,
credential, kubeconfig, ownership inventory or database contents are exported.

The unchanged T4.0 manifest commits to the complete artifact inventory. Publication
is explicitly RETROSPECTIVE_PUBLICATION even when its included witness records
were contemporaneous. A malicious trusted publisher can sign a fabricated PASS;
valid unchanged witness signatures identify contradictions instead of endorsing
that claim. Offline APIs consume only public in-memory artifacts. They do not open
artifact-supplied paths, discover targets or invoke Kubernetes/Docker.

## Running an owned example

Build all commands, then use a fresh exact installer-owned name:

```powershell
go build -trimpath -o bin/ ./cmd/...
$clusterName = 'themis-t42-' + [guid]::NewGuid().ToString('N').Substring(0,12)
./scripts/kind-native-witness.ps1 -Action up -ClusterName $clusterName
$state = Join-Path (Get-Location) ('.themis/' + $clusterName)
bin/themis-dependency plan --state "$state/runner" --directory "$state/run" --max-application-ms 500
bin/themis-native-witness keygen --key-dir "$state/witness-key" --witness my-native-witness
bin/themis-evidence keygen --key-dir "$state/publisher-key" --publisher my-publisher
```

Start the original `themis-dependency observe` in a separate terminal and wait for
its ready.json. Explicitly review the plan and use `approve-witnessed --directory
RUN --keys KEYS --approve-digest EXACT_DIGEST`. Register with `themis-native-witness
register --key-dir KEY --approval RUN/public-approval.json --session SESSION
--approve-digest EXACT_DIGEST`. Independently pin the emitted registration and
publisher identity in current public trust policies; keygen does not invent trust.

Start `themis-native-witness observe --state WITNESS_STATE --session SESSION
--key-dir WITNESS_KEY` as another process. After its signed ready.json exists, use
`themis-dependency run-witnessed --state RUNNER_STATE --directory RUN --observations
ORIGINAL_OBSERVER --witness-session SESSION --witness-policy EXTERNAL_NATIVE_POLICY`.
Observe/run are separate actors and must run concurrently.

After both processes stop, export with `themis-evidence export --engine
native-dependency-witness --state RUN --witness-session SESSION --out NEW_EXPORT`;
optionally add `--reconciliation PUBLIC_LATER_RECEIPT`. Publish with the existing
explicit `bundle --engine native-dependency-witness --source EXPORT --out NEW_ZIP
--key-dir PUBLISHER_KEY --publisher NAME`. Verify with `verify --bundle ZIP
--trust-policy EXTERNAL_PUBLISHER_POLICY --witness-policy EXTERNAL_NATIVE_POLICY`.
Use existing original-inventory cancel/reconcile commands for current cleanup and
`kind-native-witness.ps1 -Action down -ClusterName EXACT_NAME` for guarded teardown.

New witness exits: 0 completed bounded collection, 2 usage, 3 output/I/O, 6 denied
input/session, 8 incomplete collection. Existing native runner exits remain intact.
Native bundle verification uses 0 supported correlation, 4 envelope/signature
failure, 5 untrusted signer/policy, 6 invalid source, 7 unsupported mapping,
8 incomplete/no-effect/uncertain execution, and 9 contradiction/invalid witness.
Always read structured findings, especially original FAIL and cleanup disposition.

## Trust limits and next stages

Demonstrated actors share one OS user, host and administrator. Distinct processes,
keys and Kubernetes principals do not provide hardware or mutually independent
machine attestation or prevent administrator collusion. Trusted installer images,
Downward API, Kubernetes identity reads, routing, scheduling and process monotonic
clocks remain assumptions. The native hard-expiry limits do not guarantee recovery
through proxy, kernel, node or filesystem failure. Chaos Mesh remains disabled;
this L7 mechanism does not solve that provider's separate unresolved gates.

Old T0-T4.2 commands and T4.0/T4.1 mappings remain separate and compatible. The old
standalone native replay still classifies its unsigned collection conservatively;
it does not silently become the new witnessed mapping. T4.4 is integrated
adversarial hardening; the Stage 5 audit/remediation/release plan is in the
[roadmap](roadmap.md), not a substitute for current safety tests.
