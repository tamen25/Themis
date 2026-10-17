# Signed evidence bundles (T4.0)

## Threat model

An importer controls every archive byte, filename, embedded observation key,
historical report, journal and claimed timestamp. A publisher may sign fabricated
evidence. An attacker may copy a publisher name, replace a key, truncate a file,
recompute an unsigned journal, or submit an archive intended to exhaust resources.
Neither an embedded public key nor a valid signature establishes execution truth.

The verifier trusts only a separately provisioned publisher/key/scope policy and
its caller-supplied verification clock. The publishing OS account, filesystem and
signing-key holder are trusted. Same-account attackers and administrators can
bypass local file protection. There is no hardware-backed key, trusted timestamp,
external witness, transparency log, production nonrepudiation or compliance claim.

Artifact integrity, publisher authenticity and execution evidence are separate
results. Retrospective publication authenticates a publisher's assertion about
historical bytes; it never upgrades an unsigned execution to independently proven
PASS. Client timing, Docker/PostgreSQL observations, whole-run authorization and
fixture software honesty retain their original provenance limitations.

## Serialization and signature specification

Version: `themis.evidence-bundle/v1alpha1`. Metadata uses compact Go
`encoding/json` serialization of the specified concrete structs in declaration
order, default HTML escaping, UTF-8, no insignificant whitespace or final newline.
Arrays with set semantics are sorted and unique. Integers use decimal Go JSON
encoding; floating point fields and arbitrary maps are absent from the envelope.
Decoders reject unknown, duplicate, case-mismatched and null fields, invalid UTF-8,
trailing values and noncanonical encodings. This is not RFC 8785.

`bundleId` is lowercase SHA-256 of these manifest bytes with `bundleId` replaced
by the empty string. Each artifact has its exact byte count and lowercase SHA-256.
The detached Ed25519 signature covers the literal UTF-8 bytes
`themis.evidence-bundle.signature.v1\n` followed by the complete manifest bytes.
The manifest binds publisher name, SHA-256 public-key fingerprint, public key,
algorithm, signature domain, provenance, publication-time claim and complete
artifact inventory. The signature file repeats and must match these identities.
There is no circular dependency: only artifacts are inventoried, not the manifest
or detached signature. Publication time is an authenticated publisher claim.

The archive contains `manifest.json`, `signature.json`, then sorted flat
`artifacts/<lowercase-name>.json` or `.jsonl` paths. Only the exact canonical ZIP
encoding produced by this version is admitted. ZIP uses STORE, fixed metadata,
regular read-only files, no directory entries, comments, extra fields, compression,
hidden entries, Unicode names, backslashes, traversal, symlinks or devices.
Canonical byte comparison also rejects trailing/prepended data and ambiguous
local/central-directory representations. Limits are 64 artifacts, 8 MiB per
artifact, 32 MiB total artifact bytes, 128 KiB manifest, 4 KiB signature and
34 MiB archive. STORE-only admission makes decompression amplification impossible.

External trust is deny by default. A policy pins publisher, key fingerprint,
Ed25519 public key and exact source-engine scope, with explicit validity interval
and revocation. Verification uses current caller-supplied time, never solely the
signed publication time. Revocation rejects old artifacts too. Rotation requires
explicitly retaining an old key in a currently valid policy; the archive cannot
add trust roots. Policy authenticity and distribution are operator responsibilities.

Publication explicitly freezes an allowlisted public export. All inputs are opened
as regular nonsymlink files under one rooted directory, read boundedly, checked
for identity/metadata changes, then reopened and byte-compared before signing.
The in-memory snapshot is the signed object. Sources must be quiescent; these
checks detect observed changes, not a malicious owner's change-and-restore attack
or an atomic multi-file filesystem transaction. A synced temporary archive is
hard-linked exclusively to the final name; existing publications are never
replaced. Partial temporary files are never accepted as final publications.
Local ownership and permissions enforce immutability, not write-once hardware.
File flushes and supported directory sync are not proof of power-loss durability.

## Source mappings and completeness

| Engine / mapping | Public evidence | Rechecked offline |
| --- | --- | --- |
| `postgres-replication` / `postgres-replication/v1` | Public plan projection, report, preparation/execution journals, prepared seal, COMMIT receipt array | Projection digest and original references, seal/receipt signatures, journal hashes/order, invocation/effect identities, recovery measurements, receipt/row comparison, existing assertions and cleanup consistency |
| `kubernetes-synthetic` / `kubernetes-synthetic/v1` | Execution journal, report, coordination proposal with request/preview | Full execution-plan digest, preview/request/target bindings, fixture data/status signatures, correlations, existing paired timing/assertion predicates, saved report and cleanup consistency |

PostgreSQL original plans embed private ownership metadata. The new
`themis.postgres-replication-public/v1alpha1` projection includes original plan/
inventory SHA-256 references, contract, run/container/network/database/boot/peer
identities, public ledger key and authority-key fingerprints. Its digest is
SHA-256 of `version + newline + compact typed JSON` with `Digest` empty. This is
a publisher assertion, not a derivation proof for the withheld private plan.
`source.unsupported` includes `original-private-plan-recompilation`. Receipt,
seal and journal bindings must match the original reference. No local directory,
actor, socket, capability or ownership inventory is exported. Receipts collected
from preparation events preserve signed message values. SQL/Docker observations
remain unsigned local claims.

Kubernetes retains its original public plan, proposal/preview/request mapping and
fixture signatures. Those signatures cover response values and fixture hold
measurements, not client start/end times, phase placement, whole-run authorization
or fixture software honesty. The proposal cannot establish cluster execution.

Both mappings reuse existing assertion predicates and compare saved verdicts with
observations. A consistently fabricated or rehashed unsigned history may still
satisfy candidate predicates. Execution attestation is therefore always
`NOT_INDEPENDENTLY_ATTESTED`, and trusted execution verdict is `INCONCLUSIVE`.

`artifactComplete` means the exact signed inventory is present.
`sourceChecks.complete` separately describes available mapping inputs. Status is
`PASSED`, `FAILED`, `INCOMPLETE` or `UNSUPPORTED`. PASSED means supported internal
checks passed, not that an experiment PASS was proven. A complete no-op experiment
can consistently claim INCONCLUSIVE. Missing measurements, source inputs and
cleanup uncertainty remain visible. T0–T3.2 retain their existing replay APIs;
this milestone adds no evaluators for those formats. The core API can sign an
explicitly curated older artifact; the full verifier labels its source unsupported.

## CLI and external trust

```console
go build -trimpath -o bin/ ./cmd/themis-evidence
themis-evidence keygen --key-dir .themis/evidence-signer --publisher example-operator
themis-evidence export --engine postgres-replication --state ORIGINAL_RUN --out PUBLIC_EXPORT
themis-evidence bundle --engine postgres-replication --source PUBLIC_EXPORT --key-dir .themis/evidence-signer --publisher example-operator --out published.zip
themis-evidence verify --bundle published.zip --trust-policy trusted-publishers.json
themis-evidence inspect --bundle published.zip
```

Key generation prints public identity only. Independently review/distribute an
external policy; never trust a policy obtained solely from the archive:

```json
{
  "version": "themis.evidence-trust/v1alpha1",
  "keys": [{
    "publisher": "example-operator",
    "keyId": "REPLACE_WITH_64_HEX_SHA256_OF_PUBLIC_KEY",
    "publicKey": "REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY",
    "algorithm": "Ed25519",
    "engines": ["kubernetes-synthetic", "postgres-replication"],
    "notBefore": "2026-10-18T00:00:00Z",
    "notAfter": "2027-10-18T00:00:00Z",
    "revoked": false
  }]
}
```

Validity is `[notBefore, notAfter)`, evaluated against verification time. Unknown
names/keys, wrong scope, revocation and expired/future policies deny trust.
Every policy field is explicit; duplicate identities, case-mismatched and missing
fields are rejected. There is no trust-on-first-use or public-key network fetch.

For Kubernetes use `export --engine kubernetes-synthetic --state ORIGINAL_RUN
--proposal ORIGINAL_PROPOSAL --out PUBLIC_EXPORT`, or use only retained public
records: `export --engine kubernetes-synthetic --record COORDINATION.json
--journal EVENTS.jsonl --out PUBLIC_EXPORT`. Public-record export reserializes
the existing typed nested report/proposal; original files and signed message
values are unchanged. Publication rejects reuse of fixture/ledger/approval keys.
Only fixed allowlisted public files are exported. Known secret structures/patterns
are rejected, but this is not a universal secret detector; curate inputs carefully.

`bundle` is the explicit signing action; no unsigned intermediate is presented as
a publication. Its new exclusive output is outside the curated source directory.
All commands emit JSON. Inspection never grants execution authority.

| Exit | Meaning |
| --- | --- |
| 0 | Command succeeded; verify passed integrity, signature, external trust and supported source checks. Candidate FAIL/INCONCLUSIVE may still be authentic. Never independently proven execution PASS. |
| 2 | Invalid command/arguments |
| 3 | Local I/O, protected signing-key or publication failure |
| 4 | Invalid archive, manifest, artifact integrity or signature |
| 5 | Missing/invalid external policy or untrusted publisher |
| 6 | Inconsistent source evidence or forbidden source/publisher key reuse |
| 7 | Unsupported source engine/mapping |
| 8 | Incomplete source-check inputs/coverage |

Inspect returns zero for a structurally valid archive even if publisher trust or
source checks fail; its JSON reports those fields. Read structured outcomes for
downstream decisions. A verification exit code is not a reliability verdict.

## APIs and validation

`pkg/evidence.Verify(readerAt, size, externalPolicy, verificationTime)` imports
only the standard library and reports source checks NOT_CHECKED.
`pkg/evidenceverify.Verify` adds the two concrete pure source mappings, with
compile-time dependencies on existing engine packages. Neither opens paths from
artifacts, invokes Docker/Kubernetes or needs private runtime state. The caller
must authenticate policy distribution and verification time. Mutating returned
in-memory values does not authenticate new claims or change original bundles.

Portable fixtures retain actual synthetic histories; tests distinguish original
outcomes, consistency predicates and unproven execution. Adversarial checks cover
archives, trust policy, rotation, source forgeries and actual publisher process
death before exclusive publication. Run `go test -count=1 ./...`, supported CGO
`go test -race ./...`, and bounded campaigns in `make fuzz`. The handoff identifies
actual offline CLI executions and infrastructure tests not rerun in T4.0.

References: Go's [ZIP reader](https://pkg.go.dev/archive/zip),
[Ed25519 API](https://pkg.go.dev/crypto/ed25519) and
[rooted filesystem API](https://pkg.go.dev/os#Root). They do not supply Themis's
trust policy, canonical archive rules or execution attestation.
