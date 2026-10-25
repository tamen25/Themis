# Developer-preview candidate

Themis is pre-release software for synthetic workloads and explicitly owned
disposable environments. This document prepares a candidate for review; it is
not a release approval, production support statement or infrastructure attestation.
The current milestone handoff records actual tests, failures, skips and open gates.

## Platforms and prerequisites

| Component | Candidate platform | Qualification required |
| --- | --- | --- |
| CLI, contracts, replay and offline verification | Windows AMD64, Linux AMD64 | Native full tests and CLI builds; actual Windows private DACLs or Unix ownership |
| CLI and pure verification libraries | macOS AMD64 | Configured Intel hosted job; cross compilation alone is insufficient |
| Linux file-identity and sandbox checks | Linux | Linux filesystem/process evidence; Windows rename denial is a different observation |
| Owned Kubernetes demonstrations | Local Linux Docker engine or Docker Desktop Linux engine | Fresh installer-owned Kind; exact cluster/namespace/Pod/boot guards |
| PostgreSQL demonstrations | Local Linux/AMD64 Docker engine | Fresh owned containers, private inventory and exact engine/socket |

Use exactly Go **1.26.10** for the preview build and recorded CI configuration.
Obtain offline SDK archives from [official Go downloads](https://go.dev/dl/) and
verify the archive SHA-256 against the official HTTPS release metadata before
extraction. Old Go 1.26.9 preview binaries require a fresh build and scan.
Ordinary source builds still honor the `go.mod` minimum. Python 3.10 or newer is
needed only for the CI recorder and preview packaging scripts. Kubernetes setup
also needs PowerShell, kubectl and Kind 0.32.0 at `.cache/tools/kind[.exe]`.
The existing installers pin their node and workload images. Read their guides
before provisioning anything. macOS Docker/integration support is not qualified
by a Go cross-build or an old run on another commit.

CI uses explicit Ubuntu 24.04, Windows 2025 and macOS 15 Intel runner labels.
These labels select an OS/architecture family, not an immutable runner image;
the observed image version and Go environment remain part of each run's evidence.
[GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
describes the labels. No macOS execution is claimed without a matching run record.

## Build and inspect

```sh
go mod download
go mod verify
go test -count=1 ./...
go build -trimpath -o bin/ ./cmd/...
python scripts/build-preview.py --output ../themis-preview
```

The preview script requires a clean checkout by default. A local review may use
`--allow-dirty`; its label and manifest then identify an **uncommitted** source
snapshot and the base commit. That does not claim the changes exist in Git HEAD.
`--platform linux/amd64` limits a build; omitted means all three listed platforms.
Dependencies must already be available: compilation is offline and CGO is disabled.
The script refuses symlinked source and private inputs, preserves legitimate
public fixtures, and builds from two separate source/cache directories. Matching
SHA-256 values are required for every CLI. This proves those two builds matched
on that builder/toolchain; it is not independent machine reproducibility.

Output contains platform-labeled binaries, `LICENSE`, this document as
`PREVIEW.md`, a source/module/toolchain manifest and `SHA256SUMS.txt`.
The manifest records exact source file hashes, the base commit, dirty state,
toolchain binary hash and actual build commands. The existing `themis version`
command includes the preview label. Other commands retain their existing CLI;
their exact binary hashes are attributed through the manifest. No signing key,
approval, kubeconfig, runtime inventory, database, backup/WAL or cache is bundled.
No build artifact is automatically published as a release or trusted attestation.

On Linux verify with `sha256sum -c SHA256SUMS.txt`; on macOS use
`shasum -a 256 -c SHA256SUMS.txt`. Windows users can compare each listed path with
`Get-FileHash -Algorithm SHA256`. Obtain the expected checksum/manifest from an
independently trusted channel: an attacker able to replace both can replace a
binary too. Downloaded Linux/macOS binaries may need `chmod +x` after extraction.

## Minimal workflows

The local HTTP path needs no Kubernetes, Docker, database or cloud account:

```sh
bin/themis contract validate -f examples/local-http/contract.yaml
bin/themis plan -f examples/local-http/contract.yaml --output json
go run ./examples/local-http/server
# In another terminal; use only the synthetic server endpoint in this contract:
bin/themis run -f examples/local-http/healthy.yaml
```

Planning never authorizes execution. HTTP observation does not establish ownership
of arbitrary loopback services. The [local fault walkthrough](../examples/owned-latency/README.md)
creates its own fixture and explicitly approves the exact plan. Its only fault
is bounded user-space HTTP response latency. Missing samples and scheduling delay
can correctly produce INCONCLUSIVE even when the service is healthy.

For Kubernetes, follow the [synthetic operator workflow](kubernetes-coordination.md),
[signed observer](live-observation.md), [native adapter](native-dependency.md) and
[integrated native witness](native-witness.md). Use a fresh random owned cluster;
never select an ambient kubeconfig or adopt previous state. Runtime principals
cannot install workloads, delete Pods, patch targets, exec or read Secrets.
Installer-only regression tests may disrupt their exact owned tasks and must
restore outages and prove teardown separately. The controller remains dry-run.

The [logical](postgres-recovery.md), [durable](postgres-durable-recovery.md),
[PITR](postgres-pitr.md) and [synchronous failover](postgres-replication.md) guides
use an explicit local Docker endpoint and original engine. They create separate
synthetic resources. They accept no existing database, arbitrary SQL/DSN, production
restore target or implicit cleanup adoption. Separate approvals bind prepared
state, termination, fencing, promotion and cleanup. Inspect signed receipts and
application checks; a successful Docker or PostgreSQL command is insufficient.

Chaos Mesh **execution is disabled**. Its optional installer installs only the
reviewed schema and read-only planner. No privileged node agent or external fault
resource is included in this preview scope.

## Offline verification and trust

```sh
bin/themis-evidence verify --bundle public.zip --trust-policy publisher-policy.json
bin/themis-evidence verify --bundle native-public.zip --trust-policy publisher-policy.json --witness-policy witness-policy.json
```

Use the exact supported command and policy examples in
[evidence bundles](evidence-bundles.md) and [native witness](native-witness.md).
Independently pin publisher and witness keys and exact engine/run/plan/invocation/
session scope. Embedded keys or a policy supplied by a publisher do not provision
trust. Distribute policies through a trusted channel and manage revocation and
verifier time explicitly. Keys for installation, approval, Apply, cleanup,
publication and observation retain separate roles.

| Result | Meaning |
| --- | --- |
| Plan/admission | Declared intent and a separate scope decision |
| Execution and candidate verdict | What the original runner attempted and measured |
| Original cleanup | What was confirmed when that run finalized |
| Later reconciliation | A new observation; historical uncertainty is preserved |
| Witness corroboration | Separately signed observations under external exact-scope trust |
| Publisher signature | Attribution and integrity of assertions about bytes |
| Whole execution | **NOT_INDEPENDENTLY_ATTESTED / INCONCLUSIVE** |

Administrative or verification exit 0 is not an application PASS. CLI namespaces
retain their existing distinct exit-code contracts; see [the CLI reference](cli.md).
No schema, original plan digest, scheduler behavior or historical verdict is
silently upgraded. Same-user administrators, kernel/runtime, installer images,
clocks, routing, filesystem and private-key custody remain trusted assumptions.

## Troubleshooting and release gates

* An INCONCLUSIVE healthy run can indicate missing slots, slow journal writes or
  invalid paired measurements. Inspect the report and original observations;
  do not relax coverage or fault thresholds to obtain PASS.
  Complete samples can still lack recovery proof when paired client latency
  exceeds its bound; a healthy fixture alone does not establish that guarantee.
* Cancellation polling now reports a runner that exits before the requested
  phase. The FINAL test separately diagnoses finalization ordering and an
  original healthy run that never established PASS. Historical intermittent
  Windows failures remain open until their cause is demonstrated.
* Protected Windows state requires the actual current-user owner and exact
  private DACL. Newly created group-owned state is explicitly pinned to that
  user when permitted; failure is closed. Unsupported storage, owner changes
  or insufficient permissions cannot be treated as successful admission.
* Kind quota discovery is asynchronous. A Pod quota counter does not prove that
  the VerificationRun counter is initialized. Installation now waits for both.
* Integration skips mean **NOT RUN**. Full ordinary tests do not enable Docker,
  SQL or Kubernetes faults. Run integration only with explicit disposable ownership.
* Run the ordinary suite, each live Kind suite and each PostgreSQL family as
  separate qualification campaigns. Keep normal Go package concurrency within
  the ordinary suite. A saturated host can violate the local 50 ms recovery
  measurement bound after the injected delay has been removed, with or without
  connection reuse. Preserve that INCONCLUSIVE result; do not retry it into a
  replacement PASS or infer that an earlier failed measurement was harmless.
* The PostgreSQL CI matrix retains the original test exit and separately runs
  `scripts/verify-postgres-cleanup.py` in `finally`. The checker reads the exact
  original inventory, including nested volume names, verifies the engine and
  invokes the original guarded CLI only for remaining recorded resources.
  A later absence proof never changes the original cleanup verdict. An incomplete
  inventory or unavailable cleanup authority keeps the gate open.
* Preserve partial setup records. Never prune Docker, delete a guessed resource,
  adopt an old cluster, renew a consumed invocation or overwrite a historical report.

Before preview approval require current reviewed-commit hosted CI on supported
platforms, current dependency/reachability scans, owned live integration and cleanup,
matching independent build hashes, historical compatibility and review of all
failures/skips. The manual preview workflow creates review artifacts only.
It does not publish a GitHub release or approve a deployment.
