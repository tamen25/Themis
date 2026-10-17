# Themis

`themis-postgres` supports owned disposable local PostgreSQL recovery experiments:
[logical restore](docs/postgres-recovery.md), [durable logical recovery after
SIGKILL](docs/postgres-durable-recovery.md), and [physical backup/WAL/PITR](docs/postgres-pitr.md).
They retain separate contracts and fault authority, signed COMMIT receipts,
measured application recovery, conservative verdicts and exact-resource cleanup.
Chaos Mesh remains planning-only with its existing execution blockers.

Themis is an early Go reliability verification project. Its T0 CLI validates
contracts, creates immutable plans, runs bounded local HTTP checks, and exports
unsigned reports that can be replayed offline. Experimental T1.1 adds one owned
synthetic service and response-latency proxy, with explicit authorization,
independent measurements, bounded expiry and cleanup. Production targets and
external providers remain unsupported.

T1.2 adds read-only experiment status, cross-process cancellation, reconciliation
under damaged journals, explicit operation diagnostics and evidence provenance.
See [lifecycle and recovery](docs/experiment-lifecycle.md) and the
[T1.2 validation matrix](docs/t12-test-matrix.md).

Experimental T2.0 adds a separate Kubernetes controller for deterministic **dry-run
previews only**, namespaced VerificationRuns, independent safety policy and narrow
RBAC. That controller has no fault or reliability assertion execution path;
preview verdicts stay NOT_RUN or INCONCLUSIVE. See
[Kind setup and API limits](docs/kubernetes.md) and the
[Kubernetes threat model](docs/kubernetes-security.md).

Experimental T2.1 adds a separate operator-invoked runner for one preinstalled
synthetic application-path latency experiment in an explicitly owned Kind cluster.
It binds approval to the live Pod and proxy boot, independently verifies delay
and application behavior, and records recovery, expiry and cleanup. The controller
and its read-only target permissions are unchanged. See the
[owned Kind experiment guide](docs/kubernetes-experiments.md) for setup, the four
demonstrations, authorization boundaries and evidence limitations.

## Build and use

Requires Go 1.26.9 or newer. The local CLI needs no cluster, cloud account,
database, Docker, Argus or Arete. The first build downloads the pinned Go modules; Go's automatic
toolchain selection may also download the required Go patch release.

```sh
go build -trimpath -o bin/ ./cmd/themis
go run ./cmd/themis version
go run ./cmd/themis contract validate -f examples/local-http/contract.yaml
go run ./cmd/themis plan -f examples/local-http/contract.yaml --output json
```

The compiled executable is `bin/themis` on Unix and `bin/themis.exe` on Windows.
Invoke it directly when a script needs Themis's exit code; `go run` wraps nonzero
program exits. Release builds may set a version with
`-ldflags "-X main.version=v0.x.y"`; development builds report `dev`.

Validation prints `VALID <name> sha256:<digest>`. Planning prints JSON containing
`planDigest` and its `plan` payload. It only reads the supplied contract and writes
stdout/stderr. To save the result, redirect stdout explicitly:

```sh
bin/themis plan -f examples/local-http/contract.yaml --output json > plan.json
```

No application needs to be running to validate or plan a T0 contract. Every T0 plan says
`mode: planning-only`, `executionAllowed: false` and that target identity is only
declared. Each check identifies the supported runner and separate admission.

Start the disposable fixture in another terminal:

```sh
go run ./examples/local-http/server
```

Port 8080 must be available. If occupied, use `-listen 127.0.0.1:18080` and change
the URL in your own copy of the example contract to the same port.

With `bin` on PATH, run the health contract:

```console
$ themis run -f examples/local-http/healthy.yaml
Contract: local-http-health
Run:      run-...
Samples:  100
Coverage: sufficient

Readiness: PASS
Error rate: PASS

Verdict: PASS
```

This collects 100 real GET observations across 10 seconds. The run does not
start or replace a service. Stop the fixture with Ctrl+C; restart it using
`go run ./examples/local-http/server -status 503` to reproduce FAIL. A missing
service produces unsuccessful connection observations and never produces PASS.
Slow or interrupted collection can produce INCONCLUSIVE.

Runs create `.themis/runs/<run-id>/events.jsonl` and `report.json`. Choose another
root with `--runs-dir <directory>` or request structured stdout with
`--output json`. Stop the fixture and replay the observations offline:

```sh
bin/themis replay -f .themis/runs/<run-id>/events.jsonl --output json
bin/themis replay -f internal/run/testdata/healthy.jsonl
bin/themis replay -f internal/run/testdata/unhealthy.jsonl
```

The included fixtures yield PASS and FAIL respectively. Replay checks internal
consistency and recomputes results; unsigned evidence does not prove authenticity
or physical workload identity. See [run semantics](docs/runs.md).

Contracts default to requiring approval. Review `themis plan`, then run with
`--approve-plan sha256:<exact-plan-digest>`. The disposable healthy example
explicitly disables that extra confirmation. Invoking `run` authorizes the
bounded GETs. Only use endpoints you control; loopback alone does not establish
isolation.

## Implemented contract subset

The schema version is `themis.contract/v1alpha1`. The
[JSON Schema](api/schemas/contract-v1alpha1.json) is embedded in the binary and is
used during validation. [Contract documentation](docs/contracts.md) describes
the additional semantic rules, defaults and normalization.

- Named `local-http` target with a literal loopback HTTP(S) URL and explicit port.
- Local execution profile, maximum duration of 10 minutes, zero concurrent faults.
- Ordered observation phases whose total duration fits the execution budget.
- `http-ready` and `http-success-rate` assertion declarations, with required and
  optional checks and bounded sample counts.
- Strict unknown-field, duplicate-key, schema-version and type rejection.
- Bounded YAML input, deterministic normalized contract hash and plan hash.
- Typed verdicts and pure aggregation with evidence prerequisites, tested
  independently of the CLI.

Examples under [examples/invalid](examples/invalid) deliberately fail validation
with exit code 4. T0 faults, Kubernetes targets, arbitrary scripts, provider checks,
raw traces, retention and signed evidence are unsupported and rejected.

## Experimental owned latency experiment

Read [the experiment guide](docs/experiments.md) before enabling faults. Only
fixtures started by this executable are supported. The
[v1alpha2 example](examples/owned-latency/experiment.yaml) names the fixture;
it cannot supply an arbitrary upstream URL. Review the resolved plan, authorize
its exact digest, then run using the separate private authorization record.
T0's `--approve-plan` never authorizes a fault.

```sh
bin/themis fixture start --directory .themis/fixtures/demo --name demo
bin/themis experiment validate -f examples/owned-latency/experiment.yaml
bin/themis experiment plan -f examples/owned-latency/experiment.yaml --fixture .themis/fixtures/demo
# Review that resolved plan before the next command; paste its exact digest.
bin/themis experiment authorize -f examples/owned-latency/experiment.yaml --fixture .themis/fixtures/demo --approve sha256:<reviewed-digest>
# Immediately use the authorizationFile path printed above (valid for 20s).
bin/themis experiment run -f examples/owned-latency/experiment.yaml --fixture .themis/fixtures/demo --authorization <private-record-path>
```

Each fixture is single use and expires independently within two minutes. A fault
expires within three seconds. The default example requests 200ms for two seconds.
Normal cleanup stops the fixture after observing recovery. Use a new directory
for each run. Modes `healthy`, `buggy`, `noop-adapter` and `cleanup-denied`
demonstrate PASS, FAIL, INCONCLUSIVE and CLEANUP_PENDING. These modes change only
the disposable fixture. See [CLI reference](docs/cli.md) for reconciliation.

Private state requires real owner-only access controls: protected DACLs on
Windows NTFS, or owned private directories on Unix. Linux on a WSL Windows mount
may not enforce modes; use the WSL Linux filesystem for fixture/run directories.
Same-user processes and administrators are trusted. This is local experimental
authorization, not enterprise authentication or production-ready fault injection.

## Kubernetes lifecycle

Owned Kind experiments now support cross-process cancellation, read-only status,
idempotent reconciliation and trust-aware offline verification:

```sh
themis-kube cancel --run-directory /absolute/private/run-directory
themis-kube status --run-directory /absolute/private/run-directory
themis-kube reconcile --run-directory /absolute/private/run-directory
themis-kube verify -f /path/to/events.jsonl --expect-plan-digest sha256:RETAINED_DIGEST
```

Cancellation accepted before finalization prevents PASS. Later cleanup preserves
historical outcomes. Offline verification checks individual signatures and
candidate assertions; an unsigned journal cannot produce trusted execution PASS.
See [Kubernetes lifecycle, versions and test matrix](docs/kubernetes-lifecycle.md).
The dry-run controller retains its original permissions and behavior.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Help/version, valid contract, generated plan or verified PASS |
| 2 | Completed run/replay with verified FAIL |
| 3 | INCONCLUSIVE/NOT_RUN, cancellation or expiration |
| 4 | Invalid command, contract or unsupported feature |
| 5 | Run admission denied: approval mismatch or impossible sample minimum |
| 6 | I/O/infrastructure failure or invalid/incomplete journal |
| 7 | Experimental cleanup pending or unresolved resources |

Execution status and verdict remain separate. Completed collection can measure
FAIL. An interrupted journal can preserve an early credible FAIL while its
execution status and process exit indicate interruption. In experiments, exit 7
takes priority over a measured FAIL; the separate verdict retains that failure.

## Develop and test

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go mod verify
go test ./internal/contract -run '^$' -fuzz '^FuzzParse$' -fuzztime 10s
go test ./internal/result -run '^$' -fuzz '^FuzzAggregateNeverFalsePass$' -fuzztime 10s
go test ./internal/run -run '^$' -fuzz '^FuzzReplay$' -fuzztime 10s
go test ./internal/experiment -run '^$' -fuzz '^FuzzReplayExperiment$' -fuzztime 10s
go test ./internal/kube -run '^$' -fuzz '^FuzzDryRunSpec$' -fuzztime 10s
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The race detector requires a supported C toolchain and CGO. GNU Make targets
include `build`, `fmt`, `fmt-check`, `vet`, `test`, `race`, `fuzz` and `check`.
`fmt-check` requires a POSIX shell; native Windows users can run
`gofmt -l cmd internal api examples test` and require empty output and exit 0.

CI checks formatting, dependency integrity, `go vet`, tests and builds on Linux,
Windows and macOS; Linux also runs race tests, short fuzz campaigns and a
vulnerability audit. Workflow actions use commit pins.
The suite includes a real 100-request, 10-second healthy run, unhealthy and slow
targets, cancellation, approval denial and deterministic offline replay. Hosted
CI still needs execution after publication.

## Architecture and delivery boundary

Themis starts as a modular monolith:

| Path | Responsibility |
| --- | --- |
| `cmd/themis` | Process entry point, signals and build version |
| `internal/cli` | Arguments, file/stream I/O and exit codes |
| `internal/contract` | Parse, schema/semantic validation, normalization and digest |
| `internal/plan` | Pure compilation into an immutable planning snapshot |
| `internal/localpolicy` | Versioned execution bounds shared by plan and runner |
| `internal/probe` | Bounded status-only HTTP observations |
| `internal/run` | Admission, schedule, journal, assessment and replay |
| `internal/safety` | Independent deny-by-default experiment policy |
| `internal/localstate` | Private credentials and crash-consistent local records |
| `internal/fixture` | Owned service/proxy process, authority, expiry and signed responses |
| `internal/experiment` | Client observer, state machine, journal, assessment and cleanup |
| `internal/result` | Execution/result types and evidence-aware verdict aggregation |
| `internal/kubefault` | Bounded in-Pod fixture protocol, authenticated commands and expiry |
| `internal/kubeexperiment` | Restricted Kind runner, Pod resolution, measurements and cleanup |
| `api/schemas` | Embedded, versioned contract schema |
| `examples` | Valid contract and intentionally invalid contracts |
| `docs/adr` | Architectural decisions and explicit scope choices |

See [architecture](docs/architecture.md) and [decisions](docs/adr/README.md).
No generic provider or storage framework is introduced.

T2.3 adds an explicit [operator coordination workflow](docs/kubernetes-coordination.md):
inspect the untrusted VerificationRun preview, independently reconstruct a plan,
approve its exact digest, start once, and inspect/cancel/reconcile from another
process. It reuses the existing restricted synthetic Kind engine and evidence
verifier. Controller permissions and fault scope stay unchanged; public indexes
cannot turn unsigned historical evidence into trusted execution PASS.

T2.4 adds [Chaos Mesh research and non-executable planning](docs/chaosmesh.md).
The audited provider cannot yet satisfy the approved-UID and independent-expiry
gates. External admission stays DENIED; only CRD-schema/read-only negative tests
are enabled. A second working fault provider and readiness for T3.0 are unproven.

T0 has a reviewed local implementation. Experimental T1.1 adds authorized local
faults and independently observed intervention. Review its implementation and
execution evidence before extending it. Later milestones may add
PostgreSQL recovery and authenticated end-to-end evidence. Arete, Argus
and CloudOps remain optional future integrations.

Read [CONTRIBUTING](CONTRIBUTING.md) before contributing and
[SECURITY](SECURITY.md) for security boundaries and vulnerability reporting.
Licensed under [Apache-2.0](LICENSE).

T3.1 adds a separate [durable PostgreSQL recovery workflow](docs/postgres-durable-recovery.md):
owned persistent source/destination volumes, a validated independent host archive,
separate SIGKILL approval, independently observed failure, and acknowledged data
loss/recovery measurements. Use `themis-postgres durable ...`; existing T3.0
commands remain unchanged. This is an owned local synthetic logical-recovery
experiment; whole-run signing, physical recovery, WAL/PITR and failover are deferred.

T3.2 adds a separate [physical PostgreSQL PITR workflow](docs/postgres-pitr.md):
manifest-verified base backup, independently retained WAL, an exact named target
created after backup completion, separate SIGKILL approval, paused target/data
inspection, observed promotion, and independent cleanup. `themis-postgres pitr`
keeps target fidelity separate from all acknowledged data loss. This remains a
disposable local synthetic experiment; failover and whole-run attestation remain
outside its scope.
