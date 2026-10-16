# CLI reference

The separate owned Kind binary supports `cancel --run-directory`,
`status --run-directory`, `reconcile --run-directory` and
`verify -f events.jsonl [--expect-plan-digest DIGEST]`.
See [Kubernetes lifecycle CLI and exit semantics](kubernetes-lifecycle.md).
These commands do not add authority to the local CLI or dry-run controller.

T0 commands and formats retain their existing meanings. `themis --help` lists
them; [run semantics](runs.md) describe T0 journaling. T1.1 is an explicitly
experimental namespace: `themis experiment --help`.

| Command | Inputs and behavior |
| --- | --- |
| `fixture start` | Required `--directory` must be new. `--name demo`, `--mode healthy`, `--ttl 2m` are defaults. Starts the separate owned process and prints resolved identity JSON. TTL range 15s–2m. |
| `fixture status` | `--directory` authenticates that exact instance; prints active fault, apply count and bounded structured lifecycle events. |
| `fixture stop` | `--directory` authenticates and stops the fixture, then checks listeners. Repeated stop after disappearance cannot authenticate; use experiment cleanup for durable idempotent reconciliation. |
| `experiment validate` | `-f` reads strict v1alpha2 YAML/JSON and prints its digest. No network. Safety admission is still separate. |
| `experiment plan` | `-f`, `--fixture`. Resolves and authenticates the live fixture; prints immutable plan JSON and digest. Sends read-only identity requests. |
| `experiment authorize` | `-f`, `--fixture`, `--approve sha256:...`. Requires the exact resolved digest; authority recompiles and applies trusted policy. Prints private `authorizationFile`, digest and expiry. No fault application. |
| `experiment run` | `-f`, `--fixture`, `--authorization <file>`, optional `--runs-dir` (default `.themis/experiments`). Consumes the single-use 20s authorization; prints structured verification report JSON. |
| `experiment replay` | `-f <events.jsonl>`. Offline consistency checking and re-evaluation. No control requests or external actions. |
| `experiment cleanup` | `--run <directory>`. Independently reconciles the protected resource inventory; prints a new cleanup receipt. Historical report and journal are preserved. |
| `experiment status` | `--run <directory>`, optional `--output text\|json` (default text). Read-only journal-prefix inspection, original result, runner lock, authenticated live state and independent listener observations. |
| `experiment cancel` | `--run <directory>`, optional `--output text\|json` (default JSON). Durably requests cancellation, permanently fences the owned claim, removes its fault and attempts authorized shutdown. Works from another process. |

Supported fixture modes are `healthy`, `buggy`, `noop-adapter`, `cleanup-denied`.
Mode selection occurs only when creating the owned demo process; contracts
cannot select arbitrary workload behavior. The final mode blocks fixture stop to
exercise pending cleanup; the fault and fixture still expire independently.

Every experiment command rejects unknown flags and extra positional arguments.
There is no `--approve-plan`, `--force`, arbitrary target URL or fault bypass in
this namespace. Old T0 commands reject fault-capable contracts.

Exit 0 means PASS or a successful administrative command. Completed FAIL uses 2;
INCONCLUSIVE/cancel/timeout uses 3; invalid configuration 4; denied authorization
5; infrastructure or corrupt replay 6; unresolved cleanup 7. Cleanup pending
has precedence over the separate verification verdict. An interrupted experiment
journal without terminal cleanup stays pending on offline replay. T0 exit
semantics are unchanged.

T1.2 `run`, `replay` and `cleanup` also accept `--output text|json`; their
default remains JSON. `replay --provenance imported` explicitly classifies
externally supplied evidence in a versioned replay envelope. Default replay
classifies new journals as `UNSIGNED_LOCAL_REPLAY`. Old T1.1 report JSON retains
its published shape; human output and imported envelopes describe its limits.

Status exit 0 means inspection completed without a reconciliation requirement;
it does not mean the historical experiment passed. Exit 7 means operator action
is necessary. Missing/corrupt protected inventory is visible as unusable and
never authorizes mutation. Cancel/cleanup return 7 for unresolved resources or an
unpersisted cleanup receipt, even when listeners appear closed. Invalid protected
state is reported as an error; independent fixture expiry remains the fallback.

New local artifacts include `runner.lock`, `lifecycle.lock`, immutable
`action-<id>.json`, `failure-<id>.json` and a single `stop-request.json` when an
external action is accepted before finalization. Inspect these only locally;
the private inventory and fixture directory must not be uploaded wholesale.
See [lifecycle, versions and cancellation](experiment-lifecycle.md).

Run artifacts are `resources.json`, append-only `events.jsonl`, `report.json` and
new `cleanup-<random-id>.json` receipts under the private run directory. Fixture
state includes private credentials and authorization files: keep them local.
`worker.log` contains worker diagnostics, never HTTP bodies or control tokens.

T2.3 adds `themis-kube coordinate preview|prepare|approve|start|status|cancel|reconcile|verify`.
The [operator coordination guide](kubernetes-coordination.md) describes exact JSON
records, private state, explicit digest approval, single-use start, independent
cancel/reconcile and offline trust semantics. Existing individual commands and
their formats remain available. An administrative exit 0 is not a verdict.

The separate `themis-chaosmesh plan|admit|provider` CLI is documented in the
[external-provider planning guide](chaosmesh.md). Plan/provider are read-only
administrative output; admit always returns DENIED/NOT_RUN, exit 5. It has no
fault execution or approval command and cannot consume synthetic grants.
