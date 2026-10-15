# Owned local latency demo (experimental)

T1.2 adds `themis experiment status --run <private-run-directory>` for read-only
inspection, and `experiment cancel` for safe cross-process cancellation.
`experiment cleanup` reconciles resources while preserving historical results.
See [lifecycle and trust limits](../../docs/experiment-lifecycle.md).

Build `themis` and use the compiled executable to retain its actual exit code.
The contract names fixture `demo`; each case must use a new directory and a new
fixture. No external service or privileged networking command is used.

PowerShell (from the repository; replace `healthy` with another mode per case):

```powershell
$themis = (Resolve-Path bin/themis.exe).Path
$fixture = Join-Path (Get-Location) ('.themis/fixtures/demo-' + [guid]::NewGuid().ToString('N'))
& $themis fixture start --directory $fixture --name demo --mode healthy
$plan = (& $themis experiment plan -f examples/owned-latency/experiment.yaml --fixture $fixture) | ConvertFrom-Json
$plan | ConvertTo-Json -Depth 20
# Review the resolved target, scope, limits and digest above before authorizing.
$approval = (& $themis experiment authorize -f examples/owned-latency/experiment.yaml --fixture $fixture --approve $plan.planDigest) | ConvertFrom-Json
& $themis experiment run -f examples/owned-latency/experiment.yaml --fixture $fixture --authorization $approval.authorizationFile
$LASTEXITCODE
```

The authorization is valid for 20 seconds. The fixture is valid for at most two
minutes; if review takes longer, create a fresh fixture and review its new plan.
Windows directories are protected with real owner-only DACLs. In WSL place
fixture/run directories under `/tmp` or Linux home, rather than an NTFS mount
without Unix mode enforcement. The same CLI commands work in Bash; copy the
digest and authorization path from JSON or use a JSON reader.

| Mode | Expected real evidence | Verdict / execution | Exit |
| --- | --- | --- | --- |
| `healthy` | ~200ms proxied excess latency; successful app and recovery | PASS / SUCCEEDED | 0 |
| `buggy` | Same independently observed delay; app's 50ms dependency budget produces signed 503s; recovery succeeds | FAIL / SUCCEEDED | 2 |
| `noop-adapter` | Apply receipt exists but no extra response delay; app and recovery succeed | INCONCLUSIVE / SUCCEEDED | 3 |
| `cleanup-denied` | Delay and recovery observed; owned listeners remain after rejected stop | INCONCLUSIVE / CLEANUP_PENDING | 7 |

Read `report.json` and replay `events.jsonl` in the corresponding
`.themis/experiments/run-<id>` directory. For a pending/interrupted run:

```sh
themis experiment cleanup --run <private-run-directory>
```

For `cleanup-denied`, allow the configured lifetime to expire and retry cleanup.
Successful reconciliation establishes that the resources disappeared; it does
not change historical evidence into PASS. Integration tests deliberately kill
their own child processes to verify the independent expiry and crash behavior.
