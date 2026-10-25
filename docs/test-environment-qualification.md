# Test environment qualification

Correct execution, repeatable observation collection and platform qualification
are separate results. A complete, valid observation history may correctly yield
INCONCLUSIVE under contention. It must never be relabeled PASS to qualify a host.
The milestone handoff identifies the exact source, SDK, host and actual outcomes.

## Admission for timing assertions

Use the exact Go patch in go.mod, original contract/sample settings and normal
Go package concurrency. Prepare dependencies and tools before measurements;
record the actual SDK, CPU count, GOMAXPROCS, OS and source inventory. Do not
serialize packages, lower concurrent test coverage or retry failed runs until a
favorable result appears. Ordinary CI runs keep opt-in fault flags unset.

Run each Kind, PostgreSQL family, controlled load campaign, fuzz campaign and
ordinary full suite separately. Give live campaigns new original-authority
resource roots. Use the explicit original local Docker endpoint and engine,
empty DOCKER_CONTEXT and an isolated Docker configuration. Do not run a timing
qualification suite alongside image builds, database recovery, fault campaigns
or deliberate CPU workers. Background host activity and storage/scheduler limits
remain measured limitations rather than authenticated isolation guarantees.

Before calling a host profile repeatable, predeclare three successive ordinary
Windows full-suite executions with default concurrency and no source edits.
Retain every output and exit. All three must pass; a failure leaves repeatability
qualification FAIL until a cause is investigated and a justified correction is
reviewed. A later green rerun does not erase the failed qualification attempt.
This is a finite qualification of that observed environment, not a guarantee for
every future workload or moving hosted-runner image.

## Controlled contention

Keep idle, moderate and heavier load as distinct scenarios. Record requested
workers, actual completed CPU work, process placement, fixture binary hash,
all client timings, application results and cleanup. Where possible compare CPU
work in the observer process with separately spawned owned load processes;
the fixture remains an independent process. Stop only those original workers.

Test load both before baseline and after independent expiry. The latter requires
an authenticated original actuator status containing the exact fault's expired
event and no active fault before load starts. A recovery-phase label alone does
not establish expiry. Missing expiry evidence leaves that matrix cell unqualified.

The 50ms paired recovery bound, application ceiling, original sample requirements,
fault lifetime and coverage/verdict rules remain unchanged. If load prevents
baseline admission, report the denial and absence of intervention. If it prevents
complete trustworthy recovery observations, retain INCONCLUSIVE and the measured
reason. Such histories establish conservative correctness; they do not qualify
that profile for deterministic PASS assertions. A diagnostic recorder's zero
exit means it retained measurements, not that all experiments passed.

## Independent release gates

Current-user private-state tests do not qualify the Administrators-owned creation
branch. That branch requires an explicitly authorized isolated Windows runner
with the necessary ownership privileges; unavailable setup remains NOT RUN.
Do not change machine ACL policy or weaken owner/DACL checks to avoid a skip.

Cross compilation and local repeated builds do not qualify native macOS execution
or hosted Windows/Linux/macOS CI. Exact source/toolchain attribution, original-ID
cleanup, signed evidence verification and image/package scans remain separate
gates. The release-readiness report must preserve every applicable FAIL/NOT RUN;
local success does not authorize staging, committing, pushing, dispatch or release.
