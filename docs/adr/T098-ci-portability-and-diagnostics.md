# T098: Keep CI fixes separate from experiment semantics

Status: Implemented; current-platform and hosted qualification evidence required.

The historical hosted dry-run failure submitted a VerificationRun while its
custom-resource quota counter was still unknown. Wait for that actual counter,
as the later owned installers already do. A timeout fails installation; it
does not bypass quota or change the controller's privileges.

The historical Linux race test filled the global status registry before Apply.
Its first subcase took over the unchanged 20-second approval window and received
AuthorizationDenied. After filling that registry, explicitly approve a distinct
new invocation. Its original deadline still applies. This tests global capacity
separation without extending or renewing authority. Expiry and replay tests remain.

On Windows an elevated token can select Administrators as the default object
owner. Protection of newly created private state sets the current-user owner
only if it differs, alongside the existing exact protected DACL. Requesting
WRITE_OWNER for an already-correct owner is unnecessary and can fail under a
restricted account. Reads still require the original current-user SID and exact
DACL; no group-owned or foreign existing state is admitted. The regression uses
only new test files and explicitly skips when assigning that group owner is
unavailable. A skip supplies no administrator-runner qualification.

Preserve all original cancellation/PASS assertions. Replace phase polling's
unconditional wait with a bounded select that also observes runner completion;
read output buffers only after Wait. Split the FINAL disjunction so an original
INCONCLUSIVE result cannot be mislabeled as rewritten history. These diagnostics
do not establish the cause of the three historical intermittent Windows failures.

Pin CI's Go patch from go.mod and explicit OS/AMD64 runner families, disable
shared dependency/build cache restoration, retain exact child outputs/exits and
record observed runner/tool versions. Use read-only repository permission and
unprivileged PR events without deployment secrets. Moving runner images and the
public advisory database remain observed inputs. No green hosted result is
inferred from local execution or a workflow edit.

The native integration harness previously hard-coded a Windows Docker pipe,
Windows PowerShell and a local command proxy. Accept only an explicitly supplied
standard local Docker endpoint, choose PowerShell for the host OS and make the
proxy optional. Keep actual runner/witness child processes direct so process-death
tests still terminate the intended process. Installer ownership and mutation
guards, principal privileges and native expiry remain unchanged.
Reject a nonempty DOCKER_CONTEXT before any native harness target access; Docker
gives that variable precedence over DOCKER_HOST. Explicit local host selection
alone is insufficient when both are present.

Original lifecycle tests also assumed the legacy cluster name even when invoked
with a fresh T4.1 installer-owned cluster. Select context, node and controller
restart arguments from the already validated execution owner. Bind the bootstrap
owner to that same name/context, state directory and original cluster/namespace
UIDs before mutation. Run lifecycle and signed-witness suites in separate fresh
clusters: a deliberate Pod replacement must not silently repin an existing witness.

The manual PostgreSQL regression matrix runs the existing logical, durable, PITR
and replication test families on separate disposable runners with fresh private
roots. A long aggregate test must not consume another family's test-job budget.
This changes CI scheduling only, not experiment or cleanup authority deadlines.
