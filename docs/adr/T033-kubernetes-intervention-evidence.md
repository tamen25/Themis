# T033: Correlated independent probes and bounded provenance

Status: Implemented for owned Kind T2.1; pending independent review.

Collect three planned samples in each baseline/intervention/recovery phase.
Each slot sends independent concurrent direct, proxy and application HTTP
requests with one unpredictable request ID. Fixture signatures bind endpoint,
request, Pod/boot/proxy identity, invocation and HTTP status. Client monotonic
start/end measurements are separate unauthenticated facts.

Confirm intervention only with complete valid samples and three paired proxy
latency increases of at least 70% of the approved delay, a direct control below
half that delay, and the approved invocation on proxy/application responses.
Baseline and recovery require all successful signed responses and low paired
latency, with no active invocation.
Signed proxy responses additionally record that request's actual monotonic delay
wait. Confirmation requires both that hold and the independent paired client
increase; scheduling or forged client timing alone cannot elevate a no-op.
The initial contract requires zero errors; any credible signed application
failure contradicts that exact threshold. A
successful adapter receipt cannot replace measurement. Missing, duplicated,
misidentified or invalid observations block PASS.

Only an authorized live runner session may return verified PASS, with proven
intervention, full coverage, assertions, recovery and cleanup. Offline journals
report the recomputed candidate verdict but downgrade a candidate PASS to
INCONCLUSIVE. Signed responses do not authenticate client clocks, the complete
history, honest fixture software or independent Kubernetes execution provenance.
The journal is unsigned; this is not a remote gate or T4 evidence signing.
