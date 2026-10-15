# T020: Prerequisites precede durable fault intent

Status: Accepted for the experimental owned-local T1.2 scope.

T1.1 recorded intent before baseline admission. A failed baseline could therefore
be replayed as ambiguous even when Apply was unreachable. T1.2 records baseline
completion, evaluates its measurements, rechecks the current actor, exact target
and live authorization grant, then syncs intent immediately before Apply.
There is no intervening storage or target-resolution call. The authority checks
the claim again atomically at Apply, closing the admission/application race.

Known pre-send rejection is false, transport uncertainty after intent is null,
and a matching authenticated receipt is true. A poisoned journal is never
appended again. Separate immutable failure diagnostics can preserve known
application state when journal publication fails, without repairing its bytes.

Journal/report/inventory become `themis.experiment-journal/v1alpha2` and
`themis.experiment/v1alpha2`. New fields and transitions are rejected under the
old version. T1.1 replay retains its exact report shape and historical ambiguity.
T0 formats, hashes and semantics remain unchanged. Contract/plan formats,
planner/policy versions and adapter bounds are unchanged because fault admission
scope and plan bytes did not change. Fixture control becomes v2 because its
response proof and claim lifecycle changed. Existing live v1 workers expire;
there is no in-place migration or automatic restart.

Behavioral tests cover rejected baseline/revalidation, failed and torn intent
writes, lost real HTTP acknowledgments, successful application and old report
format decoding. The handoff also compares archived published artifacts against
the previous binary; generating a new golden alone is not compatibility proof.
