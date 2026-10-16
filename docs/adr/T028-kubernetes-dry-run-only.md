# T028: Preview is not verification execution

Status: Accepted; T2.1 execution is excluded.

Control flow ends at planning. No runner, observation, intervention or assertion
execution is invoked. Valid previews are NOT_RUN; incomplete/invalidated data is
INCONCLUSIVE. The status schema excludes PASS/FAIL and executionAllowed=true.

There is no Chaos Mesh client, target patch, pod deletion, fault Job or arbitrary
command interface. Setup creates the synthetic application; restart tests roll
only the owned controller. Live tests never alter the target to manufacture drift;
controlled client fixtures cover external replacement and ownership changes.
Local T1.2 execution stays separate. A single bounded cluster experiment needs a
new T2.1 design/review and authorization boundary before implementation.
