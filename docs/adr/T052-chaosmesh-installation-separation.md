# T052: Schema-only isolated installation while gates remain closed

Status: Accepted for T2.4 test infrastructure.

Create a new random uniquely owned Kind cluster with private kubeconfig and live
UID guards. Install only the digest-verified NetworkChaos CRD schema, existing safe
controller and read-only planner. No Chaos Mesh manager, privileged daemon or fault
resource is installed. Document upstream host PID/runtime socket/system mounts,
privileges and broad controller RBAC rather than hiding them. Existing controller
and synthetic runner Roles remain byte-identical. Real SARs verify denied writes.
Schema server dry-run is not a provider experiment or runtime compatibility proof.
