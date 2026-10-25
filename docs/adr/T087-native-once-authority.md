# T087: Separate one-use native plan and approval domains

Use new versioned native installation, plan, grant and command domains. Explicit
exact-digest approval creates one invocation, a 20-second first-Apply window and
distinct Apply/cleanup keys; cleanup lasts five minutes. Old fixture and Chaos Mesh
artifacts cannot authorize the mechanism. Durable runner claim and actuator intent
precede mutation. Duplicate Apply returns its original receipt without renewal;
ambiguous acknowledgement consumes the attempt and cannot trigger another Apply.
Pre-Apply Remove permanently fences the invocation. Polling is read-only and cannot
consume mutation capacity. Bound registries/journals refuse admission and reserve
space for cleanup rather than evicting replay state.

Private keys stay with explicitly provisioned actors. Same-user/admin custody is
not independent human authentication. Full portable authorization correlation and
external evidence trust are T4.3 work, not implied by native source replay.
