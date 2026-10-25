# T089: No native runtime workload mutation

Use a fresh uniquely named Kind, unique namespace, scratch digest-pinned source
images and protected original engine/cluster/namespace records. The explicit local
installer alone creates/removes resources. Runtime gets only named identity reads,
SelfSubjectReview and exact-Pod forwarding; existing controller/runner Roles are
unchanged. Data Pods have no token, privilege, host namespaces/mounts or exec path.

Application/proxy transports allow only their fixed dependency IPs/paths and no
redirect or general upstream interface. Owned loopback NodePort mappings allow
actual probing/expiry confirmation during API outage; actuator boot binding still
blocks replacement authority. These are application-code restrictions, not a CNI
isolation claim against a hostile administrator. Trusted tests alone may kill an
exact owned task or delete an owned Pod with UID precondition, and restore outages.
