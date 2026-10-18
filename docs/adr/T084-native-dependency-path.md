# T084: One real application dependency path

Use three distinct owned synthetic Pods: application, explicit fixed local proxy
and dependency. The application performs a real outbound request and returns its
nonce-bound nested signed dependency response. Only the proxy adds the approved
fixed response delay after the upstream operation. Do not wrap or relabel the old
T2.1 application-handler fixture. Themis owns this small L7 safety mechanism; it
does not fork Chaos Mesh or create a generic privileged provider engine.

Keep the new wire/server package and concrete Kubernetes adapter separate from
old formats. No new provider registry or source-bundle mapping is needed. See
[scope and protocol](../native-dependency.md).
