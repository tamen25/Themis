# T054: A blocked second provider does not justify a plugin framework

Status: Accepted.

Keep Chaos Mesh research/planning in one concrete package and separate CLI. Reuse
the actual safe Kubernetes compiler, bounded JSON/private-state utilities and
result types; do not rewrite either working synthetic engine. No provider registry,
DSL, scheduler, arbitrary Kubernetes mutation interface or second evaluator exists.
Only after a safe second actuator works should shared execution abstractions be
extracted around observed requirements and tested compatibility. T3.0 remains
blocked on proving the external-provider milestone, not on adding generic APIs.
