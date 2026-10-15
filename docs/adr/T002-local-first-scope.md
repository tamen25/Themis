# ADR-T002: Local first and bounded first vertical slice

Status: Accepted — 2026-10-15

Follow-up: ADR-T012 extends this first slice with local observations and replay.
Go 1.26.9 supersedes the initial 1.26.8 toolchain minimum after the HTTP audit.

## Context

The guide's wider T0 includes local run state and synthetic probes. The requested
first slice specifically requires validation, verdict types and planning while
excluding fault execution. The guide's contract example targets Kubernetes and
uses signing, which cannot honestly be supported by this empty repository.

## Decision

Implement T-001–T-006 as a single Go executable and internal domain packages.
Define a strict `local-http` planning subset of the proposed v1alpha1 contract:
named loopback endpoint, ordered observation phases, bounded `http-ready` and
`http-success-rate` declarations. Preserve the guide's metadata/execution/scenario/
assertion/evidence structure. Reject Kubernetes, faults, providers and signing.

Use the standard library for the CLI; use established YAML and JSON Schema
libraries for those formats. Do not create empty runner, storage, controller,
SDK or adapter packages. Use Go 1.26.8 or newer and Apache-2.0, as selected by the
maintainer.

The initial audit under the installed Go 1.26.2 found reachable
[GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218) in `net/url`. Require the
patched 1.26.8 baseline rather than accepting a known vulnerable build toolchain.

## Consequences

This is a useful planning foundation, not the guide's full T0 exit gate. T-007,
T-008 and unsigned reports follow next. Target identity is declared, not resolved
against a running workload. Adding runtime checks needs an explicit schema and
plan-compatibility decision; acceptance today does not promise execution.
