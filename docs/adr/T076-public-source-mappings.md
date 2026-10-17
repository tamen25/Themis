# T076: Concrete public evidence mappings without private inventory export

Status: Implemented for T3.3 replication and T2.3 synthetic Kubernetes.

The dependency-light public archive package imports only the standard library.
A separate public full verifier calls two concrete pure in-memory source mappings.
Reuse the existing Kubernetes evaluator and PostgreSQL receipt, state, timeline
and assertion predicates. No provider registry, scheduler or runtime interface.

The original PostgreSQL plan embeds private paths, actor and ownership inventory.
Export a versioned public plan projection instead: safe original identities,
contract, public receipt key, authority-key fingerprints and opaque original
plan/inventory digest references. Verify its own digest, preparation seal,
receipt and journal bindings. Explicitly report that the withheld original plan
cannot be recompiled offline. Do not redact and relabel the original plan as if
its digest still verified. No private file is changed.

Kubernetes retains its original full public plan in the journal and original
public proposal/preview/request mapping. Recompute fixture signatures and client
predicates; client clocks and whole-run provenance remain unauthenticated.
Unsupported engines/versions remain unsupported. Existing older engine replay
continues independently; opaque integrity signing is not a new legacy verifier.
