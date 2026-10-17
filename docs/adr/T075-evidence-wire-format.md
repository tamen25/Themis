# T075: One deterministic bounded evidence format

Status: Implemented for themis.evidence-bundle/v1alpha1; review required.

Use compact typed Go JSON in specified struct order, SHA-256 artifact hashes and
a domain-separated detached Ed25519 signature over complete manifest bytes.
This is not RFC 8785. The manifest binds provenance, complete inventory, source
identities and publisher claims. Its content ID excludes only its own value.

Use one canonical STORE-only ZIP encoding with fixed paths/metadata/order. Reject
all other encodings, compression, symlinks, devices, duplicates, traversal, hidden
or Unicode filenames, extra entries, comments and data outside the archive.
Preflight the central directory before archive/zip allocation; enforce file,
count, metadata and total byte budgets before opening entries. No extraction or
artifact-supplied path access exists. See the normative field structs and
[format specification](../evidence-bundles.md).
