# T077: Explicit protected signing and exclusive local publication

Status: Implemented for one trusted local OS actor.

Use a dedicated themis-evidence command. Key generation creates a new owner-only
directory/key using existing real Windows DACL or Unix permission checks. Every
bundle invocation explicitly selects that signer and a curated source export.
No report verdict triggers signing. Never export capabilities, passwords,
private keys, raw database volumes/WAL or ownership inventories.

Two bounded reads and file identity/metadata comparisons detect observed source
changes. The signed in-memory snapshot cannot change later. Publish a complete
synced temporary archive through an exclusive hard link; never replace a final
path. Tests kill an actual publisher before its final link and inject publication
failure. Crashes may retain an abandoned temporary file for operator review.
Trusted filesystem/account assumptions remain; no global multi-file transaction,
malicious-owner isolation, hardware immutability or power-loss guarantee exists.
