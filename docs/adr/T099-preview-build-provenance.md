# T099: Attribute preview binaries to their exact public source snapshot

Status: Implemented; qualification depends on retained execution evidence.

Build every CLI twice with the exact go.mod patch version, separate source
directories and separate empty build caches. Use offline module resolution,
disabled CGO, trimpath, disabled VCS discovery and an empty linker build ID.
Reject any differing binary hash. Shared read-only module inputs and the same
builder/toolchain remain assumptions; this is not independent-machine provenance.

The manifest binds every public source path/hash, selected module version/sum,
Go executable hash, platform, actual command and exact output hash. Normalize
UTF-8 source text to the repository's LF convention while preserving binary
fixtures. Refuse source symlinks, private input paths and oversized snapshots.
Require a clean checkout by default. Explicit dirty review builds identify both
the base commit and the snapshot digest and cannot claim their changes are in HEAD.

Only the existing main CLI has a version command; keep other CLI contracts
unchanged and attribute their binaries through the manifest. SHA256SUMS covers
the manifest, every binary and public documentation. Checksum metadata requires
an independently trusted distribution channel and supplies no infrastructure
attestation, signature trust, release approval or target-platform test result.

The manual build workflow uses read-only permissions and pinned action revisions.
It uploads a candidate with limited retention and never creates a release,
commits source, changes trust policy or promotes experiment evidence.
