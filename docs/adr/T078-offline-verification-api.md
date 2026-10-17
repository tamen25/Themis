# T078: Independent offline verification has no execution authority

Status: Implemented for T4.0.

pkg/evidence verifies ReaderAt bytes with an external policy and explicit clock.
It reports source checks NOT_CHECKED. pkg/evidenceverify adds the two concrete
historical source mappings through in-memory APIs. Neither API opens paths from
artifacts, creates clients or invokes infrastructure actions. The CLI opens only
explicit bundle/policy paths. Export and key access are separate operator actions.

Source verification does not trust the report's verdict. It rechecks supported
chains, signatures, identity correlations, measurements and existing predicates,
then compares the report and authenticated claims. Missing observations and
unsupported checks stay explicit. A separately built verifier works with only
public bundles and external policy on another OS. Future transparency logs and
external execution witnesses need new mechanisms and versioned provenance;
neither is implied by this milestone.
