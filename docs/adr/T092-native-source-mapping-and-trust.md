# T092: Add one native mapping without execution-trust promotion

`native-dependency-witness/v1` joins nine public artifacts: original native plan,
public approval reference, exact runner journal bytes, curated original result,
readiness admission, signed runner assertions, separate later cleanup receipts,
registration and exact signed
witness journal bytes. The unchanged T4.0 manifest covers the complete inventory;
publication remains retrospective. No grant, private key or runtime inventory is
exported. Missing results are explicit, never synthesized from witness recovery.

Verify original event order, signatures, original source predicates, exact identity,
grant/readiness/nonce correlations and independent measurements. Separate source
candidate, witness signature/trust, identity/authority correlation, effect, recovery
and original cleanup findings. Preserve cancellation, source uncertainty and
CLEANUP_PENDING even after healthy observations or later reconciliation. A trusted
publisher may sign fabricated PASS; unchanged witness records must expose conflict.

Use an additive VerifyNative result; historical T4.0/T4.1 formats and bytes remain
unchanged. Whole-execution trusted verdict is always INCONCLUSIVE and
NOT_INDEPENDENTLY_ATTESTED. No execution, path discovery or live infrastructure
access occurs in the offline mapping. It is not an automatic release gate.
