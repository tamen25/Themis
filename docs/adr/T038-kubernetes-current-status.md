# T038: Historical execution and current observation are separate

Status: Implemented for T2.2.

Version inspection. Show offline historical verification, journal completeness,
unsigned saved report/verdict and cancellation separately from fresh original
fixture reachability and signed state. Include deadline passage, cleanup expiry,
prior receipt and reconciliation availability. Status publishes no files and
sends no Remove. Nonce bookkeeping is replay protection, not fault mutation.

Absent/replaced/unreachable Pod means UNKNOWN. Deadline passage is neither a
current observation nor application recovery. Signed current state cannot
authenticate old journals/reports/receipts. Expired cleanup authority can prevent
queries even with reachable identity. This is a concrete CLI projection, not a
new controller status CRD or distributed event protocol.
