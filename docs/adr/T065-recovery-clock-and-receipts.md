# T065: Explicit recovery interval and receipt clock domains

Status: Accepted for T3.1's disposable local synthetic scope.

Record failure intent, last successful source query start/end, kill call
start/end/acknowledgement, independent stopped observation start/end, restore
start and committed application readiness on one runner monotonic clock.
Compare the conservative upper interval from query start to ready against the
contract. Report the observed-stop-to-ready lower interval and observation
uncertainty separately. T3.0's differently anchored interval is not substituted.

COMMIT receipts are signed only after actual matching acknowledgement and a
successful tool exit. Preparation and execution may be separate OS processes.
Their receipt offsets are ordered within explicit sessions, never subtracted
across sessions. UTC timestamps are informational. Exact missing IDs/count and
contiguous acknowledged recovery point are reported; elapsed acknowledged-loss
gap remains null. This is neither production RPO nor PITR. Lost acknowledgements
and in-flight transactions remain uncertain without fabricated host receipts.
