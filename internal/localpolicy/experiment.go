package localpolicy

import "time"

// These are trusted hard limits, not contract-supplied permissions.
const (
	ExperimentVersion     = "themis.owned-local/t1.1-v1"
	AdapterVersion        = "themis.latency-proxy/v1"
	MaxExperimentDuration = 15 * time.Second
	MaxFaultDuration      = 3 * time.Second
	MaxLatency            = 300 * time.Millisecond
	MinLatency            = 150 * time.Millisecond
	AuthorizationTTL      = 20 * time.Second
	FixtureTTL            = 2 * time.Minute
	RequestLimit          = 750 * time.Millisecond
	CleanupLimit          = 2 * time.Second
	MaxPhaseSamples       = 20
)
