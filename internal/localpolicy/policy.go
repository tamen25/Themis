// Package localpolicy defines the versioned bounds shared by planning and execution.
package localpolicy

import "time"

// Changing execution or evaluation semantics requires a new policy version and
// planner version so approvals cannot silently acquire a different meaning.
const (
	Version                = "themis.local-http/t0-v1"
	Interval               = 100 * time.Millisecond
	RequestTimeout         = time.Second
	MaxResponseHeaderBytes = 16 << 10
)
