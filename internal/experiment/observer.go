package experiment

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localstate"
)

// observe uses separate concurrent client requests, not the adapter's counters.
// A shared unpredictable correlation ID connects direct, proxy and application
// observations without persisting credentials, arbitrary bodies or diagnostics.
func observe(ctx context.Context, c *fixture.Client, epoch time.Time, phase string, index int) Observation {
	o := Observation{Phase: phase, Index: index, RequestID: localstate.RandomID(), Probes: make([]Probe, 3)}
	var group sync.WaitGroup
	for i, kind := range []string{"direct", "proxy", "application"} {
		group.Go(func() {
			p := Probe{Kind: kind, StartedNS: int64(time.Since(epoch)), Outcome: "request-error"}
			response, err := c.DataRequest(ctx, kind, o.RequestID)
			if err == nil {
				data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
				_ = response.Body.Close()
				if readErr == nil && len(data) <= 4096 {
					var body fixture.DataResponse
					if localstate.Unmarshal(data, &body) == nil {
						p.Outcome = "http"
						p.StatusCode = response.StatusCode
						p.Response = &body
					}
				}
			}
			p.CompletedNS = int64(time.Since(epoch))
			o.Probes[i] = p
		})
	}
	group.Wait()
	return o
}
