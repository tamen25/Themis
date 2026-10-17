// Package evidenceverify adds Themis's two concrete historical source checks to
// the dependency-light evidence archive verifier. All verification is in memory;
// it does not connect to Docker, Kubernetes or a private runtime directory.
package evidenceverify

import (
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidence"
	"io"
	"time"
)

func Verify(r io.ReaderAt, size int64, policy *evidence.Policy, now time.Time) (evidence.Opened, error) {
	o, err := evidence.Verify(r, size, policy, now)
	if err == nil {
		evidencesource.Check(&o)
	}
	return o, err
}
