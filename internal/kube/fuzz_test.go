package kube

import (
	"encoding/json"
	"testing"
)

func FuzzDryRunSpec(f *testing.F) {
	_, valid, _, _, _ := fixtures()
	seed, _ := json.Marshal(valid)
	f.Add(seed)
	f.Add([]byte(`{"executionProfile":"fault-injection"}`))
	f.Add([]byte(`{"executionProfile":"kind-dry-run","executionProfile":"fault-injection"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := DecodeSpec(data)
		if err != nil {
			return
		}
		p, _, cluster, namespace, target := fixtures()
		plan, code := p.Compile("44444444-4444-4444-4444-444444444444", 1, s, cluster, namespace, target)
		if code == "" {
			preview := plan.Snapshot()
			if preview.Plan.ExecutionAllowed || preview.Plan.ExecutionProfile != Profile || preview.Plan.Target.Reference.Namespace != Namespace || preview.Digest == "" {
				t.Fatal("unsafe preview from untrusted input")
			}
		}
	})
}
