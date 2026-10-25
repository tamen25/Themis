package ownedtask

import (
	"strings"
	"testing"
)

func TestStaticMirrorIdentityIsSeparateAndRestricted(t *testing.T) {
	cluster := "themis-t42-0123456789ab"
	node := cluster + "-control-plane"
	apiUID := "original-api-mirror-uid"
	hash := strings.Repeat("a", 32)
	for _, mode := range []string{"valid-static", "missing-api-uid", "wrong-node", "wrong-component", "wrong-namespace", "missing-mirror", "hash-mismatch", "wrong-source", "ordinary-workload", "mirror-on-workload"} {
		t.Run(mode, func(t *testing.T) {
			ns, name, n, uid := "kube-system", "kube-apiserver-"+node, node, apiUID
			a := map[string]string{"kubernetes.io/config.mirror": hash, "kubernetes.io/config.hash": hash, "kubernetes.io/config.source": "file"}
			switch mode {
			case "missing-api-uid":
				uid = ""
			case "wrong-node":
				n = "unrelated"
			case "wrong-component":
				name = "other-" + node
			case "wrong-namespace":
				ns = "default"
			case "missing-mirror":
				delete(a, "kubernetes.io/config.mirror")
			case "hash-mismatch":
				a["kubernetes.io/config.hash"] = strings.Repeat("b", 32)
			case "wrong-source":
				a["kubernetes.io/config.source"] = "http"
			case "ordinary-workload":
				ns = "themis-dep-0123456789ab"
				a = map[string]string{}
			case "mirror-on-workload":
				ns = "themis-dep-0123456789ab"
			}
			got, err := RuntimeUID(cluster, ns, name, n, uid, a)
			if mode == "valid-static" {
				if err != nil || got != hash || got == apiUID {
					t.Fatal(got, err)
				}
			} else if mode == "ordinary-workload" {
				if err != nil || got != apiUID {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("unrelated identity accepted")
			}
		})
	}
}
