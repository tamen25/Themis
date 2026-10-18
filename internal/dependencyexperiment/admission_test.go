package dependencyexperiment

import (
	"context"
	"errors"
	"k8s.io/client-go/tools/clientcmd"
	"path/filepath"
	"testing"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestExplicitKubeconfigRejectsExternalExecutableOrImpersonatedAuthority(t *testing.T) {
	for _, kind := range []string{"external", "url-userinfo", "insecure", "exec", "auth-provider", "password", "impersonation", "wrong-role"} {
		t.Run(kind, func(t *testing.T) {
			dir, e := localstate.CreateDirectory(filepath.Join(t.TempDir(), "actor"))
			if e != nil {
				t.Fatal(e)
			}
			o := Owner{Version: "themis.native-http-owner/v1alpha1", ClusterName: "themis-t42-123456abcdef", Namespace: "themis-dep-123456abcdef", Role: "observer"}
			contextName := "kind-" + o.ClusterName
			cluster := &clientapi.Cluster{Server: "https://127.0.0.1:12345"}
			actor := &clientapi.AuthInfo{Token: "unit-test-placeholder"}
			switch kind {
			case "external":
				cluster.Server = "https://example.com:443"
			case "url-userinfo":
				cluster.Server = "https://invalid-user@127.0.0.1:12345"
			case "insecure":
				cluster.InsecureSkipTLSVerify = true
			case "exec":
				actor.Token = ""
				actor.Exec = &clientapi.ExecConfig{Command: "must-not-execute", APIVersion: "client.authentication.k8s.io/v1", InteractiveMode: clientapi.NeverExecInteractiveMode}
			case "auth-provider":
				actor.Token = ""
				actor.AuthProvider = &clientapi.AuthProviderConfig{Name: "must-not-execute"}
			case "password":
				actor.Token = ""
				actor.Username = "invalid-user"
				actor.Password = "unit-test-placeholder"
			case "impersonation":
				actor.Impersonate = "administrator"
			case "wrong-role":
				o.Role = "runner"
			}
			config := clientapi.Config{Kind: "Config", APIVersion: "v1", Clusters: map[string]*clientapi.Cluster{"owned": cluster}, AuthInfos: map[string]*clientapi.AuthInfo{"observer": actor}, Contexts: map[string]*clientapi.Context{contextName: {Cluster: "owned", AuthInfo: "observer"}}, CurrentContext: contextName}
			if localstate.WriteNew(filepath.Join(dir, "owner.json"), o) != nil {
				t.Fatal("protected config write failed")
			}
			data, e := clientcmd.Write(config)
			if e != nil {
				t.Fatal(e)
			}
			file, e := localstate.OpenNew(filepath.Join(dir, "kubeconfig"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = file.Write(data); e != nil {
				t.Fatal(e)
			}
			_ = file.Sync()
			_ = file.Close()
			_, e = Open(context.Background(), dir, "observer")
			if !errors.Is(e, wire.ErrDenied) {
				t.Fatalf("unsafe credentials reached another failure path: %v", e)
			}
		})
	}
}
