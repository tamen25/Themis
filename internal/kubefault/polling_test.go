package kubefault

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

func TestStatusPollingCapacityCannotBlockCleanup(t *testing.T) {
	for _, action := range []string{"remove", "expire"} {
		t.Run(action, func(t *testing.T) {
			_, client, auth, _ := setup(t, "healthy")
			ctx := context.Background()
			for i := 0; i < 4095; i++ {
				if _, err := client.Control(ctx, auth, "status"); err != nil {
					t.Fatalf("poll %d: %v", i, err)
				}
			}
			applied, err := client.Control(ctx, auth, "apply")
			if err != nil || !applied.Active {
				t.Fatal("status polling prevented first authorized Apply", err)
			}
			last, err := client.Control(ctx, auth, "status")
			if err != nil || !last.Active {
				t.Error("status budget did not remain separate from mutation budget", err)
			}
			if _, err = client.Control(ctx, auth, "status"); err == nil {
				t.Fatal("status storage is not bounded")
			}
			if action == "expire" {
				time.Sleep(time.Until(applied.ExpiresAt) + 30*time.Millisecond)
			}
			removed, err := client.Control(ctx, auth, "remove")
			if err != nil || removed.Active || removed.ApplyCount != 1 {
				t.Fatal("poll exhaustion prevented authenticated cleanup", err)
			}
			if action == "expire" && removed.Reason != "expired" {
				t.Fatal("independent expiry was not observed")
			}
			duplicate, err := client.Control(ctx, auth, "remove")
			if err != nil || duplicate.Active || duplicate.ExpiresAt != applied.ExpiresAt {
				t.Fatal("duplicate Remove extended effect", err)
			}
		})
	}
}

func TestNonceReplayIsRejectedAcrossStatusAndMutationBudgets(t *testing.T) {
	server, _, auth, _ := setup(t, "healthy")
	command, err := NewCommand(auth, "status")
	if err != nil {
		t.Fatal(err)
	}
	if _, code := server.control(command); code != "" {
		t.Fatal(code)
	}
	if _, code := server.control(command); code != "CommandReplayDenied" {
		t.Fatal("status replay accepted", code)
	}
	command.Action, command.Signature = "remove", ""
	key, _ := hex.DecodeString(auth.CleanupKey)
	command.Signature = Sign("themis.kubernetes-command/v1alpha1", command, ed25519.PrivateKey(key))
	if _, code := server.control(command); code != "CommandReplayDenied" {
		t.Fatal("cross-action nonce reuse accepted", code)
	}
	remove, err := NewCommand(auth, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if _, code := server.control(remove); code != "" {
		t.Fatal(code)
	}
	if _, code := server.control(remove); code != "CommandReplayDenied" {
		t.Fatal("Remove replay accepted", code)
	}
	remove.Action, remove.Signature = "apply", ""
	key, _ = hex.DecodeString(auth.InvocationKey)
	remove.Signature = Sign("themis.kubernetes-command/v1alpha1", remove, ed25519.PrivateKey(key))
	if _, code := server.control(remove); code != "CommandReplayDenied" {
		t.Fatal("mutation nonce reused for Apply", code)
	}
}
