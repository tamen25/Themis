package dependencyhttp

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestReadOnlyAuthorityReceiptCommitsToOriginalGrantWithoutRenewal(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	client := HTTPClient()
	defer client.CloseIdleConnections()
	ctx := context.Background()
	read := func() AuthorityReceipt {
		t.Helper()
		nonce := ID()
		r, e := FetchAuthority(ctx, client, f.proxyURL+"/receipt/"+a.Grant.Invocation+"?nonce="+nonce)
		if e != nil || !r.Verified(f.plan.Binding.Target.Proxy.Process, nonce, a.Grant.Invocation) {
			t.Fatal("actual signed receipt unavailable", e)
		}
		return r
	}
	before := read()
	if before.Code != 404 || before.GrantDigest != "" || before.State.Applied {
		t.Fatal("unknown invocation fabricated authority")
	}
	first, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(f.proxy.journal.Name())
	if e != nil {
		t.Fatal(e)
	}
	for range 100 {
		r := read()
		if r.Code != 200 || r.GrantDigest != Hash(a.Grant) || r.PlanDigest != a.Grant.Digest || r.ApplyKeyID != PublicKeyID(a.Grant.ApplyKey) || r.CleanupKeyID != PublicKeyID(a.Grant.CleanupKey) || r.State.ApplyCount != 1 || r.State.DeadlineNS != first.DeadlineNS {
			t.Fatal("authority receipt lost binding or renewed fault")
		}
	}
	later, e := os.ReadFile(f.proxy.journal.Name())
	if e != nil || string(later) != string(original) {
		t.Fatal("read-only proof changed control journal")
	}
	time.Sleep(time.Until(f.proxy.boot.Add(time.Duration(first.DeadlineNS))) + 10*time.Millisecond)
	expired := read()
	if expired.State.Active || expired.State.Reason != "expired" || expired.State.DeadlineNS != first.DeadlineNS {
		t.Fatal("receipt polling changed independent expiry")
	}
}
