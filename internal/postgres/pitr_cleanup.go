package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type pitrCleanupGrant struct {
	Version, Inventory string
	NotAfter           time.Time
	Signature          []byte
}

func pitrCleanupMessage(g pitrCleanupGrant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.pitr.cleanup-capability.v1", g))
}

func pitrCleanup(ctx context.Context, i PITRInventory, withhold bool) CleanupReceipt {
	r := CleanupReceipt{Version: PITRVersion, Run: i.Run, At: time.Now().UTC(), Actions: []string{}}
	fail := func(reason string) CleanupReceipt { r.Reason = reason; return r }
	if withhold {
		return fail("immediate cleanup deliberately withheld by approved synthetic scenario")
	}
	// Reload protected identity and independent capability; the plan, report and
	// execution journal are never fallback authority for resource deletion.
	original, e := loadPITRInventory(i.Directory)
	if e != nil || digest("inventory", original) != digest("inventory", i) {
		return fail("protected cleanup inventory unavailable or changed")
	}
	var g pitrCleanupGrant
	if e = localstate.Read(filepath.Join(i.Directory, "pitr-cleanup-capability.json"), &g); e != nil {
		return fail("independent cleanup capability unavailable")
	}
	if g.Version != PITRVersion || g.Inventory != digest("themis.postgres.pitr.inventory.v1", i) || g.NotAfter != i.CleanupBefore || !time.Now().Before(g.NotAfter) || !ed25519.Verify(i.CleanupKey, pitrCleanupMessage(g), g.Signature) {
		return fail("cleanup capability invalid or expired; no deletion attempted")
	}
	deadline := time.Now().Add(45 * time.Second)
	if g.NotAfter.Before(deadline) {
		deadline = g.NotAfter
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := Docker{i.Endpoint, i.Engine}
	// Check every extant original object before the first removal. In particular,
	// never remove an unrelated source and then discover a bad restore identity.
	for _, v := range i.resources() {
		present, e := d.exists(ctx, "container", v.ID)
		if e != nil {
			return fail("Docker availability unknown")
		}
		if present {
			if _, e = d.pitrContainer(ctx, i, v, false, false); e != nil {
				return fail("container cleanup identity refused")
			}
		}
		present, e = d.exists(ctx, "volume", v.Volume.Name)
		if e != nil {
			return fail("volume availability unknown")
		}
		if present {
			if e = d.pitrVolume(ctx, i, v); e != nil {
				return fail("volume cleanup identity refused")
			}
		}
	}
	present, e := d.exists(ctx, "network", i.Network.ID)
	if e != nil {
		return fail("network availability unknown")
	}
	if present {
		if e = d.pitrNetwork(ctx, i); e != nil {
			return fail("network cleanup identity refused")
		}
	}
	if e = localstate.WriteNew(filepath.Join(i.Directory, "pitr-cleanup-intent-"+localstate.RandomID()+".json"), struct{ Run, Inventory string }{i.Run, g.Inventory}); e != nil {
		return fail("durable cleanup intent unavailable")
	}
	remove := func(kind, id string, validate func() error) error {
		present, e := d.exists(ctx, kind, id)
		if e != nil {
			return e
		}
		if present {
			if e = validate(); e != nil {
				return e
			}
			if !time.Now().Before(g.NotAfter) {
				return errors.New("cleanup expired")
			}
			if e = d.verifyEngine(ctx); e != nil {
				return e
			}
			args := []string{kind, "rm"}
			if kind == "container" {
				args = append(args, "--force")
			}
			args = append(args, id)
			if _, e = d.output(ctx, nil, args...); e != nil {
				return e
			}
			r.Actions = append(r.Actions, "removed-"+kind+":"+id)
		}
		present, e = d.exists(ctx, kind, id)
		if e != nil || present {
			return errors.New("absence not independently verified")
		}
		return nil
	}
	for _, v := range i.resources() {
		if e = remove("container", v.ID, func() error { _, e := d.pitrContainer(ctx, i, v, false, false); return e }); e != nil {
			return fail("container removal incomplete or ambiguous")
		}
		if e = remove("volume", v.Volume.Name, func() error { return d.pitrVolume(ctx, i, v) }); e != nil {
			return fail("volume removal incomplete or ambiguous")
		}
	}
	if e = remove("network", i.Network.ID, func() error { return d.pitrNetwork(ctx, i) }); e != nil {
		return fail("network removal incomplete or ambiguous")
	}
	r.Complete = true
	r.Actions = append(r.Actions, "private-host-capsule-retention:operator-managed")
	return r
}
func ReconcilePITR(ctx context.Context, dir string) (CleanupReceipt, error) {
	i, e := loadPITRInventory(dir)
	if e != nil {
		return CleanupReceipt{}, e
	}
	l, e := acquire(i.Directory)
	if e != nil {
		return CleanupReceipt{}, e
	}
	defer l.Close()
	r := pitrCleanup(ctx, i, false)
	e = localstate.WriteNew(filepath.Join(i.Directory, "pitr-cleanup-"+localstate.RandomID()+".json"), r)
	return r, e
}
