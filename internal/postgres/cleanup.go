package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type CleanupReceipt struct {
	Version  string    `json:"version"`
	Run      string    `json:"run"`
	At       time.Time `json:"at"`
	Complete bool      `json:"complete"`
	Actions  []string  `json:"actions"`
	Reason   string    `json:"reason,omitempty"`
}

func (d Docker) exists(ctx context.Context, kind, id string) (bool, error) {
	if e := d.verifyEngine(ctx); e != nil {
		return false, e
	}
	var args []string
	switch kind {
	case "container":
		args = []string{"container", "ls", "--all", "--quiet", "--no-trunc"}
	case "volume":
		args = []string{"volume", "ls", "--format", "{{.Name}}"}
	case "network":
		args = []string{"network", "ls", "--no-trunc", "--format", "{{.ID}}"}
	default:
		return false, errors.New("unsupported cleanup resource")
	}
	b, e := d.output(ctx, nil, args...)
	if e != nil {
		return false, e
	}
	if e = d.verifyEngine(ctx); e != nil {
		return false, e
	}
	for _, v := range strings.Fields(string(b)) {
		if v == id {
			return true, nil
		}
	}
	return false, nil
}

func cleanup(ctx context.Context, i Inventory, deny bool) CleanupReceipt {
	r := CleanupReceipt{Version: Version, Run: i.Run, At: time.Now().UTC(), Actions: []string{}}
	if deny {
		r.Reason = "immediate cleanup deliberately withheld by approved synthetic scenario"
		return r
	}
	if !time.Now().Before(i.CleanupBefore) {
		r.Reason = "cleanup authority expired; no deletion attempted"
		return r
	}
	d := Docker{i.Endpoint, i.Engine}
	// Cleanup has its own durable intent because a poisoned or absent execution
	// journal cannot be its authority or prerequisite. Never replace prior intent.
	if e := localstate.WriteNew(filepath.Join(i.Directory, "cleanup-intent-"+localstate.RandomID()+".json"), struct{ Run, Engine, Source, Restore, Network string }{i.Run, i.Engine, i.Source.ID, i.Restore.ID, i.Network.ID}); e != nil {
		r.Reason = "cleanup intent publication failed; no deletion attempted"
		return r
	}
	deadline := time.Now().Add(45 * time.Second)
	if i.CleanupBefore.Before(deadline) {
		deadline = i.CleanupBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	fail := func(e error) CleanupReceipt { r.Reason = e.Error(); return r }
	for _, resource := range []Resource{i.Source, i.Restore} {
		if resource.Role == "" && resource.ID == "" {
			continue
		} // No persisted role intent: no create was attempted.
		if resource.ID == "" {
			return fail(errors.New("unacknowledged container creation; identity unknown"))
		}
		exists, e := d.exists(ctx, "container", resource.ID)
		if e != nil {
			return fail(e)
		}
		if exists {
			if e = d.container(ctx, i, resource, false); e != nil {
				return fail(e)
			}
			if e = d.verifyEngine(ctx); e != nil {
				return fail(e)
			}
			if _, e = d.output(ctx, nil, "container", "rm", "--force", resource.ID); e != nil {
				return fail(e)
			}
			r.Actions = append(r.Actions, "removed-container:"+resource.ID)
		}
		if exists, e = d.exists(ctx, "container", resource.ID); e != nil || exists {
			return fail(errors.New("container absence unverified"))
		}
		if exists, e = d.exists(ctx, "volume", resource.Volume.Name); e != nil {
			return fail(e)
		}
		if exists {
			if e = d.volume(ctx, i, resource); e != nil {
				return fail(e)
			}
			if e = d.verifyEngine(ctx); e != nil {
				return fail(e)
			}
			if _, e = d.output(ctx, nil, "volume", "rm", resource.Volume.Name); e != nil {
				return fail(e)
			}
			r.Actions = append(r.Actions, "removed-volume:"+resource.Volume.Name)
		}
		if exists, e = d.exists(ctx, "volume", resource.Volume.Name); e != nil || exists {
			return fail(errors.New("volume absence unverified"))
		}
	}
	exists, e := d.exists(ctx, "network", i.Network.ID)
	if e != nil {
		return fail(e)
	}
	if exists {
		if e = d.network(ctx, i); e != nil {
			return fail(e)
		}
		if e = d.verifyEngine(ctx); e != nil {
			return fail(e)
		}
		if _, e = d.output(ctx, nil, "network", "rm", i.Network.ID); e != nil {
			return fail(e)
		}
		r.Actions = append(r.Actions, "removed-network:"+i.Network.ID)
	}
	if exists, e = d.exists(ctx, "network", i.Network.ID); e != nil || exists {
		return fail(errors.New("network absence unverified"))
	}
	r.Complete = true
	return r
}

// Reconcile only reads the original protected control inventory. It never trusts
// imported reports, labels alone, PID liveness or journal reconstruction.
func Reconcile(ctx context.Context, dir string) (CleanupReceipt, error) {
	i, e := loadInventory(dir)
	if e != nil {
		// Recover acknowledged setup resources without guessing a lost create ID.
		abs, err := filepath.Abs(dir)
		if err != nil {
			return CleanupReceipt{}, err
		}
		if err = localstate.Read(filepath.Join(abs, "setup-intent.json"), &i); err != nil {
			return CleanupReceipt{}, err
		}
		a, err := localstate.CurrentActor()
		if err != nil || i.Actor != a || i.Directory != abs || i.Version != Version || !hexID.MatchString(i.Run) || ValidateEndpoint(i.Endpoint) != nil {
			return CleanupReceipt{}, errors.New("invalid original setup authority")
		}
		if err = localstate.Read(filepath.Join(abs, "owned-network.json"), &i.Network); err != nil {
			return CleanupReceipt{}, errors.New("network identity unknown; manual review required")
		}
		for _, p := range []struct {
			role string
			r    *Resource
		}{{"source", &i.Source}, {"restore", &i.Restore}} {
			if err = localstate.Read(filepath.Join(abs, "owned-"+p.role+".json"), p.r); err != nil {
				var intent map[string]string
				if e := localstate.Read(filepath.Join(abs, p.role+"-intent.json"), &intent); !errors.Is(e, os.ErrNotExist) {
					return CleanupReceipt{}, errors.New("setup incomplete; resource identity unknown; manual review required")
				}
			}
		}
		// A damaged final inventory cannot be replaced by a partial setup record.
		if _, err = os.Lstat(filepath.Join(abs, "inventory.json")); !errors.Is(err, os.ErrNotExist) {
			return CleanupReceipt{}, e
		}
	}
	l, e := acquire(i.Directory)
	if e != nil {
		return CleanupReceipt{}, e
	}
	defer l.Close()
	r := cleanup(ctx, i, false)
	e = localstate.WriteNew(filepath.Join(i.Directory, "cleanup-"+localstate.RandomID()+".json"), r)
	return r, e
}
