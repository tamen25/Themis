package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// Offsets belong to one process session. Preparation and failure execution may
// be different processes; their monotonic clocks are never subtracted. UTC is
// descriptive metadata, not a trustworthy elapsed-time clock.
type PITRReceipt struct {
	Version, Plan, Session string
	ID                     int
	Payload, XID           string
	AckOffsetNS            int64
	AckAtUTC               time.Time
	Previous               string
	Signature              []byte
}

func pitrReceiptMessage(r PITRReceipt) []byte {
	r.Signature = nil
	return []byte(digest("themis.postgres.pitr.commit-receipt.v1", r))
}
func validPITRReceipt(r PITRReceipt, p PITRPlan) bool {
	return r.Version == PITRVersion && r.Plan == p.Digest && hexID.MatchString(r.Session) && r.ID >= 1 && r.ID <= 64 && r.Payload == payload(r.ID) && validPITRXID(r.XID) && r.AckOffsetNS > 0 && !r.AckAtUTC.IsZero() && ed25519.Verify(p.Inventory.LedgerKey, pitrReceiptMessage(r), r.Signature)
}
func verifyPITRReceipts(rs []PITRReceipt, p PITRPlan, expected int) error {
	if len(rs) != expected {
		return errors.New("PITR receipt coverage incomplete")
	}
	previous, session := "", ""
	var offset int64
	seen := map[string]bool{}
	xids := map[string]bool{}
	for n, r := range rs {
		if !validPITRReceipt(r, p) || r.ID != n+1 || r.Previous != previous || xids[r.XID] {
			return errors.New("PITR receipt signature, order or identity invalid")
		}
		if r.Session != session {
			if seen[r.Session] {
				return errors.New("receipt process session reused out of order")
			}
			seen[r.Session] = true
			session = r.Session
			offset = 0
		}
		if r.AckOffsetNS <= offset {
			return errors.New("nonmonotonic acknowledgement within process session")
		}
		offset = r.AckOffsetNS
		xids[r.XID] = true
		previous = digest("pitr-receipt", r)
	}
	return nil
}
func pitrCommit(ctx context.Context, d Docker, p PITRPlan, k ed25519.PrivateKey, j *journal, session, previous string, id int, opts pitrOptions) (PITRReceipt, error) {
	var r PITRReceipt
	uncertain := func(reason string) (PITRReceipt, error) {
		if e := j.append("COMMIT_OUTCOME_UNCERTAIN", map[string]any{"id": id, "reason": reason}); e != nil {
			return PITRReceipt{}, e
		}
		return PITRReceipt{}, errors.New(reason)
	}
	if e := j.append("COMMIT_INTENT", map[string]int{"id": id}); e != nil {
		return r, e
	}
	sql := fmt.Sprintf("BEGIN; INSERT INTO themis_app.transactions VALUES(%d,'%s'); UPDATE themis_app.accounts SET balance=balance-1 WHERE id=1; UPDATE themis_app.accounts SET balance=balance+1 WHERE id=2; SELECT json_build_object('id',%d,'payload','%s','xid',pg_current_xact_id()::text); COMMIT;", id, payload(id), id, payload(id))
	v, e := d.sql(ctx, p.Inventory.Source.ID, sql)
	if opts.acknowledgement != nil {
		v, e = opts.acknowledgement(id, v, e)
	}
	if e != nil {
		return uncertain("COMMIT acknowledgement ambiguous; no receipt published")
	}
	lines := strings.Split(v, "\n")
	if len(lines) != 6 || lines[0] != "BEGIN" || lines[1] != "INSERT 0 1" || lines[2] != "UPDATE 1" || lines[3] != "UPDATE 1" || lines[5] != "COMMIT" {
		return uncertain("COMMIT acknowledgement incomplete; no receipt published")
	}
	var ack struct {
		ID           int
		Payload, XID string
	}
	if json.Unmarshal([]byte(lines[4]), &ack) != nil || ack.ID != id || ack.Payload != payload(id) || ack.XID == "" {
		return uncertain("COMMIT identity uncertain")
	}
	r = PITRReceipt{Version: PITRVersion, Plan: p.Digest, Session: session, ID: id, Payload: ack.Payload, XID: ack.XID, AckOffsetNS: time.Since(j.start).Nanoseconds(), AckAtUTC: time.Now().UTC(), Previous: previous}
	r.Signature = ed25519.Sign(k, pitrReceiptMessage(r))
	if e = localstate.WriteNew(filepath.Join(p.Inventory.Directory, fmt.Sprintf("pitr-receipt-%02d.json", id)), r); e != nil {
		return uncertain("acknowledged COMMIT receipt publication failed")
	}
	return r, j.append("COMMIT_ACKNOWLEDGED", map[string]any{"id": id, "receiptHash": digest("pitr-receipt", r)})
}
