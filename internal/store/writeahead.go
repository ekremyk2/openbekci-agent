package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Write-ahead of decisions. The gate is opened only after the decision is
// durable: the event row and the spent use commit in one transaction first.

// ErrUsedUp means the credential's use budget was already spent: nothing was
// recorded and the gate must not open.
var ErrUsedUp = errors.New("store: credential use budget exhausted")

// HoldTimeout is how long a held event stays out of the upload queue before
// ReleaseStale lets it go (the pulse is bounded far below this).
const HoldTimeout = time.Minute

// RecordAllow is the write-ahead step of an open: in ONE transaction it
// inserts the held allow event and, when usesID is set, spends one use of the
// credential (refusing with ErrUsedUp when maxUses is already reached). The
// caller opens the gate only after this returned nil, then settles the event
// with ReleaseHeld or RevertHeld. A crash in between therefore leaves "use
// consumed, maybe not opened", never "opened, nothing recorded".
func (s *Store) RecordAllow(ctx context.Context, ev protocol.Event, now time.Time, usesID string, maxUses int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if usesID != "" {
		res, err := tx.ExecContext(ctx, `INSERT INTO uses(entry_id, count) VALUES(?, 1)
			ON CONFLICT(entry_id) DO UPDATE SET count = count + 1 WHERE count < ?`, usesID, maxUses)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUsedUp
		}
	}
	if err := s.insertEvent(ctx, tx, ev, now, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, _ = s.afterEnqueue(ctx) // limit enforcement failing must not fail a committed decision
	return nil
}

// RecordCommandAndEvent is RecordAllow for a guard's open_point: the
// provisional command result and the held manual_open event commit together.
func (s *Store) RecordCommandAndEvent(ctx context.Context, cmdID string, provisional json.RawMessage, ev protocol.Event, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.putCommand(ctx, tx, cmdID, provisional, now); err != nil {
		return err
	}
	if err := s.insertEvent(ctx, tx, ev, now, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, _ = s.afterEnqueue(ctx)
	return nil
}

// ReleaseHeld lets a held event upload (the gate opened).
func (s *Store) ReleaseHeld(ctx context.Context, eventID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE queue SET hold = 0 WHERE event_id = ?`, eventID)
	return err
}

// ReleaseStale releases events held for longer than HoldTimeout, e.g. because
// settling failed; the event then uploads as recorded.
func (s *Store) ReleaseStale(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE queue SET hold = 0 WHERE hold <> 0 AND enqueued_ms < ?`, now.Add(-HoldTimeout).UnixMilli())
	return err
}

// RevertHeld downgrades a held allow event to deny/reason after the driver
// failed, gives the spent use back (usesID may be empty) and releases it.
func (s *Store) RevertHeld(ctx context.Context, eventID, reason, usesID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT json FROM queue WHERE event_id = ?`, eventID).Scan(&raw); err != nil {
		return err
	}
	var ev protocol.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return err
	}
	ev.Decision, ev.Reason = protocol.DecisionDeny, reason
	out, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE queue SET decision = ?, json = ?, hold = 0 WHERE event_id = ?`, ev.Decision, string(out), eventID); err != nil {
		return err
	}
	if usesID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE uses SET count = count - 1 WHERE entry_id = ? AND count > 0`, usesID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DiscardHeld deletes a held event whose gate never opened (a failed guard
// open_point reports the failure in its ack instead).
func (s *Store) DiscardHeld(ctx context.Context, eventID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM queue WHERE event_id = ? AND hold <> 0`, eventID)
	return err
}
