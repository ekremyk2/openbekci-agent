// Package store is the agent's local persistence: a SQLite database (WAL,
// pure Go) holding the allow-list, the event queue, the command replay cache
// and the configuration. Plate values are encrypted per row with AES-256-GCM
// under a key file in the state directory.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// File names inside the state directory.
const (
	DBFile = "store.db"
)

// Queue limits (design section 6.5).
const (
	MaxQueuedEvents = 100_000
	MaxQueuedBytes  = 50 << 20
	CommandTTL      = 24 * time.Hour
	CommandKeep     = 1000
)

// Meta keys.
const (
	MetaSnapshotVersion = "snapshot_version"
	MetaConfigVersion   = "config_version"
	MetaTimezone        = "timezone"
	MetaLastContact     = "last_contact_ms"
	MetaDropped         = "dropped_events"
	MetaDriversStatus   = "drivers_status"
	MetaQuarantined     = "quarantined_since_ms"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entry (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  vhash BLOB NOT NULL,
  value_enc BLOB NOT NULL,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entry_lookup ON entry(kind, vhash);
CREATE TABLE IF NOT EXISTS uses (entry_id TEXT PRIMARY KEY, count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS queue (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  decision TEXT NOT NULL,
  enqueued_ms INTEGER NOT NULL,
  json TEXT NOT NULL,
  plate_enc BLOB,
  hold INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS command_seen (id TEXT PRIMARY KEY, result TEXT NOT NULL, at_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshot_stage (
  version INTEGER NOT NULL,
  part INTEGER NOT NULL,
  parts INTEGER NOT NULL,
  blob BLOB NOT NULL,
  PRIMARY KEY (version, part)
);
`

// Store is the agent's local database.
type Store struct {
	db     *sql.DB
	seal   *sealer
	dir    string
	enqCnt int
}

// Open opens (creating if needed) the store in dir. dir is created with mode
// 0700 when missing. The database runs in WAL mode with synchronous=FULL: in
// WAL mode NORMAL does not fsync on commit, so a power loss (the realistic
// crash on an SD card) could lose the provisional command record, the use
// count or queued events and let a gate open twice. Writes are a few per
// minute, so FULL costs nothing that matters.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: state dir: %w", err)
	}
	sl, err := loadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.ToSlash(filepath.Join(dir, DBFile))
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises all access; the agent is not write-heavy.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	s := &Store{db: db, seal: sl, dir: dir}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

// migrate upgrades databases created by earlier builds and releases events
// that a crash left on hold (their gate may or may not have opened; the event
// must reach the server either way).
func (s *Store) migrate(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM pragma_table_info('queue')`)
	if err != nil {
		return err
	}
	hasHold := false
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return err
		}
		hasHold = hasHold || n == "hold"
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasHold {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE queue ADD COLUMN hold INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `UPDATE queue SET hold = 0 WHERE hold <> 0`)
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Wipe removes all rows (allow-list, queue, config, commands, meta). The
// caller removes the token and key files.
func (s *Store) Wipe(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range []string{"meta", "entry", "uses", "queue", "command_seen", "config", "snapshot_stage"} {
		stmt := "DELETE FROM " + t //nolint:gosec // t is one of the fixed table names above
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- meta ----

type execer interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func getMeta(ctx context.Context, q execer, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func setMeta(ctx context.Context, q execer, key, value string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// GetMeta returns a meta value.
func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	return getMeta(ctx, s.db, key)
}

// SetMeta stores a meta value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	return setMeta(ctx, s.db, key, value)
}

func (s *Store) metaInt(ctx context.Context, key string) (int64, error) {
	v, ok, err := getMeta(ctx, s.db, key)
	if err != nil || !ok {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// SnapshotVersion is the allow-list version the store holds (0 = none).
func (s *Store) SnapshotVersion(ctx context.Context) (int64, error) {
	return s.metaInt(ctx, MetaSnapshotVersion)
}

// ConfigVersion is the config_version of the stored configuration.
func (s *Store) ConfigVersion(ctx context.Context) (int64, error) {
	return s.metaInt(ctx, MetaConfigVersion)
}

// Timezone is the site timezone from the latest snapshot or update_config.
func (s *Store) Timezone(ctx context.Context) (string, error) {
	v, _, err := getMeta(ctx, s.db, MetaTimezone)
	return v, err
}

// DroppedEvents is the count of events dropped by queue overflow.
func (s *Store) DroppedEvents(ctx context.Context) (int64, error) {
	return s.metaInt(ctx, MetaDropped)
}

// SetLastContact records the time of the last authenticated server contact.
func (s *Store) SetLastContact(ctx context.Context, t time.Time) error {
	return s.SetMeta(ctx, MetaLastContact, strconv.FormatInt(t.UnixMilli(), 10))
}

// LastContact returns the last server contact; the zero time if never.
func (s *Store) LastContact(ctx context.Context) (time.Time, error) {
	ms, err := s.metaInt(ctx, MetaLastContact)
	if err != nil || ms == 0 {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

// ---- config ----

// SaveConfig replaces the stored configuration and records its version and
// timezone, in one transaction.
func (s *Store) SaveConfig(ctx context.Context, cfg protocol.Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO config(id, json) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json`, string(raw)); err != nil {
		return err
	}
	if err := setMeta(ctx, tx, MetaConfigVersion, strconv.FormatInt(cfg.ConfigVersion, 10)); err != nil {
		return err
	}
	if cfg.Site.Timezone != "" {
		if err := setMeta(ctx, tx, MetaTimezone, cfg.Site.Timezone); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadConfig returns the stored configuration, or nil if none.
func (s *Store) LoadConfig(ctx context.Context) (*protocol.Config, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT json FROM config WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg protocol.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ---- allow-list ----

func (s *Store) putEntry(ctx context.Context, tx execer, e protocol.Entry) error {
	enc, err := s.seal.seal([]byte(e.Value), "entry:"+e.ID)
	if err != nil {
		return err
	}
	vhash := s.seal.index(e.Kind, e.Value)
	e.Value = "" // the value lives only in value_enc
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO entry(id, kind, vhash, value_enc, json) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, vhash=excluded.vhash, value_enc=excluded.value_enc, json=excluded.json`,
		e.ID, e.Kind, vhash, enc, string(raw))
	return err
}

type rowScanner interface{ Scan(dest ...any) error }

func (s *Store) scanEntry(r rowScanner) (protocol.Entry, error) {
	var (
		id, raw string
		enc     []byte
	)
	if err := r.Scan(&id, &enc, &raw); err != nil {
		return protocol.Entry{}, err
	}
	var e protocol.Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return protocol.Entry{}, err
	}
	val, err := s.seal.open(enc, "entry:"+id)
	if err != nil {
		return protocol.Entry{}, err
	}
	e.Value = string(val)
	return e, nil
}

func (s *Store) queryEntries(ctx context.Context, q string, args ...any) ([]protocol.Entry, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []protocol.Entry
	for rows.Next() {
		e, err := s.scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Lookup returns the entries with exactly (kind, value), ordered by id.
func (s *Store) Lookup(ctx context.Context, kind, value string) ([]protocol.Entry, error) {
	return s.queryEntries(ctx, `SELECT id, value_enc, json FROM entry WHERE kind = ? AND vhash = ? ORDER BY id`,
		kind, s.seal.index(kind, value))
}

// ListByKind returns every entry of a kind, ordered by id (used by tolerant
// plate matching).
func (s *Store) ListByKind(ctx context.Context, kind string) ([]protocol.Entry, error) {
	return s.queryEntries(ctx, `SELECT id, value_enc, json FROM entry WHERE kind = ? ORDER BY id`, kind)
}

// EntryCount returns the number of allow-list entries.
func (s *Store) EntryCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM entry`).Scan(&n)
	return n, err
}

// RemoveEntry removes one entry (used by revoke_credential).
func (s *Store) RemoveEntry(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM entry WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM uses WHERE entry_id = ?`, id); err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, tx.Commit()
}

// Uses returns the local use count of an entry.
func (s *Store) Uses(ctx context.Context, id string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count FROM uses WHERE entry_id = ?`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// IncUses increments the local use count of an entry.
func (s *Store) IncUses(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO uses(entry_id, count) VALUES(?, 1) ON CONFLICT(entry_id) DO UPDATE SET count = count + 1`, id)
	return err
}

// DeltaStatus is the outcome of ApplyDelta.
type DeltaStatus int

// Delta outcomes.
const (
	DeltaApplied DeltaStatus = iota
	DeltaDuplicate
	DeltaGap
)

// ApplyDelta applies d only if d.FromVersion equals the stored version; the
// changes and the version bump commit in one transaction. The returned version
// is the version held afterwards.
func (s *Store) ApplyDelta(ctx context.Context, d protocol.Delta) (DeltaStatus, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	cur := int64(0)
	if v, ok, err := getMeta(ctx, tx, MetaSnapshotVersion); err != nil {
		return 0, 0, err
	} else if ok {
		if cur, err = strconv.ParseInt(v, 10, 64); err != nil {
			return 0, 0, err
		}
	}
	switch {
	case d.ToVersion <= cur:
		return DeltaDuplicate, cur, nil
	case d.FromVersion != cur:
		return DeltaGap, cur, nil
	}
	for _, c := range d.Changes {
		switch c.Op {
		case protocol.OpUpsert:
			if err := s.putEntry(ctx, tx, *c.Entry); err != nil {
				return 0, 0, err
			}
		case protocol.OpRemove:
			if _, err := tx.ExecContext(ctx, `DELETE FROM entry WHERE id = ?`, c.CredentialID); err != nil {
				return 0, 0, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM uses WHERE entry_id = ?`, c.CredentialID); err != nil {
				return 0, 0, err
			}
		default:
			return 0, 0, fmt.Errorf("store: unknown delta op %q", c.Op)
		}
	}
	if err := setMeta(ctx, tx, MetaSnapshotVersion, strconv.FormatInt(d.ToVersion, 10)); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return DeltaApplied, d.ToVersion, nil
}

// ApplySnapshotPart stages one snapshot part (persistently, so a restart in
// the middle keeps the parts already received) and, when all parts of the
// version have arrived, replaces the whole allow-list and the version in one
// transaction. It reports whether the snapshot was applied.
func (s *Store) ApplySnapshotPart(ctx context.Context, p protocol.Snapshot) (bool, error) {
	raw, err := json.Marshal(p.Entries)
	if err != nil {
		return false, err
	}
	blob, err := s.seal.seal(raw, fmt.Sprintf("stage:%d:%d", p.Version, p.Part))
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM snapshot_stage WHERE version <> ?`, p.Version); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO snapshot_stage(version, part, parts, blob) VALUES(?,?,?,?)
		ON CONFLICT(version, part) DO UPDATE SET parts = excluded.parts, blob = excluded.blob`, p.Version, p.Part, p.Parts, blob); err != nil {
		return false, err
	}
	var have int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM snapshot_stage WHERE version = ?`, p.Version).Scan(&have); err != nil {
		return false, err
	}
	if have < p.Parts {
		return false, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT part, blob FROM snapshot_stage WHERE version = ? ORDER BY part`, p.Version)
	if err != nil {
		return false, err
	}
	var all []protocol.Entry
	for rows.Next() {
		var part int
		var b []byte
		if err := rows.Scan(&part, &b); err != nil {
			_ = rows.Close()
			return false, err
		}
		plain, err := s.seal.open(b, fmt.Sprintf("stage:%d:%d", p.Version, part))
		if err != nil {
			_ = rows.Close()
			return false, err
		}
		var es []protocol.Entry
		if err := json.Unmarshal(plain, &es); err != nil {
			_ = rows.Close()
			return false, err
		}
		all = append(all, es...)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM entry`); err != nil {
		return false, err
	}
	// Keep use counters only for entries that survive the replacement.
	for _, e := range all {
		if err := s.putEntry(ctx, tx, e); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM uses WHERE entry_id NOT IN (SELECT id FROM entry)`); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM snapshot_stage`); err != nil {
		return false, err
	}
	if err := setMeta(ctx, tx, MetaSnapshotVersion, strconv.FormatInt(p.Version, 10)); err != nil {
		return false, err
	}
	if p.Site.Timezone != "" {
		if err := setMeta(ctx, tx, MetaTimezone, p.Site.Timezone); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// ---- event queue ----

// QueuedEvent is an event waiting for an ack.
type QueuedEvent struct {
	Seq   int64
	Event protocol.Event
	Size  int
}

// Enqueue appends an event; it is idempotent by event id. When the queue
// exceeds its limits the oldest deny events are dropped first, then the oldest
// allow events; the drop count is kept in meta (heartbeat.dropped_events).
func (s *Store) Enqueue(ctx context.Context, ev protocol.Event, now time.Time) (dropped int, err error) {
	if err := s.insertEvent(ctx, s.db, ev, now, false); err != nil {
		return 0, err
	}
	return s.afterEnqueue(ctx)
}

// insertEvent writes one queue row through q (the database or a transaction).
// A held row is not uploaded until released.
func (s *Store) insertEvent(ctx context.Context, q execer, ev protocol.Event, now time.Time, hold bool) error {
	plate := ev.ObservedPlate
	ev.ObservedPlate = ""
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	var enc []byte
	if plate != "" {
		if enc, err = s.seal.seal([]byte(plate), "queue:"+ev.ID); err != nil {
			return err
		}
	}
	h := 0
	if hold {
		h = 1
	}
	_, err = q.ExecContext(ctx, `INSERT OR IGNORE INTO queue(event_id, decision, enqueued_ms, json, plate_enc, hold) VALUES(?,?,?,?,?,?)`,
		ev.ID, ev.Decision, now.UnixMilli(), string(raw), enc, h)
	return err
}

// afterEnqueue enforces the queue limits cheaply (a full check every 256
// inserts or when the row count is over the limit).
func (s *Store) afterEnqueue(ctx context.Context) (dropped int, err error) {
	s.enqCnt++
	if s.enqCnt%256 != 0 {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM queue`).Scan(&n); err != nil {
			return 0, err
		}
		if n <= MaxQueuedEvents {
			return 0, nil
		}
	}
	return s.enforceLimits(ctx)
}

func (s *Store) enforceLimits(ctx context.Context) (int, error) {
	var n int
	var size sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*), sum(length(json) + coalesce(length(plate_enc),0)) FROM queue`).Scan(&n, &size); err != nil {
		return 0, err
	}
	over := n - MaxQueuedEvents
	if size.Valid && size.Int64 > MaxQueuedBytes && n > 0 {
		avg := size.Int64 / int64(n)
		if byBytes := int((size.Int64 - MaxQueuedBytes) / max(avg, 1)); byBytes > over {
			over = byBytes + 1
		}
	}
	if over <= 0 {
		return 0, nil
	}
	dropped := 0
	for _, where := range []string{`decision = 'deny'`, `1 = 1`} {
		res, err := s.db.ExecContext(ctx, `DELETE FROM queue WHERE seq IN (SELECT seq FROM queue WHERE `+where+` ORDER BY seq LIMIT ?)`, over-dropped) //nolint:gosec // where is one of two constant predicates
		if err != nil {
			return dropped, err
		}
		k, _ := res.RowsAffected()
		dropped += int(k)
		if dropped >= over {
			break
		}
	}
	if dropped > 0 {
		cur, _ := s.DroppedEvents(ctx)
		if err := s.SetMeta(ctx, MetaDropped, strconv.FormatInt(cur+int64(dropped), 10)); err != nil {
			return dropped, err
		}
	}
	return dropped, nil
}

// QueueDepth returns the number of queued events.
func (s *Store) QueueDepth(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM queue`).Scan(&n)
	return n, err
}

// NextBatch returns up to limit queued events with seq greater than after, in
// queue order, stopping before the batch would exceed maxBytes of JSON.
func (s *Store) NextBatch(ctx context.Context, after int64, limit, maxBytes int) ([]QueuedEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, event_id, json, plate_enc FROM queue WHERE seq > ? AND hold = 0 ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []QueuedEvent
	total := 0
	for rows.Next() {
		var (
			seq     int64
			id, raw string
			enc     []byte
		)
		if err := rows.Scan(&seq, &id, &raw, &enc); err != nil {
			return nil, err
		}
		if len(out) > 0 && total+len(raw) > maxBytes {
			break
		}
		var ev protocol.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		if enc != nil {
			plate, err := s.seal.open(enc, "queue:"+id)
			if err != nil {
				return nil, err
			}
			ev.ObservedPlate = string(plate)
		}
		total += len(raw)
		out = append(out, QueuedEvent{Seq: seq, Event: ev, Size: len(raw)})
	}
	return out, rows.Err()
}

// DeleteEvents removes acknowledged (or permanently rejected) events.
func (s *Store) DeleteEvents(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `DELETE FROM queue WHERE event_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- command replay cache ----

// RecordCommand stores the result of a command so a re-delivery is answered
// without executing it again. Entries older than 24 h and beyond the newest
// 1 000 are pruned.
func (s *Store) RecordCommand(ctx context.Context, id string, result json.RawMessage, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.putCommand(ctx, tx, id, result, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) putCommand(ctx context.Context, q execer, id string, result json.RawMessage, now time.Time) error {
	if _, err := q.ExecContext(ctx, `INSERT OR REPLACE INTO command_seen(id, result, at_ms) VALUES(?,?,?)`, id, string(result), now.UnixMilli()); err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM command_seen WHERE at_ms < ?`, now.Add(-CommandTTL).UnixMilli()); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `DELETE FROM command_seen WHERE id NOT IN (SELECT id FROM command_seen ORDER BY at_ms DESC, rowid DESC LIMIT ?)`, CommandKeep)
	return err
}

// CommandResult returns the stored result of a command seen within 24 h.
func (s *Store) CommandResult(ctx context.Context, id string, now time.Time) (json.RawMessage, bool, error) {
	var res string
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT result, at_ms FROM command_seen WHERE id = ?`, id).Scan(&res, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if time.UnixMilli(at).Before(now.Add(-CommandTTL)) {
		return nil, false, nil
	}
	return json.RawMessage(res), true, nil
}
