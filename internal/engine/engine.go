package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Plate matching modes.
const (
	PlateExact    = "exact"
	PlateTolerant = "tolerant"
)

// DefaultGraceHours is the default offline grace period.
const DefaultGraceHours = 72

// DefaultDedupe is the presentation dedupe window per (point, value).
const DefaultDedupe = 10 * time.Second

// Store is the part of the local store the engine needs.
type Store interface {
	Lookup(ctx context.Context, kind, value string) ([]protocol.Entry, error)
	ListByKind(ctx context.Context, kind string) ([]protocol.Entry, error)
	Uses(ctx context.Context, id string) (int, error)
	IncUses(ctx context.Context, id string) error
	Enqueue(ctx context.Context, ev protocol.Event, now time.Time) (int, error)
}

// Settings are the evaluation settings that come from the server.
type Settings struct {
	Location   *time.Location
	GraceHours int
	PlateMatch string
}

// Presentation is a credential shown to a point.
type Presentation struct {
	PointID    string
	Kind       string // plate | visitor_qr | tag | pin
	Value      string // raw reader value
	Confidence float64
	At         time.Time // zero = now
	RawRef     string
	Detail     map[string]any
}

// Options configure an Engine.
type Options struct {
	Store Store
	// Clock is the agent's own clock; defaults to time.Now.
	Clock func() time.Time
	// LastContact returns the last authenticated server contact (zero = never).
	LastContact func() time.Time
	// Open executes an allow decision on the point's hardware.
	Open func(ctx context.Context, pointID string) error
	// OnEvent is called after an event was queued.
	OnEvent func()
	Dedupe  time.Duration
	Log     *slog.Logger
}

// Result describes what Handle did with a presentation.
type Result struct {
	// Suppressed is true when the presentation was a duplicate inside the
	// dedupe window: nothing was decided, opened or logged.
	Suppressed bool
	// Event is the queued event (zero when Suppressed).
	Event protocol.Event
	// Opened is true when the point was opened.
	Opened bool
}

// Engine decides presentations.
type Engine struct {
	o  Options
	mu sync.Mutex // guards settings and the dedupe table
	s  Settings
	dd map[string]time.Time
}

// New creates an engine with UTC, 72 h grace and exact plate matching.
func New(o Options) *Engine {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Dedupe == 0 {
		o.Dedupe = DefaultDedupe
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Engine{o: o, s: Settings{Location: time.UTC, GraceHours: DefaultGraceHours, PlateMatch: PlateExact}, dd: map[string]time.Time{}}
}

// SetSettings replaces the evaluation settings. Zero values keep defaults.
func (e *Engine) SetSettings(s Settings) {
	if s.Location == nil {
		s.Location = time.UTC
	}
	if s.GraceHours <= 0 {
		s.GraceHours = DefaultGraceHours
	}
	if s.PlateMatch == "" {
		s.PlateMatch = PlateExact
	}
	e.mu.Lock()
	e.s = s
	e.mu.Unlock()
}

// Settings returns the current settings.
func (e *Engine) Settings() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.s
}

// Stopped reports whether the offline grace period has elapsed (design 6.3).
func (e *Engine) Stopped() bool {
	if e.o.LastContact == nil {
		return false
	}
	last := e.o.LastContact()
	if last.IsZero() {
		return false
	}
	return e.o.Clock().Sub(last) > time.Duration(e.Settings().GraceHours)*time.Hour
}

// canonical converts the raw reader value to the stored credential value.
func canonical(kind, raw string) (string, bool) {
	switch kind {
	case "plate":
		v := NormalizePlate(raw)
		return v, v != ""
	case "visitor_qr":
		return QRValue(raw)
	case "tag", "pin":
		// The per-site salt is unknown to the agent, so the reader (or the
		// future driver) must present the hex SHA-256 already.
		v := strings.ToLower(strings.TrimSpace(raw))
		return v, v != ""
	}
	return "", false
}

func (e *Engine) dedupe(key string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.dd[key]; ok && now.Sub(t) < e.o.Dedupe && now.Sub(t) >= 0 {
		return true
	}
	if len(e.dd) > 1024 {
		for k, t := range e.dd {
			if now.Sub(t) >= e.o.Dedupe {
				delete(e.dd, k)
			}
		}
	}
	e.dd[key] = now
	return false
}

// Handle decides one presentation, opens the point on allow, and queues the
// resulting event. An error means the event could not be persisted.
func (e *Engine) Handle(ctx context.Context, p Presentation) (Result, error) {
	now := e.o.Clock()
	st := e.Settings()
	value, valid := canonical(p.Kind, p.Value)

	if valid && e.dedupe(p.PointID+"|"+p.Kind+"|"+value, now) {
		return Result{Suppressed: true}, nil
	}

	ev := protocol.Event{
		ID:            protocol.NewID(),
		PointID:       p.PointID,
		Decision:      protocol.DecisionDeny,
		PresentedKind: p.Kind,
		RawRef:        p.RawRef,
		OccurredAt:    protocol.At(now),
	}
	if !p.At.IsZero() {
		ev.OccurredAt = protocol.At(p.At)
	}
	if p.Kind == "plate" {
		ev.ObservedPlate = value // QR / tag values are never stored
	}
	tolerant := false
	var matched *protocol.Entry
	reason := ReasonUnknown

	switch {
	case e.Stopped():
		reason = ReasonAgentStopped
	case !valid:
		reason = ReasonUnknown
	default:
		cands, err := e.o.Store.Lookup(ctx, p.Kind, value)
		if err != nil {
			return Result{}, err
		}
		if len(cands) == 0 && p.Kind == "plate" && st.PlateMatch == PlateTolerant {
			if c, err := e.tolerantCandidates(ctx, value); err != nil {
				return Result{}, err
			} else if len(c) > 0 {
				cands, tolerant = c, true
			}
		}
		var usesErr error
		out := Evaluate(cands, p.PointID, now, st.Location, func(id string) int {
			n, err := e.o.Store.Uses(ctx, id)
			if err != nil {
				usesErr = err
			}
			return n
		})
		if usesErr != nil {
			return Result{}, usesErr
		}
		reason, matched = out.Reason, out.Entry
		if out.Allowed {
			ev.Decision = protocol.DecisionAllow
		}
	}
	if matched != nil {
		ev.CredentialID = matched.ID
	}

	opened := false
	if ev.Decision == protocol.DecisionAllow {
		if err := e.open(ctx, p.PointID); err != nil {
			e.o.Log.Warn("open failed", "point_id", p.PointID, "error", err)
			ev.Decision, reason = protocol.DecisionDeny, ReasonDriverError
		} else {
			opened = true
			if matched.MaxUses != nil {
				if err := e.o.Store.IncUses(ctx, matched.ID); err != nil {
					e.o.Log.Error("count use failed", "error", err)
				}
			}
		}
	}
	ev.Reason = reason
	ev.Detail = detail(p, tolerant)

	if _, err := e.o.Store.Enqueue(ctx, ev, now); err != nil {
		return Result{}, err
	}
	e.o.Log.Info("decision", "point_id", p.PointID, "decision", ev.Decision, "reason", ev.Reason, "credential_id", ev.CredentialID, "event_id", ev.ID)
	if e.o.OnEvent != nil {
		e.o.OnEvent()
	}
	return Result{Event: ev, Opened: opened}, nil
}

func (e *Engine) open(ctx context.Context, pointID string) error {
	if e.o.Open == nil {
		return nil
	}
	return e.o.Open(ctx, pointID)
}

// tolerantCandidate returns the single plate entry that is an OCR-confusable
// neighbour of value, or nil when none or more than one qualifies.
func (e *Engine) tolerantCandidates(ctx context.Context, value string) ([]protocol.Entry, error) {
	all, err := e.o.Store.ListByKind(ctx, "plate")
	if err != nil {
		return nil, err
	}
	var found []protocol.Entry
	plate := ""
	for _, c := range all {
		if !ocrNeighbour(c.Value, value) {
			continue
		}
		if plate != "" && c.Value != plate {
			return nil, nil // ambiguous: more than one plate qualifies
		}
		plate = c.Value
		found = append(found, c)
	}
	return found, nil
}

func detail(p Presentation, tolerant bool) json.RawMessage {
	d := map[string]any{}
	for k, v := range p.Detail {
		d[k] = v
	}
	if p.Confidence > 0 && p.Confidence < 1 {
		d["confidence"] = p.Confidence
	}
	if tolerant {
		d["tolerant"] = true
	}
	if len(d) == 0 {
		return nil
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > protocol.MaxEventDetailBytes {
		return nil
	}
	return raw
}
