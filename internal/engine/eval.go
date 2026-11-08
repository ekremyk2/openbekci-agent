package engine

import (
	"fmt"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Decision reasons produced by the evaluator and the engine.
const (
	ReasonMatch         = "match"
	ReasonUnknown       = "unknown"
	ReasonOutsideWindow = "outside_window"
	ReasonWrongPoint    = "wrong_point"
	ReasonUsedUp        = "used_up"
	ReasonAgentStopped  = "agent_stopped"
	ReasonDriverError   = "driver_error"
	// ReasonStoreError: the allow-list could not be read (corrupt row, DB
	// error). The gate stays closed and the denial is still recorded.
	ReasonStoreError = "store_error"
)

// Outcome is the result of evaluating candidate entries for a presentation.
type Outcome struct {
	Allowed bool
	Reason  string
	// Entry is the matching entry when Allowed, otherwise the entry that
	// produced the denial reason (nil for "unknown").
	Entry *protocol.Entry
}

// Evaluate applies design section 3.4 steps 2-5 to the candidate entries (all
// entries whose kind and value equal the presented credential) at instant now
// in the site timezone loc. uses returns the local use count of an entry.
func Evaluate(candidates []protocol.Entry, pointID string, now time.Time, loc *time.Location, uses func(id string) int) Outcome {
	if len(candidates) == 0 {
		return Outcome{Reason: ReasonUnknown}
	}
	var denial Outcome
	rank := func(reason string) int {
		switch reason {
		case ReasonOutsideWindow:
			return 3
		case ReasonWrongPoint:
			return 2
		case ReasonUsedUp:
			return 1
		}
		return 0
	}
	for i := range candidates {
		e := &candidates[i]
		reason := ReasonMatch
		switch {
		case !hasPoint(e, pointID):
			reason = ReasonWrongPoint
		case !inWindow(e, now, loc):
			reason = ReasonOutsideWindow
		case e.MaxUses != nil && uses != nil && uses(e.ID) >= *e.MaxUses:
			reason = ReasonUsedUp
		}
		if reason == ReasonMatch {
			return Outcome{Allowed: true, Reason: ReasonMatch, Entry: e}
		}
		if rank(reason) > rank(denial.Reason) {
			denial = Outcome{Reason: reason, Entry: e}
		}
	}
	return denial
}

func hasPoint(e *protocol.Entry, pointID string) bool {
	for _, p := range e.Points {
		if p == pointID {
			return true
		}
	}
	return false
}

// inWindow reports whether now lies inside the validity bounds and, when set,
// the recurring rule of e.
func inWindow(e *protocol.Entry, now time.Time, loc *time.Location) bool {
	if now.Before(e.ValidFrom.Time) {
		return false
	}
	if e.ValidTo != nil && now.After(e.ValidTo.Time) {
		return false
	}
	if e.Recurring == nil {
		return true
	}
	return InRecurring(*e.Recurring, now, loc)
}

// InRecurring evaluates a weekly wall-clock window in the site timezone.
// Boundaries are inclusive at the minute. start > end is an overnight window
// that belongs to the day it starts on. Wall-clock semantics make DST changes
// follow the clock on the wall.
func InRecurring(r protocol.Recurring, now time.Time, loc *time.Location) bool {
	local := now.In(loc)
	start, ok1 := parseHHMM(r.Start)
	end, ok2 := parseHHMM(r.End)
	if !ok1 || !ok2 {
		return false
	}
	minute := local.Hour()*60 + local.Minute()
	today := isoWeekday(local)
	yesterday := (today+5)%7 + 1
	in := func(day int) bool {
		for _, d := range r.Days {
			if d == day {
				return true
			}
		}
		return false
	}
	if start <= end {
		return in(today) && minute >= start && minute <= end
	}
	return (in(today) && minute >= start) || (in(yesterday) && minute <= end)
}

func isoWeekday(t time.Time) int {
	if d := int(t.Weekday()); d != 0 {
		return d
	}
	return 7
}

func parseHHMM(s string) (int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%02d:%02d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}
