package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type evalCase struct {
	Name         string                       `json:"name"`
	TZ           string                       `json:"tz"`
	Now          string                       `json:"now"`
	Point        string                       `json:"point"`
	Uses         map[string]int               `json:"uses"`
	Presentation struct{ Kind, Value string } `json:"presentation"`
	AllowList    []protocol.Entry             `json:"allow_list"`
	Expect       struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		EntryID  string `json:"entry_id"`
	} `json:"expect"`
}

// TestEvaluationFixtures runs every testdata/evaluation/*.json file (the shape
// of the shared fixtures of design section 10).
func TestEvaluationFixtures(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "evaluation", "*.json"))
	if len(files) == 0 {
		t.Fatal("no evaluation fixtures")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cases []evalCase
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, c := range cases {
			t.Run(c.Name, func(t *testing.T) {
				value, ok := canonical(c.Presentation.Kind, c.Presentation.Value)
				var cands []protocol.Entry
				if ok {
					for _, e := range c.AllowList {
						if e.Kind == c.Presentation.Kind && e.Value == value {
							cands = append(cands, e)
						}
					}
				}
				out := Evaluate(cands, c.Point, ts(t, c.Now), mustLoc(t, c.TZ), func(id string) int { return c.Uses[id] })
				dec := "deny"
				if out.Allowed {
					dec = "allow"
				}
				if dec != c.Expect.Decision || out.Reason != c.Expect.Reason {
					t.Fatalf("got %s/%s, want %s/%s", dec, out.Reason, c.Expect.Decision, c.Expect.Reason)
				}
				if c.Expect.EntryID != "" && (out.Entry == nil || out.Entry.ID != c.Expect.EntryID) {
					t.Fatalf("entry %+v, want %s", out.Entry, c.Expect.EntryID)
				}
			})
		}
	}
}

func TestPlateNormalizationFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plate-normalization.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Input      string  `json:"input"`
		Normalized *string `json:"normalized"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		got := NormalizePlate(c.Input)
		want := ""
		if c.Normalized != nil {
			want = *c.Normalized
		}
		if got != want {
			t.Errorf("NormalizePlate(%q) = %q, want %q", c.Input, got, want)
		}
	}
}

func TestInRecurring(t *testing.T) {
	ist := mustLoc(t, "Europe/Istanbul")
	berlin := mustLoc(t, "Europe/Berlin")
	weekdays := protocol.Recurring{Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "17:00"}
	night := protocol.Recurring{Days: []int{5}, Start: "22:00", End: "06:00"} // Friday evening into Saturday morning
	sun := func(s, e string) protocol.Recurring { return protocol.Recurring{Days: []int{7}, Start: s, End: e} }

	tests := []struct {
		name string
		r    protocol.Recurring
		loc  *time.Location
		now  string
		want bool
	}{
		{"mon 09:00 local", weekdays, ist, "2026-11-09T06:00:00Z", true},
		{"mon 08:59 local", weekdays, ist, "2026-11-09T05:59:59Z", false},
		{"mon 17:00:59 local (inclusive minute)", weekdays, ist, "2026-11-09T14:00:59Z", true},
		{"mon 17:01 local", weekdays, ist, "2026-11-09T14:01:00Z", false},
		{"sat noon", weekdays, ist, "2026-11-14T09:00:00Z", false},
		{"fri 21:59 local", night, ist, "2026-11-13T18:59:00Z", false},
		{"fri 22:00 local", night, ist, "2026-11-13T19:00:00Z", true},
		{"sat 06:00 local (inclusive end)", night, ist, "2026-11-14T03:00:00Z", true},
		{"sat 06:01 local", night, ist, "2026-11-14T03:01:00Z", false},
		{"sat 23:00 local (Saturday is not a start day)", night, ist, "2026-11-14T20:00:00Z", false},
		{"fri 02:00 local (Thursday is not a start day)", night, ist, "2026-11-12T23:00:00Z", false},
		{"sun-to-mon: mon 01:00 local", protocol.Recurring{Days: []int{7}, Start: "22:00", End: "06:00"}, ist, "2026-11-08T22:00:00Z", true},
		// Berlin DST: spring forward 2026-03-29 01:00Z, fall back 2026-10-25 01:00Z.
		{"berlin spring: 03:15 local inside 02:30-03:30", sun("02:30", "03:30"), berlin, "2026-03-29T01:15:00Z", true},
		{"berlin spring: 03:45 local outside", sun("02:30", "03:30"), berlin, "2026-03-29T01:45:00Z", false},
		{"berlin spring: 01:59 local before", sun("02:30", "03:30"), berlin, "2026-03-29T00:59:00Z", false},
		{"berlin fall: first 02:30", sun("02:00", "02:59"), berlin, "2026-10-25T00:30:00Z", true},
		{"berlin fall: repeated 02:30", sun("02:00", "02:59"), berlin, "2026-10-25T01:30:00Z", true},
		{"berlin fall: 03:00 local", sun("02:00", "02:59"), berlin, "2026-10-25T02:00:00Z", false},
		// Istanbul: permanent +03 since 2016, so 2026-03-29 has no transition ...
		{"istanbul 2026-03-29 09:30 local", sun("09:00", "10:00"), ist, "2026-03-29T06:30:00Z", true},
		{"istanbul 2026-03-29 08:30 local", sun("09:00", "10:00"), ist, "2026-03-29T05:30:00Z", false},
		// ... but the 2015 transition (EET to EEST, 03:00 -> 04:00 local at 01:00Z) is in tzdata.
		{"istanbul 2015 spring: 04:15 local inside 03:30-04:30", sun("03:30", "04:30"), ist, "2015-03-29T01:15:00Z", true},
		{"istanbul 2015 spring: 02:59 local before", sun("03:30", "04:30"), ist, "2015-03-29T00:59:00Z", false},
		{"istanbul 2015 spring: 04:45 local after", sun("03:30", "04:30"), ist, "2015-03-29T01:45:00Z", false},
		// Istanbul local midnight is 21:00Z the day before.
		{"istanbul midnight crossing: mon 00:30 local is sun 21:30Z", protocol.Recurring{Days: []int{1}, Start: "00:00", End: "01:00"}, ist, "2026-11-08T21:30:00Z", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := InRecurring(tc.r, ts(t, tc.now), tc.loc); got != tc.want {
				t.Errorf("InRecurring = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluateDetails(t *testing.T) {
	p1, p2 := "p1", "p2"
	base := func(id string) protocol.Entry {
		return protocol.Entry{ID: id, Kind: "plate", Value: "X", Points: []string{p1}, ValidFrom: protocol.At(ts(t, "2026-01-01T00:00:00Z"))}
	}
	now := ts(t, "2026-11-09T10:00:00Z")
	expired := base("c2")
	expired.ValidTo = &protocol.Time{Time: ts(t, "2026-02-01T00:00:00Z")}
	wrong := base("c1")
	wrong.Points = []string{p2}
	limited := base("c3")
	one := 1
	limited.MaxUses = &one
	uses := func(id string) int {
		if id == "c3" {
			return 1
		}
		return 0
	}

	if out := Evaluate([]protocol.Entry{wrong, expired, limited}, p1, now, time.UTC, uses); out.Allowed || out.Reason != ReasonOutsideWindow || out.Entry.ID != "c2" {
		t.Errorf("priority: %+v", out)
	}
	if out := Evaluate([]protocol.Entry{wrong, limited}, p1, now, time.UTC, uses); out.Reason != ReasonWrongPoint {
		t.Errorf("wrong_point over used_up: %+v", out)
	}
	if out := Evaluate([]protocol.Entry{limited}, p1, now, time.UTC, uses); out.Reason != ReasonUsedUp {
		t.Errorf("used_up: %+v", out)
	}
	if out := Evaluate([]protocol.Entry{expired, base("c4")}, p1, now, time.UTC, uses); !out.Allowed || out.Entry.ID != "c4" {
		t.Errorf("first match wins: %+v", out)
	}
	if out := Evaluate(nil, p1, now, time.UTC, uses); out.Reason != ReasonUnknown {
		t.Errorf("unknown: %+v", out)
	}
}

func TestNormalizeAndQR(t *testing.T) {
	if v, ok := QRValue("obk1.hello"); !ok || v != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("QRValue = %q %v", v, ok)
	}
	for _, bad := range []string{"", "hello", "obk1.", "obk2.x"} {
		if _, ok := QRValue(bad); ok {
			t.Errorf("QRValue(%q) accepted", bad)
		}
	}
	if !ocrNeighbour("34ABC123", "34A8C123") || ocrNeighbour("34ABC123", "34ABC124") || ocrNeighbour("34ABC123", "34ABC123") || ocrNeighbour("34ABC123", "34ABC12") {
		t.Error("ocrNeighbour")
	}
}
