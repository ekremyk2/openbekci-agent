package platecam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

func TestConfidenceDedupeAndChannelMap(t *testing.T) {
	r, _ := NewMockReader("")
	d, err := New("cam", Config{ChannelMap: map[string]string{"entry": "in"}}, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan driver.Presentation, 8)
	go func() { _ = d.Subscribe(ctx, out) }()

	now := time.Now()
	r.Feed(Read{Plate: "34ABC123", Confidence: 0.93, Lane: "entry", At: now})
	r.Feed(Read{Plate: "34ABC123", Confidence: 0.95, Lane: "entry", At: now.Add(5 * time.Second)}) // deduped
	r.Feed(Read{Plate: "06XYZ999", Confidence: 0.5, Lane: "entry", At: now})                       // low confidence
	r.Feed(Read{Plate: "34ABC123", Confidence: 0.9, Lane: "entry", At: now.Add(31 * time.Second)}) // after window

	get := func() driver.Presentation {
		select {
		case p := <-out:
			return p
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
			return driver.Presentation{}
		}
	}
	if p := get(); p.Value != "34ABC123" || p.Channel != "in" || p.Instance != "cam" || p.Confidence != 0.93 {
		t.Fatalf("first %+v", p)
	}
	if p := get(); p.Value != "" || p.Detail["low_confidence"] != true {
		t.Fatalf("low confidence read must lose its value: %+v", p)
	}
	if p := get(); p.Value != "34ABC123" {
		t.Fatalf("after dedupe window %+v", p)
	}
	if err := d.Open(ctx, "in"); !errors.Is(err, driver.ErrNotSupported) {
		t.Fatalf("open: %v", err)
	}
}

func TestRegistrationRejectsUnknownAdapter(t *testing.T) {
	for _, cfg := range []map[string]any{{}, {"adapter": "hikvision"}, {"adapter": "mock", "bogus": 1}} {
		if _, err := Registration.New("cam", cfg, nil); err == nil {
			t.Errorf("%v accepted", cfg)
		}
	}
	if _, err := Registration.New("cam", map[string]any{"adapter": "mock"}, nil); err != nil {
		t.Fatal(err)
	}
}
