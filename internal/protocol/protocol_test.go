package protocol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixtureFiles(t *testing.T, prefix string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "protocol", "v1", prefix+"-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no %s fixtures: %v", prefix, err)
	}
	return files
}

// stripNulls removes null-valued object members so that optional-null and
// omitted fields compare equal.
func stripNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if e == nil || e == "" {
				continue
			}
			out[k] = stripNulls(e)
		}
		return out
	case []any:
		for i := range x {
			x[i] = stripNulls(x[i])
		}
	}
	return v
}

func normalize(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return stripNulls(v)
}

func TestValidFixturesRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range fixtureFiles(t, "valid") {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			env, err := ParseEnvelope(raw)
			if err != nil {
				t.Fatalf("envelope: %v", err)
			}
			p, err := env.Decode()
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			seen[env.Type] = true
			payload, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			out := Envelope{V: env.V, Type: env.Type, ID: env.ID, TS: env.TS, Payload: payload}
			wire, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalize(t, raw), normalize(t, wire)) {
				t.Errorf("round trip mismatch\n in: %s\nout: %s", raw, wire)
			}
			// The re-encoded frame must itself parse and decode.
			again, err := ParseEnvelope(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := again.Decode(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, typ := range []string{TypeHello, TypeSnapshot, TypeDelta, TypeEvent, TypeAck, TypeCommand, TypeHeartbeat} {
		if !seen[typ] {
			t.Errorf("no valid fixture for message type %q", typ)
		}
	}
}

func TestInvalidFixturesRejected(t *testing.T) {
	for _, f := range fixtureFiles(t, "invalid") {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			env, err := ParseEnvelope(raw)
			if err != nil {
				return
			}
			if _, err := env.Decode(); err == nil {
				t.Errorf("fixture was accepted")
			}
		})
	}
}

func TestUnknownTypeAndForwardCompat(t *testing.T) {
	e := Envelope{V: 1, Type: "future", ID: NewID(), TS: Now(), Payload: json.RawMessage(`{}`)}
	if _, err := e.Decode(); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
	// Unknown payload fields are tolerated.
	e = Envelope{V: 1, Type: TypeAck, ID: NewID(), TS: Now(), Payload: json.RawMessage(`{"ref":"` + idMsg + `","status":"ok","new_field":true}`)}
	if _, err := e.Decode(); err != nil {
		t.Fatal(err)
	}
}

func TestNewEnvelope(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	e, err := New(TypeHeartbeat, Heartbeat{Drivers: []DriverState{}}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"ts":"2026-11-07T10:00:00.000Z"`) {
		t.Errorf("ts not millisecond precision: %s", b)
	}
	if !IsUUIDv7(e.ID) {
		t.Errorf("id %q is not a UUIDv7", e.ID)
	}
	if _, err := ParseEnvelope(b); err != nil {
		t.Fatal(err)
	}
}
