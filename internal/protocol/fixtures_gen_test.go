package protocol

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateFixtures = flag.Bool("update-fixtures", false, "regenerate testdata/protocol/v1")

const (
	idAgent   = "0192f1a0-0000-7000-8000-0000000000a1"
	idPoint   = "0192f1a0-0000-7000-8000-0000000000b1"
	idPoint2  = "0192f1a0-0000-7000-8000-0000000000b2"
	idCred    = "0192f1a0-0000-7000-8000-0000000000c1"
	idCred2   = "0192f1a0-0000-7000-8000-0000000000c2"
	idEvent   = "0192f1a0-0000-7000-8000-0000000000e1"
	idEvent2  = "0192f1a0-0000-7000-8000-0000000000e2"
	idMsg     = "0192f1a0-0000-7000-8000-0000000000f1"
	idCommand = "0192f1a0-0000-7000-8000-0000000000d1"
	idSite    = "0192f1a0-0000-7000-8000-0000000000a5"
)

// env wraps a payload literal in an envelope literal.
func env(typ, payload string) string {
	return `{"v":1,"type":"` + typ + `","id":"` + idMsg + `","ts":"2026-11-07T10:00:00.123Z","payload":` + payload + `}`
}

// fixtureSet is the source of the shared conformance fixtures. It follows the
// appendix A examples of docs/plans/07-access-control.md, with concrete ids.
func fixtureSet() map[string]string {
	entry := `{"id":"` + idCred + `","kind":"plate","value":"34ABC123","points":["` + idPoint + `"],` +
		`"valid_from":"2026-11-07T10:00:00Z","valid_to":"2026-11-07T11:30:00Z","recurring":null,"max_uses":1}`
	recurring := `{"id":"` + idCred2 + `","kind":"visitor_qr","value":"` + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" + `","points":["` + idPoint + `","` + idPoint2 + `"],` +
		`"valid_from":"2026-11-07T08:00:00Z","valid_to":null,"recurring":{"days":[1,3,5],"start":"22:00","end":"06:00"},"max_uses":null}`
	ev := `{"id":"` + idEvent + `","point_id":"` + idPoint + `","decision":"allow","reason":"match","credential_id":"` + idCred + `",` +
		`"presented_kind":"plate","observed_plate":"34ABC123","occurred_at":"2026-11-07T10:01:12.481Z",` +
		`"raw_ref":"snap/20261107-100112.jpg","detail":{"confidence":0.93,"lane":"in"}}`
	drivers := `[{"instance":"gate-relay","state":"ok"}]`
	f := map[string]string{
		"valid-hello-agent": env("hello", `{"from":"agent","agent_id":"`+idAgent+`","agent_version":"0.3.0","platform":"linux/arm64",`+
			`"protocol_versions":[1],"snapshot_version":1041,"config_version":7,"drivers":`+drivers+`,"queue_depth":0,"clock_offset_ms":-312}`),
		"valid-hello-server": env("hello", `{"from":"server","protocol_version":1,"server_time":"2026-11-07T10:00:00.500Z","heartbeat_seconds":30,`+
			`"config_version":7,"rotate_by":"2027-05-06T00:00:00Z","rotate_now":false,`+
			`"site":{"id":"`+idSite+`","timezone":"Europe/Istanbul"},"snapshot_version":1042}`),
		"valid-snapshot":  env("snapshot", `{"version":1042,"part":1,"parts":2,"site":{"timezone":"Europe/Istanbul"},"entries":[`+entry+`,`+recurring+`]}`),
		"valid-delta":     env("delta", `{"from_version":1041,"to_version":1042,"changes":[{"op":"upsert","entry":`+entry+`},{"op":"remove","credential_id":"`+idCred2+`"}]}`),
		"valid-event":     env("event", `{"clock_offset_ms":-312,"events":[`+ev+`]}`),
		"valid-ack-event": env("ack", `{"ref":"`+idMsg+`","status":"ok","detail":{"accepted":["`+idEvent+`"],"duplicates":[],"rejected":[{"id":"`+idEvent2+`","code":"unknown_point"}]}}`),
		"valid-ack-gap":   env("ack", `{"ref":"`+idMsg+`","status":"gap","detail":{"have_version":1040}}`),
		"valid-ack-done":  env("ack", `{"ref":"`+idMsg+`","status":"done"}`),
		"valid-command-open-point": env("command", `{"command":"open_point","point_id":"`+idPoint+`","visitor_entry_id":"`+idCred2+`",`+
			`"actor":{"user_id":"`+idAgent+`","display":"Guard Ali"},"issued_at":"2026-11-07T10:02:15Z","expires_at":"2026-11-07T10:02:30Z"}`),
		"valid-command-revoke-credential": env("command", `{"command":"revoke_credential","credential_id":"`+idCred+`"}`),
		"valid-command-request-snapshot":  env("command", `{"command":"request_snapshot"}`),
		"valid-command-update-config": env("command", `{"command":"update_config","config_version":8,"site":{"timezone":"Europe/Istanbul"},`+
			`"points":[{"id":"`+idPoint+`","name":"Main gate - in","kind":"vehicle_gate","direction":"in","driver_ref":{"instance":"gate-cam","channel":"in"},"enabled":true}],`+
			`"settings":{"offline_grace_hours":72,"plate_match":"exact","heartbeat_seconds":30,"maintenance_hour":3}}`),
		"valid-command-revoked": env("command", `{"command":"revoked"}`),
		"valid-heartbeat": env("heartbeat", `{"snapshot_version":1042,"queue_depth":3,"dropped_events":0,"uptime_s":86400,"clock_suspect":false,`+
			`"drivers":[{"instance":"gate-cam","state":"ok","detail":""}]}`),

		"invalid-envelope-version": `{"v":2,"type":"heartbeat","id":"` + idMsg + `","ts":"2026-11-07T10:00:00.123Z","payload":{}}`,
		"invalid-envelope-id":      `{"v":1,"type":"heartbeat","id":"not-a-uuid","ts":"2026-11-07T10:00:00.123Z","payload":{}}`,
		"invalid-envelope-extra":   `{"v":1,"type":"heartbeat","id":"` + idMsg + `","ts":"2026-11-07T10:00:00.123Z","payload":{},"extra":1}`,
		"invalid-hello-agent-no-drivers": env("hello", `{"from":"agent","agent_id":"`+idAgent+`","agent_version":"0.3.0",`+
			`"protocol_versions":[1],"snapshot_version":1,"config_version":1,"queue_depth":0}`),
		"invalid-hello-server-heartbeat": env("hello", `{"from":"server","protocol_version":1,"server_time":"2026-11-07T10:00:00.500Z","heartbeat_seconds":5,`+
			`"config_version":7,"site":{"id":"`+idSite+`","timezone":"Europe/Istanbul"},"snapshot_version":1042}`),
		"invalid-snapshot-part":                env("snapshot", `{"version":1,"part":3,"parts":2,"site":{"timezone":"Europe/Istanbul"},"entries":[]}`),
		"invalid-delta-order":                  env("delta", `{"from_version":5,"to_version":5,"changes":[]}`),
		"invalid-delta-op":                     env("delta", `{"from_version":1,"to_version":2,"changes":[{"op":"replace","credential_id":"`+idCred+`"}]}`),
		"invalid-event-empty":                  env("event", `{"events":[]}`),
		"invalid-event-uuid-v4":                env("event", `{"events":[{"id":"0192f1a0-0000-4000-8000-0000000000e1","point_id":"`+idPoint+`","decision":"allow","reason":"match","occurred_at":"2026-11-07T10:01:12.481Z"}]}`),
		"invalid-event-decision":               env("event", `{"events":[{"id":"`+idEvent+`","point_id":"`+idPoint+`","decision":"maybe","reason":"match","occurred_at":"2026-11-07T10:01:12.481Z"}]}`),
		"invalid-ack-status":                   env("ack", `{"ref":"`+idMsg+`","status":"great"}`),
		"invalid-command-open-point-no-expiry": env("command", `{"command":"open_point","point_id":"`+idPoint+`","issued_at":"2026-11-07T10:02:15Z"}`),
		"invalid-command-unknown":              env("command", `{"command":"self_destruct"}`),
		"invalid-entry-day": env("delta", `{"from_version":1,"to_version":2,"changes":[{"op":"upsert","entry":{"id":"`+idCred+`","kind":"plate","value":"34ABC123","points":["`+idPoint+`"],`+
			`"valid_from":"2026-11-07T10:00:00Z","valid_to":null,"recurring":{"days":[0],"start":"09:00","end":"17:00"},"max_uses":null}}]}`),
		"invalid-entry-hhmm": env("delta", `{"from_version":1,"to_version":2,"changes":[{"op":"upsert","entry":{"id":"`+idCred+`","kind":"plate","value":"34ABC123","points":["`+idPoint+`"],`+
			`"valid_from":"2026-11-07T10:00:00Z","valid_to":null,"recurring":{"days":[1],"start":"9:00","end":"17:00"},"max_uses":null}}]}`),
		"invalid-heartbeat-no-drivers": env("heartbeat", `{"snapshot_version":1,"queue_depth":0}`),

		// update_config: required parts missing; grace period outside 1..336.
		"invalid-command-update-config": env("command", `{"command":"update_config","config_version":8,"site":{"timezone":"Europe/Istanbul"}}`),
		"invalid-command-update-config-grace": env("command", `{"command":"update_config","config_version":8,"site":{"timezone":"Europe/Istanbul"},"points":[],`+
			`"settings":{"offline_grace_hours":337,"plate_match":"exact","heartbeat_seconds":30,"maintenance_hour":3}}`),
		"invalid-command-revoke-credential": env("command", `{"command":"revoke_credential","credential_id":"not-a-uuid"}`),
		"invalid-delta-remove-with-entry":   env("delta", `{"from_version":1,"to_version":2,"changes":[{"op":"remove","credential_id":"`+idCred+`","entry":`+entry+`}]}`),
		// Over the limits of section 4.5: 101 events, 2 001 entries, 501 changes.
		"invalid-event-batch-101":       env("event", `{"events":[`+repeatJoin(minimalEvent(), 101)+`]}`),
		"invalid-snapshot-entries-2001": env("snapshot", `{"version":1,"part":1,"parts":1,"site":{"timezone":"Europe/Istanbul"},"entries":[`+repeatJoin(minimalEntry(), 2001)+`]}`),
		"invalid-delta-changes-501":     env("delta", `{"from_version":1,"to_version":2,"changes":[`+repeatJoin(`{"op":"remove","credential_id":"`+idCred+`"}`, 501)+`]}`),
	}
	return f
}

func repeatJoin(item string, n int) string {
	return strings.TrimSuffix(strings.Repeat(item+",", n), ",")
}

func minimalEvent() string {
	return `{"id":"` + idEvent + `","point_id":"` + idPoint + `","decision":"deny","reason":"unknown","occurred_at":"2026-11-07T10:01:12.481Z"}`
}

func minimalEntry() string {
	return `{"id":"` + idCred + `","kind":"plate","value":"A","points":["` + idPoint + `"],"valid_from":"2026-11-07T10:00:00Z"}`
}

// TestGenerateFixtures rewrites testdata/protocol/v1 when run with
// -update-fixtures; otherwise it only checks the files are up to date.
func TestGenerateFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "protocol", "v1")
	for name, src := range fixtureSet() {
		var buf bytes.Buffer
		if len(src) > 20_000 {
			// the limit fixtures are big: keep them compact
			buf.WriteString(src)
		} else if err := json.Indent(&buf, []byte(src), "", "  "); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		buf.WriteByte('\n')
		path := filepath.Join(dir, name+".json")
		if *updateFixtures {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/protocol -update-fixtures)", name, err)
		}
		if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), buf.Bytes()) {
			t.Errorf("%s is out of date (run go test ./internal/protocol -update-fixtures)", name)
		}
	}
}
