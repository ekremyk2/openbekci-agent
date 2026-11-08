package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The fixtures are generated from the agent's own Go structs, which makes a
// round trip self-referential. These tests validate every fixture against the
// JSON Schemas of design 07 Appendix B (testdata/protocol/v1/schema), which
// are independent of the Go code.

const schemaBase = "https://schemas.openbekci.org/agent-protocol/v1/"

// schemaCannotExpress lists the invalid fixtures whose defect is a rule JSON
// Schema cannot state (relations between two properties, byte sizes); the
// agent's own validation rejects them instead (TestInvalidFixturesRejected).
var schemaCannotExpress = map[string]string{
	"invalid-delta-order.json":   "to_version > from_version compares two properties",
	"invalid-snapshot-part.json": "part <= parts compares two properties",
}

func loadSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "protocol", "v1", "schema")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no schemas in %s: %v", dir, err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := c.AddResource(schemaBase+filepath.Base(f), doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, name := range []string{"envelope", "hello-agent", "hello-server", "snapshot", "delta", "event", "ack", "command", "heartbeat"} {
		s, err := c.Compile(schemaBase + name + ".schema.json")
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		out[name] = s
	}
	return out
}

// validateFrame checks an envelope and its payload; it returns the first error.
func validateFrame(t *testing.T, schemas map[string]*jsonschema.Schema, raw []byte) error {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	if err := schemas["envelope"].Validate(doc); err != nil {
		return err
	}
	var env struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	name := env.Type
	if name == "hello" {
		var from struct {
			From string `json:"from"`
		}
		_ = json.Unmarshal(env.Payload, &from)
		name = "hello-" + from.From
	}
	s, ok := schemas[name]
	if !ok {
		t.Fatalf("no schema for message type %q", env.Type)
	}
	payload, err := jsonschema.UnmarshalJSON(strings.NewReader(string(env.Payload)))
	if err != nil {
		return err
	}
	return s.Validate(payload)
}

func TestValidFixturesMatchTheSchemas(t *testing.T) {
	schemas := loadSchemas(t)
	for _, f := range fixtureFiles(t, "valid") {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateFrame(t, schemas, raw); err != nil {
			t.Errorf("%s does not match the schema: %v", filepath.Base(f), err)
		}
	}
}

func TestInvalidFixturesAreRejectedBySchemaToo(t *testing.T) {
	schemas := loadSchemas(t)
	for _, f := range fixtureFiles(t, "invalid") {
		name := filepath.Base(f)
		if _, skip := schemaCannotExpress[name]; skip {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateFrame(t, schemas, raw); err == nil {
			t.Errorf("%s is invalid for the agent but passes the schema: the fixture or the schema is wrong", name)
		}
	}
	for name := range schemaCannotExpress {
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "protocol", "v1", name)); err != nil {
			t.Errorf("schemaCannotExpress names a fixture that does not exist: %s", name)
		}
	}
}

// Every limit named in section 4.5 has an invalid fixture.
func TestLimitFixturesExist(t *testing.T) {
	for _, name := range []string{
		"invalid-command-update-config.json", "invalid-command-update-config-grace.json", "invalid-command-revoke-credential.json",
		"invalid-event-batch-101.json", "invalid-snapshot-entries-2001.json", "invalid-delta-changes-501.json", "invalid-delta-remove-with-entry.json",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "protocol", "v1", name)); err != nil {
			t.Errorf("missing fixture %s", name)
		}
	}
}
