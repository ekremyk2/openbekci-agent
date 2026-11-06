// Package protocol holds the wire types of the OpenBekci agent protocol v1
// (docs/plans/07-access-control.md section 4 and appendix B): the envelope,
// every message payload, JSON (un)marshalling and validation.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Version is the protocol version this package speaks.
const Version = 1

// Subprotocol is the WebSocket subprotocol name.
const Subprotocol = "openbekci.agent.v1"

// Message types.
const (
	TypeHello     = "hello"
	TypeSnapshot  = "snapshot"
	TypeDelta     = "delta"
	TypeEvent     = "event"
	TypeAck       = "ack"
	TypeCommand   = "command"
	TypeHeartbeat = "heartbeat"
)

// Command names.
const (
	CmdOpenPoint        = "open_point"
	CmdRevokeCredential = "revoke_credential" //nolint:gosec // a command name, not a credential
	CmdRequestSnapshot  = "request_snapshot"
	CmdUpdateConfig     = "update_config"
	CmdRevoked          = "revoked"
)

// Ack statuses.
const (
	AckOK           = "ok"
	AckDuplicate    = "duplicate"
	AckGap          = "gap"
	AckDone         = "done"
	AckFailed       = "failed"
	AckExpired      = "expired"
	AckRefused      = "refused"
	AckUnknownPoint = "unknown_point"
	AckUnsupported  = "unsupported"
	AckError        = "error"
)

// WebSocket close codes.
const (
	CloseRevoked         = 4401
	CloseReplaced        = 4409
	CloseNoCommonVersion = 4426
	CloseRateLimited     = 4429
)

// Limits from the schemas.
const (
	MaxFrameBytes       = 1 << 20
	MaxSnapshotEntries  = 2000
	MaxDeltaChanges     = 500
	MaxEventBatch       = 100
	MaxEventRawRef      = 256
	MaxEventDetailBytes = 2048
	MaxEntryValueLen    = 128
	MaxPollWaitSeconds  = 30
	MinHeartbeatSeconds = 10
	MaxHeartbeatSeconds = 120
)

var (
	// ErrUnknownType is returned by Decode for a message type this package
	// does not know; receivers answer with an "unsupported" ack.
	ErrUnknownType = errors.New("protocol: unknown message type")

	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hhmmRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// Time is a timestamp that marshals as RFC 3339 UTC (with a fractional part
// only when the value has one) and accepts any RFC 3339 input.
type Time struct{ time.Time }

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	u := t.UTC()
	layout := time.RFC3339Nano
	switch ns := u.Nanosecond(); {
	case ns == 0:
		layout = time.RFC3339
	case ns%1_000_000 == 0:
		layout = "2006-01-02T15:04:05.000Z07:00"
	}
	return json.Marshal(u.Format(layout))
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("invalid timestamp %q: %w", s, err)
	}
	t.Time = p.UTC()
	return nil
}

// Now returns the current time as a Time truncated to milliseconds.
func Now() Time { return At(time.Now()) }

// At converts t to a protocol Time (UTC, millisecond precision).
func At(t time.Time) Time { return Time{t.UTC().Truncate(time.Millisecond)} }

// NewID returns a fresh UUIDv7 string.
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if the system random source fails.
		panic(err)
	}
	return id.String()
}

// IsUUID reports whether s matches the protocol's lowercase UUID pattern.
func IsUUID(s string) bool { return uuidRE.MatchString(s) }

// IsUUIDv7 reports whether s is a lowercase UUID with version nibble 7.
func IsUUIDv7(s string) bool { return IsUUID(s) && s[14] == '7' }

// Envelope is the frame wrapper; Payload stays raw until Decode.
type Envelope struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      Time            `json:"ts"`
	Payload json.RawMessage `json:"payload"`
}

// MarshalJSON writes ts with millisecond precision as the spec requires.
func (e Envelope) MarshalJSON() ([]byte, error) {
	type wire struct {
		V       int             `json:"v"`
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		TS      string          `json:"ts"`
		Payload json.RawMessage `json:"payload"`
	}
	return json.Marshal(wire{e.V, e.Type, e.ID, e.TS.UTC().Format("2006-01-02T15:04:05.000Z07:00"), e.Payload})
}

// New builds an envelope for payload with a fresh UUIDv7 and the given clock.
func New(typ string, payload any, now time.Time) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{V: Version, Type: typ, ID: NewID(), TS: At(now), Payload: raw}, nil
}

// ParseEnvelope strictly parses and validates one frame.
func ParseEnvelope(data []byte) (Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("protocol: envelope: %w", err)
	}
	if err := env.Validate(); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// Validate checks the envelope against envelope.schema.json.
func (e Envelope) Validate() error {
	switch {
	case e.V != Version:
		return fmt.Errorf("protocol: unsupported version %d", e.V)
	case e.Type == "":
		return errors.New("protocol: envelope: empty type")
	case !IsUUID(e.ID):
		return fmt.Errorf("protocol: envelope: invalid id %q", e.ID)
	case e.TS.IsZero():
		return errors.New("protocol: envelope: missing ts")
	}
	p := bytes.TrimSpace(e.Payload)
	if len(p) == 0 || p[0] != '{' {
		return errors.New("protocol: envelope: payload must be an object")
	}
	return nil
}

// DriverState is a driver instance's health as reported in hello/heartbeat.
type DriverState struct {
	Instance string `json:"instance"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
}

func (d DriverState) validate() error {
	if d.Instance == "" {
		return errors.New("driver state: empty instance")
	}
	switch d.State {
	case "ok", "degraded", "down", "missing":
		return nil
	}
	return fmt.Errorf("driver state: invalid state %q", d.State)
}

// DriverRef binds a point to a driver instance (and lane/relay channel).
type DriverRef struct {
	Instance string `json:"instance"`
	Channel  string `json:"channel,omitempty"`
}

// Recurring is a weekly wall-clock window in the site timezone.
type Recurring struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// Entry is one allow-list entry (section 3.1).
type Entry struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Value     string     `json:"value"`
	Points    []string   `json:"points"`
	ValidFrom Time       `json:"valid_from"`
	ValidTo   *Time      `json:"valid_to"`
	Recurring *Recurring `json:"recurring"`
	MaxUses   *int       `json:"max_uses"`
}

// Validate checks the entry against the $defs/entry schema.
func (e Entry) Validate() error {
	if !IsUUID(e.ID) {
		return fmt.Errorf("entry: invalid id %q", e.ID)
	}
	if e.Kind == "" {
		return errors.New("entry: empty kind")
	}
	if n := len(e.Value); n < 1 || n > MaxEntryValueLen {
		return fmt.Errorf("entry: value length %d out of range", n)
	}
	if len(e.Points) == 0 {
		return errors.New("entry: no points")
	}
	for _, p := range e.Points {
		if !IsUUID(p) {
			return fmt.Errorf("entry: invalid point id %q", p)
		}
	}
	if e.ValidFrom.IsZero() {
		return errors.New("entry: missing valid_from")
	}
	if e.MaxUses != nil && *e.MaxUses < 1 {
		return errors.New("entry: max_uses < 1")
	}
	if r := e.Recurring; r != nil {
		if len(r.Days) == 0 {
			return errors.New("entry: recurring without days")
		}
		seen := map[int]bool{}
		for _, d := range r.Days {
			if d < 1 || d > 7 || seen[d] {
				return fmt.Errorf("entry: invalid recurring day %d", d)
			}
			seen[d] = true
		}
		if !hhmmRE.MatchString(r.Start) || !hhmmRE.MatchString(r.End) {
			return errors.New("entry: recurring start/end must be HH:MM")
		}
	}
	return nil
}

// Site is the site block of server hello, snapshot and update_config.
type Site struct {
	ID       string `json:"id,omitempty"`
	Timezone string `json:"timezone"`
}

// AgentHello is the agent's first message (from = "agent").
type AgentHello struct {
	From             string        `json:"from"`
	AgentID          string        `json:"agent_id"`
	AgentVersion     string        `json:"agent_version"`
	Platform         string        `json:"platform,omitempty"`
	ProtocolVersions []int         `json:"protocol_versions"`
	SnapshotVersion  int64         `json:"snapshot_version"`
	ConfigVersion    int64         `json:"config_version"`
	Drivers          []DriverState `json:"drivers"`
	QueueDepth       int64         `json:"queue_depth"`
	ClockOffsetMS    *int64        `json:"clock_offset_ms,omitempty"`
}

// Validate implements Payload.
func (h AgentHello) Validate() error {
	if h.From != "agent" {
		return errors.New("hello: from must be \"agent\"")
	}
	if h.AgentID == "" || h.AgentVersion == "" {
		return errors.New("hello: agent_id and agent_version required")
	}
	if len(h.ProtocolVersions) == 0 {
		return errors.New("hello: protocol_versions required")
	}
	if h.SnapshotVersion < 0 || h.ConfigVersion < 0 || h.QueueDepth < 0 {
		return errors.New("hello: negative counter")
	}
	if h.Drivers == nil {
		return errors.New("hello: drivers required")
	}
	for _, d := range h.Drivers {
		if err := d.validate(); err != nil {
			return fmt.Errorf("hello: %w", err)
		}
	}
	return nil
}

// ServerHello is the server's reply (from = "server").
type ServerHello struct {
	From             string `json:"from"`
	ProtocolVersion  int    `json:"protocol_version"`
	ServerTime       Time   `json:"server_time"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
	ConfigVersion    int64  `json:"config_version"`
	RotateBy         *Time  `json:"rotate_by,omitempty"`
	RotateNow        bool   `json:"rotate_now"`
	Site             Site   `json:"site"`
	SnapshotVersion  int64  `json:"snapshot_version"`
}

// Validate implements Payload.
func (h ServerHello) Validate() error {
	switch {
	case h.From != "server":
		return errors.New("hello: from must be \"server\"")
	case h.ProtocolVersion < 1:
		return errors.New("hello: protocol_version required")
	case h.ServerTime.IsZero():
		return errors.New("hello: server_time required")
	case h.HeartbeatSeconds < MinHeartbeatSeconds || h.HeartbeatSeconds > MaxHeartbeatSeconds:
		return fmt.Errorf("hello: heartbeat_seconds %d out of range", h.HeartbeatSeconds)
	case h.ConfigVersion < 0 || h.SnapshotVersion < 0:
		return errors.New("hello: negative version")
	case h.Site.ID == "" || h.Site.Timezone == "":
		return errors.New("hello: site.id and site.timezone required")
	}
	return nil
}

// Snapshot is one part of a full allow-list at Version.
type Snapshot struct {
	Version int64   `json:"version"`
	Part    int     `json:"part"`
	Parts   int     `json:"parts"`
	Site    Site    `json:"site"`
	Entries []Entry `json:"entries"`
}

// Validate implements Payload.
func (s Snapshot) Validate() error {
	switch {
	case s.Version < 0:
		return errors.New("snapshot: negative version")
	case s.Part < 1 || s.Parts < 1 || s.Part > s.Parts:
		return fmt.Errorf("snapshot: invalid part %d/%d", s.Part, s.Parts)
	case s.Site.Timezone == "":
		return errors.New("snapshot: site.timezone required")
	case s.Entries == nil:
		return errors.New("snapshot: entries required")
	case len(s.Entries) > MaxSnapshotEntries:
		return errors.New("snapshot: too many entries in part")
	}
	for _, e := range s.Entries {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
	}
	return nil
}

// Delta ops.
const (
	OpUpsert = "upsert"
	OpRemove = "remove"
)

// Change is one delta operation.
type Change struct {
	Op           string `json:"op"`
	Entry        *Entry `json:"entry,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
}

// Delta takes the allow-list from FromVersion to ToVersion.
type Delta struct {
	FromVersion int64    `json:"from_version"`
	ToVersion   int64    `json:"to_version"`
	Changes     []Change `json:"changes"`
}

// Validate implements Payload.
func (d Delta) Validate() error {
	switch {
	case d.FromVersion < 0 || d.ToVersion <= d.FromVersion:
		return fmt.Errorf("delta: invalid versions %d -> %d", d.FromVersion, d.ToVersion)
	case d.Changes == nil:
		return errors.New("delta: changes required")
	case len(d.Changes) > MaxDeltaChanges:
		return errors.New("delta: too many changes")
	}
	for _, c := range d.Changes {
		switch c.Op {
		case OpUpsert:
			if c.Entry == nil || c.CredentialID != "" {
				return errors.New("delta: upsert needs exactly an entry")
			}
			if err := c.Entry.Validate(); err != nil {
				return fmt.Errorf("delta: %w", err)
			}
		case OpRemove:
			if c.Entry != nil || !IsUUID(c.CredentialID) {
				return errors.New("delta: remove needs exactly a credential_id")
			}
		default:
			return fmt.Errorf("delta: unknown op %q", c.Op)
		}
	}
	return nil
}

// Event decisions.
const (
	DecisionAllow      = "allow"
	DecisionDeny       = "deny"
	DecisionManualOpen = "manual_open"
)

// Event is one access event (decision) in a batch.
type Event struct {
	ID             string          `json:"id"`
	PointID        string          `json:"point_id"`
	Decision       string          `json:"decision"`
	Reason         string          `json:"reason"`
	CredentialID   string          `json:"credential_id,omitempty"`
	PresentedKind  string          `json:"presented_kind,omitempty"`
	ObservedPlate  string          `json:"observed_plate,omitempty"`
	CommandID      string          `json:"command_id,omitempty"`
	VisitorEntryID string          `json:"visitor_entry_id,omitempty"`
	OccurredAt     Time            `json:"occurred_at"`
	RawRef         string          `json:"raw_ref,omitempty"`
	Detail         json.RawMessage `json:"detail,omitempty"`
}

// Validate checks one event.
func (e Event) Validate() error {
	if !IsUUIDv7(e.ID) {
		return fmt.Errorf("event: id %q is not a UUIDv7", e.ID)
	}
	if !IsUUID(e.PointID) {
		return errors.New("event: invalid point_id")
	}
	switch e.Decision {
	case DecisionAllow, DecisionDeny, DecisionManualOpen:
	default:
		return fmt.Errorf("event: invalid decision %q", e.Decision)
	}
	if e.Reason == "" || e.OccurredAt.IsZero() {
		return errors.New("event: reason and occurred_at required")
	}
	for name, v := range map[string]string{"credential_id": e.CredentialID, "command_id": e.CommandID, "visitor_entry_id": e.VisitorEntryID} {
		if v != "" && !IsUUID(v) {
			return fmt.Errorf("event: invalid %s", name)
		}
	}
	if len(e.RawRef) > MaxEventRawRef {
		return errors.New("event: raw_ref too long")
	}
	if len(e.Detail) > MaxEventDetailBytes {
		return errors.New("event: detail too large")
	}
	if len(e.Detail) > 0 && e.Detail[0] != '{' {
		return errors.New("event: detail must be an object")
	}
	return nil
}

// EventBatch is the payload of an "event" message.
type EventBatch struct {
	ClockOffsetMS *int64  `json:"clock_offset_ms,omitempty"`
	Events        []Event `json:"events"`
}

// Validate implements Payload.
func (b EventBatch) Validate() error {
	if n := len(b.Events); n < 1 || n > MaxEventBatch {
		return fmt.Errorf("event: batch size %d out of range", n)
	}
	for _, e := range b.Events {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Rejection is one rejected event in an event ack.
type Rejection struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

// EventAckDetail is the ack detail for event batches.
type EventAckDetail struct {
	Accepted   []string    `json:"accepted"`
	Duplicates []string    `json:"duplicates"`
	Rejected   []Rejection `json:"rejected"`
}

// Rejection codes of event acks.
const (
	RejectUnknownPoint = "unknown_point"
	RejectInvalid      = "invalid"
)

// Ack acknowledges a message by Ref.
type Ack struct {
	Ref    string          `json:"ref"`
	Status string          `json:"status"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

// Validate implements Payload.
func (a Ack) Validate() error {
	if !IsUUID(a.Ref) {
		return errors.New("ack: invalid ref")
	}
	switch a.Status {
	case AckOK, AckDuplicate, AckGap, AckDone, AckFailed, AckExpired, AckRefused, AckUnknownPoint, AckUnsupported, AckError:
	default:
		return fmt.Errorf("ack: invalid status %q", a.Status)
	}
	if len(a.Detail) > 0 && a.Detail[0] != '{' {
		return errors.New("ack: detail must be an object")
	}
	return nil
}

// NewAck builds an ack payload; detail may be nil.
func NewAck(ref, status string, detail any) (Ack, error) {
	a := Ack{Ref: ref, Status: status}
	if detail != nil {
		raw, err := json.Marshal(detail)
		if err != nil {
			return Ack{}, err
		}
		if string(raw) != "null" { // a typed nil map or slice means "no detail"
			a.Detail = raw
		}
	}
	return a, nil
}

// Actor is who caused an open command (for the agent's log only).
type Actor struct {
	UserID  string `json:"user_id,omitempty"`
	Display string `json:"display,omitempty"`
}

// PointConfig is a point definition inside update_config.
type PointConfig struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Direction string    `json:"direction"`
	DriverRef DriverRef `json:"driver_ref"`
	Enabled   bool      `json:"enabled"`
}

// Settings are the site access settings carried by update_config.
type Settings struct {
	OfflineGraceHours int    `json:"offline_grace_hours"`
	PlateMatch        string `json:"plate_match"`
	HeartbeatSeconds  int    `json:"heartbeat_seconds"`
	MaintenanceHour   int    `json:"maintenance_hour"`
}

// Config is the replaceable agent configuration from update_config.
type Config struct {
	ConfigVersion int64         `json:"config_version"`
	Site          Site          `json:"site"`
	Points        []PointConfig `json:"points"`
	Settings      Settings      `json:"settings"`
}

// Command is the payload of a "command" message; which fields are set depends
// on Command.
type Command struct {
	Command        string `json:"command"`
	PointID        string `json:"point_id,omitempty"`
	CredentialID   string `json:"credential_id,omitempty"`
	VisitorEntryID string `json:"visitor_entry_id,omitempty"`
	Actor          *Actor `json:"actor,omitempty"`
	IssuedAt       *Time  `json:"issued_at,omitempty"`
	ExpiresAt      *Time  `json:"expires_at,omitempty"`

	// update_config
	ConfigVersion *int64        `json:"config_version,omitempty"`
	Site          *Site         `json:"site,omitempty"`
	Points        []PointConfig `json:"points,omitempty"`
	Settings      *Settings     `json:"settings,omitempty"`
}

// Validate implements Payload.
func (c Command) Validate() error {
	switch c.Command {
	case CmdOpenPoint:
		if !IsUUID(c.PointID) || c.IssuedAt == nil || c.ExpiresAt == nil {
			return errors.New("command open_point: point_id, issued_at and expires_at required")
		}
		for _, v := range []string{c.CredentialID, c.VisitorEntryID} {
			if v != "" && !IsUUID(v) {
				return errors.New("command open_point: invalid id")
			}
		}
	case CmdRevokeCredential:
		if !IsUUID(c.CredentialID) {
			return errors.New("command revoke_credential: credential_id required")
		}
	case CmdUpdateConfig:
		if c.ConfigVersion == nil || c.Site == nil || c.Site.Timezone == "" || c.Settings == nil || c.Points == nil {
			return errors.New("command update_config: config_version, site, points and settings required")
		}
		for _, p := range c.Points {
			if !IsUUID(p.ID) || p.Name == "" || p.DriverRef.Instance == "" {
				return errors.New("command update_config: invalid point")
			}
		}
	case CmdRequestSnapshot, CmdRevoked:
	default:
		return fmt.Errorf("command: unknown command %q", c.Command)
	}
	return nil
}

// Config extracts the replaceable configuration of an update_config command.
func (c Command) Config() Config {
	cfg := Config{Points: c.Points}
	if c.ConfigVersion != nil {
		cfg.ConfigVersion = *c.ConfigVersion
	}
	if c.Site != nil {
		cfg.Site = *c.Site
	}
	if c.Settings != nil {
		cfg.Settings = *c.Settings
	}
	return cfg
}

// Heartbeat is the agent's periodic keep-alive.
type Heartbeat struct {
	SnapshotVersion int64         `json:"snapshot_version"`
	QueueDepth      int64         `json:"queue_depth"`
	DroppedEvents   int64         `json:"dropped_events"`
	UptimeS         int64         `json:"uptime_s"`
	ClockSuspect    bool          `json:"clock_suspect"`
	ClockOffsetMS   *int64        `json:"clock_offset_ms,omitempty"`
	Drivers         []DriverState `json:"drivers"`
}

// Validate implements Payload.
func (h Heartbeat) Validate() error {
	if h.SnapshotVersion < 0 || h.QueueDepth < 0 || h.DroppedEvents < 0 || h.UptimeS < 0 {
		return errors.New("heartbeat: negative counter")
	}
	if h.Drivers == nil {
		return errors.New("heartbeat: drivers required")
	}
	for _, d := range h.Drivers {
		if err := d.validate(); err != nil {
			return fmt.Errorf("heartbeat: %w", err)
		}
	}
	return nil
}

// Payload is implemented by every decoded payload type.
type Payload interface{ Validate() error }

// Decode parses and validates e's payload into its typed form: *AgentHello or
// *ServerHello (by "from"), *Snapshot, *Delta, *EventBatch, *Ack, *Command or
// *Heartbeat. Unknown types return ErrUnknownType. Unknown payload fields are
// tolerated (forward compatibility).
func (e Envelope) Decode() (Payload, error) {
	var p Payload
	switch e.Type {
	case TypeHello:
		var probe struct {
			From string `json:"from"`
		}
		if err := json.Unmarshal(e.Payload, &probe); err != nil {
			return nil, fmt.Errorf("protocol: hello: %w", err)
		}
		switch probe.From {
		case "agent":
			p = &AgentHello{}
		case "server":
			p = &ServerHello{}
		default:
			return nil, fmt.Errorf("protocol: hello: invalid from %q", probe.From)
		}
	case TypeSnapshot:
		p = &Snapshot{}
	case TypeDelta:
		p = &Delta{}
	case TypeEvent:
		p = &EventBatch{}
	case TypeAck:
		p = &Ack{}
	case TypeCommand:
		p = &Command{}
	case TypeHeartbeat:
		p = &Heartbeat{}
	default:
		return nil, ErrUnknownType
	}
	if err := json.Unmarshal(e.Payload, p); err != nil {
		return nil, fmt.Errorf("protocol: %s: %w", e.Type, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}
	return p, nil
}

// Poll is the long-poll HTTP body in both directions.
type Poll struct {
	Messages    []Envelope `json:"messages"`
	WaitSeconds int        `json:"wait_seconds,omitempty"`
}

// EnrolRequest is the enrolment request body (section 4.2).
type EnrolRequest struct {
	EnrolmentToken string `json:"enrolment_token"`
	Hostname       string `json:"hostname"`
	Platform       string `json:"platform"`
	AgentVersion   string `json:"agent_version"`
}

// EnrolResponse is the enrolment response body.
type EnrolResponse struct {
	AgentID          string `json:"agent_id"`
	AgentToken       string `json:"agent_token"`
	OrgID            string `json:"org_id"`
	SiteID           string `json:"site_id"`
	ServerTime       Time   `json:"server_time"`
	WSURL            string `json:"ws_url"`
	PollURL          string `json:"poll_url"`
	ProtocolVersions []int  `json:"protocol_versions"`
}

// RotateResponse is the token rotation response body.
type RotateResponse struct {
	AgentToken string `json:"agent_token"`
}
