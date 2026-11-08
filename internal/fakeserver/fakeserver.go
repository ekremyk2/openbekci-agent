// Package fakeserver is an in-process implementation of the server side of the
// agent protocol (docs/plans/07-access-control.md section 4), used by the
// agent's integration-style tests. It speaks WebSocket and long-poll over TLS
// (httptest), keeps an allow-list with a change log, issues commands and
// records everything the agent sends.
package fakeserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Server is the fake server. All exported methods are safe for concurrent use.
type Server struct {
	*httptest.Server
	t testing.TB

	mu      sync.Mutex
	offline atomic.Bool

	// identity
	OrgID, SiteID, AgentID string
	Timezone               string
	enrolTokens            map[string]bool
	token, prevToken       string
	prevExpiry             time.Time
	revoked                bool
	rejectAuth             bool // answer 401 to every authenticated request without revoking
	dropRotate             int  // rotate n times but lose the response
	enrolments             []protocol.EnrolRequest

	// tuning (set before or during a test)
	HeartbeatSeconds int
	RotateBy         time.Time
	rotateNow        bool
	ClockSkew        time.Duration // added to server_time
	SnapshotPart     int           // max entries per snapshot part
	DeltaMax         int           // max changes per delta message
	Now              func() time.Time

	upgradeFailures int // >0: next n upgrades fail with 200; <0: always
	upgradeAttempts int
	dropEventAcks   int
	rotations       int

	// allow-list
	version    int64
	entries    map[string]protocol.Entry
	log        []logged
	baseVer    int64 // deltas are only possible from versions >= baseVer
	cfg        protocol.Config
	knownPoint map[string]bool // event point validation; empty = accept all

	// session state
	live     *session
	pollSess *session
	pollOut  []protocol.Envelope
	pollSeq  int64
	pollReqs int // poll requests that carried messages from the agent
	pollWake chan struct{}

	// recorded traffic
	hellos     []protocol.AgentHello
	heartbeats []protocol.Heartbeat
	batches    []protocol.EventBatch
	events     []protocol.Event
	eventSeen  map[string]bool
	acks       []protocol.Ack
	commands   map[string]*command
	sent       []protocol.Envelope
	gapAcks    int
	dupAcks    int
	unsupp     int
	connects   int
}

type logged struct {
	version int64
	change  protocol.Change
}

type command struct {
	env    protocol.Envelope
	result *protocol.Ack
}

// session is one live agent connection (WebSocket or poll).
type session struct {
	out       chan protocol.Envelope // ws only
	pollMode  bool
	closeFn   func(code int, reason string)
	closeOnce sync.Once
	done      chan struct{}
}

func (s *session) close(code int, reason string) {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.closeFn != nil {
			s.closeFn(code, reason)
		}
	})
}

// New starts a fake server; it is closed by t.Cleanup.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		t:                t,
		OrgID:            id("a0"),
		SiteID:           id("a5"),
		AgentID:          id("a1"),
		Timezone:         "Europe/Istanbul",
		enrolTokens:      map[string]bool{},
		HeartbeatSeconds: 30,
		SnapshotPart:     protocol.MaxSnapshotEntries,
		DeltaMax:         protocol.MaxDeltaChanges,
		Now:              time.Now,
		entries:          map[string]protocol.Entry{},
		eventSeen:        map[string]bool{},
		commands:         map[string]*command{},
		pollWake:         make(chan struct{}, 1),
		cfg: protocol.Config{ConfigVersion: 1, Site: protocol.Site{Timezone: "Europe/Istanbul"}, Points: []protocol.PointConfig{},
			Settings: protocol.Settings{OfflineGraceHours: 72, PlateMatch: "exact", HeartbeatSeconds: 30, MaintenanceHour: 3}},
	}
	s.cfg.Site.ID = s.SiteID
	s.RotateBy = time.Now().AddDate(0, 6, 0)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/enrol", s.handleEnrol)
	mux.HandleFunc("POST /v1/orgs/{org}/sites/{site}/agents:enrol", s.handleEnrol)
	mux.HandleFunc("GET /v1/agent/ws", s.handleWS)
	mux.HandleFunc("POST /v1/agent/poll", s.handlePoll)
	mux.HandleFunc("POST /v1/agent/token:rotate", s.handleRotate)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.offline.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func id(suffix string) string { return "0192f1a0-0000-7000-8000-0000000000" + suffix }

// Close stops the server and ends live sessions.
func (s *Server) Close() {
	s.mu.Lock()
	if s.live != nil {
		s.live.close(1001, "server shutdown")
	}
	s.mu.Unlock()
	s.CloseClientConnections()
	s.Server.Close()
}

// WSURL, PollURL and RotateURL are the endpoints handed out at enrolment.
func (s *Server) WSURL() string     { return "wss" + strings.TrimPrefix(s.URL, "https") + "/v1/agent/ws" }
func (s *Server) PollURL() string   { return s.URL + "/v1/agent/poll" }
func (s *Server) RotateURL() string { return s.URL + "/v1/agent/token:rotate" }

// CACertFile writes the server's TLS certificate (PEM) to a temp file for use
// as the agent's ca_file.
func (s *Server) CACertFile() string {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Server.Certificate().Raw})
	p := filepath.Join(s.t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pemData, 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewEnrolToken creates a one-time enrolment token.
func (s *Server) NewEnrolToken() string {
	tok := "obk_enr_" + randHex(16)
	s.mu.Lock()
	s.enrolTokens[tok] = true
	s.mu.Unlock()
	return tok
}

func (s *Server) newAgentToken() string { return "obk_agt_" + s.AgentID + "." + randHex(32) }

// authorized checks a bearer token; the previous token stays valid for 10
// minutes after rotation.
func (s *Server) authorized(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.rejectAuth || tok == "" {
		return false
	}
	return tok == s.token || (tok == s.prevToken && s.Now().Before(s.prevExpiry))
}

// ---- configuration of the fake's behaviour ----

// FailUpgrades makes the next n WebSocket upgrades answer 200 (what a
// blocking proxy does); a negative n fails all of them.
func (s *Server) FailUpgrades(n int) { s.mu.Lock(); s.upgradeFailures = n; s.mu.Unlock() }

// UpgradeAttempts counts WebSocket upgrade attempts (including failed ones).
func (s *Server) UpgradeAttempts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.upgradeAttempts }

// DropEventAcks makes the server swallow the acks of the next n event batches
// (it still stores the events), to test redelivery.
func (s *Server) DropEventAcks(n int) { s.mu.Lock(); s.dropEventAcks = n; s.mu.Unlock() }

// SetKnownPoints makes events for other points rejected with unknown_point.
func (s *Server) SetKnownPoints(ids ...string) {
	s.mu.Lock()
	s.knownPoint = map[string]bool{}
	for _, p := range ids {
		s.knownPoint[p] = true
	}
	s.mu.Unlock()
}

// ForceRotate sets rotate_now in the next hello.
func (s *Server) ForceRotate() { s.mu.Lock(); s.rotateNow = true; s.mu.Unlock() }

// SetRotateBy changes rotate_by in the next hello.
func (s *Server) SetRotateBy(t time.Time) { s.mu.Lock(); s.RotateBy = t; s.mu.Unlock() }

// Rotations returns how many token rotations were served.
func (s *Server) Rotations() int { s.mu.Lock(); defer s.mu.Unlock(); return s.rotations }

// CurrentToken returns the valid agent token.
func (s *Server) CurrentToken() string { s.mu.Lock(); defer s.mu.Unlock(); return s.token }

// PrevToken returns the previous (still valid for 10 minutes) token.
func (s *Server) PrevToken() string { s.mu.Lock(); defer s.mu.Unlock(); return s.prevToken }

// ExpirePrevToken ends the grace period of the previous token.
func (s *Server) ExpirePrevToken() { s.mu.Lock(); s.prevExpiry = time.Time{}; s.mu.Unlock() }

// Revoked reports whether Revoke was called.
func (s *Server) Revoked() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.revoked }

// ---- allow-list ----

// Version is the current allow-list version.
func (s *Server) Version() int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.version }

// Upsert adds or replaces an entry, bumps the version and pushes the delta to
// a connected agent.
func (s *Server) Upsert(e protocol.Entry) {
	s.apply([]protocol.Change{{Op: protocol.OpUpsert, Entry: &e}})
}

// Remove deletes an entry (delta op remove).
func (s *Server) Remove(credentialID string) {
	s.apply([]protocol.Change{{Op: protocol.OpRemove, CredentialID: credentialID}})
}

func (s *Server) apply(changes []protocol.Change) {
	s.mu.Lock()
	defer s.mu.Unlock()
	from := s.version
	s.version++
	for _, c := range changes {
		switch c.Op {
		case protocol.OpUpsert:
			s.entries[c.Entry.ID] = *c.Entry
		case protocol.OpRemove:
			delete(s.entries, c.CredentialID)
		}
		s.log = append(s.log, logged{s.version, c})
	}
	s.sendLocked(s.envLocked(protocol.TypeDelta, protocol.Delta{FromVersion: from, ToVersion: s.version, Changes: changes}))
}

// SilentUpsert changes the allow-list and bumps the version without telling a
// connected agent (so the next delta it receives has a gap).
func (s *Server) SilentUpsert(e protocol.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version++
	s.entries[e.ID] = e
	s.log = append(s.log, logged{s.version, protocol.Change{Op: protocol.OpUpsert, Entry: &e}})
}

// PruneLog drops the change log: agents older than the current version get a
// snapshot instead of deltas.
func (s *Server) PruneLog() {
	s.mu.Lock()
	s.baseVer = s.version
	s.log = nil
	s.mu.Unlock()
}

// SendRawDelta pushes an arbitrary delta (to create gaps and duplicates).
func (s *Server) SendRawDelta(from, to int64, changes []protocol.Change) protocol.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	env := s.envLocked(protocol.TypeDelta, protocol.Delta{FromVersion: from, ToVersion: to, Changes: changes})
	s.sendLocked(env)
	return env
}

// SetConfig replaces the point/config definition; it is sent as update_config
// to a connected agent and at every hello whose config_version differs.
func (s *Server) SetConfig(points []protocol.PointConfig, settings *protocol.Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.ConfigVersion++
	s.cfg.Points = points
	if settings != nil {
		s.cfg.Settings = *settings
	}
	s.sendLocked(s.configCmdLocked())
}

// ConfigVersion is the current config_version.
func (s *Server) ConfigVersion() int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.cfg.ConfigVersion }

func (s *Server) configCmdLocked() protocol.Envelope {
	cv := s.cfg.ConfigVersion
	site := s.cfg.Site
	set := s.cfg.Settings
	return s.envLocked(protocol.TypeCommand, protocol.Command{Command: protocol.CmdUpdateConfig, ConfigVersion: &cv, Site: &site, Points: s.cfg.Points, Settings: &set})
}

// ---- commands ----

// IssueOpen sends an open_point command with the given TTL and returns its id
// (the envelope id, which is also the command id).
func (s *Server) IssueOpen(pointID string, ttl time.Duration) string {
	return s.IssueOpenAt(pointID, s.Now(), ttl)
}

// IssueOpenAt is IssueOpen with an explicit issued_at (e.g. in the past, to
// deliver an already expired command).
func (s *Server) IssueOpenAt(pointID string, issued time.Time, ttl time.Duration) string {
	iss, exp := protocol.At(issued), protocol.At(issued.Add(ttl))
	s.mu.Lock()
	defer s.mu.Unlock()
	env := s.envLocked(protocol.TypeCommand, protocol.Command{
		Command: protocol.CmdOpenPoint, PointID: pointID, IssuedAt: &iss, ExpiresAt: &exp,
		Actor: &protocol.Actor{UserID: id("99"), Display: "Guard Ali"},
	})
	s.commands[env.ID] = &command{env: env}
	s.sendLocked(env)
	return env.ID
}

// Redeliver sends a previously issued command again, unchanged.
func (s *Server) Redeliver(commandID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.commands[commandID]; ok {
		s.sendLocked(c.env)
	}
}

// Command sends any command payload.
func (s *Server) Command(c protocol.Command) protocol.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	env := s.envLocked(protocol.TypeCommand, c)
	s.sendLocked(env)
	return env
}

// CommandResult returns the ack the agent sent for a command.
func (s *Server) CommandResult(commandID string) (protocol.Ack, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.commands[commandID]; ok && c.result != nil {
		return *c.result, true
	}
	return protocol.Ack{}, false
}

// Revoke revokes the agent: the connected agent gets command revoked and a
// 4401 close; every later request answers 401.
func (s *Server) Revoke() {
	s.mu.Lock()
	s.sendLocked(s.envLocked(protocol.TypeCommand, protocol.Command{Command: protocol.CmdRevoked}))
	live := s.live
	s.revoked = true
	s.mu.Unlock()
	if live != nil {
		// give the writer goroutine a moment to flush the command first
		time.Sleep(50 * time.Millisecond)
		live.close(protocol.CloseRevoked, "revoked")
	}
}

// RejectAuth makes the server answer a bare 401 to every authenticated request
// (what a WAF or a deploy-time auth-cache miss does) without revoking the agent.
func (s *Server) RejectAuth(v bool) { s.mu.Lock(); s.rejectAuth = v; s.mu.Unlock() }

// DropRotateResponses makes the next n rotations take effect on the server but
// lose the response on the wire.
func (s *Server) DropRotateResponses(n int) { s.mu.Lock(); s.dropRotate = n; s.mu.Unlock() }

// CloseWith closes the live WebSocket with the given close code and nothing else.
func (s *Server) CloseWith(code int, reason string) {
	s.mu.Lock()
	live := s.live
	s.mu.Unlock()
	if live != nil {
		live.close(code, reason)
	}
}

// DropConnection closes the live WebSocket abruptly-ish (code 1001), as a
// network cut would.
func (s *Server) DropConnection() {
	s.mu.Lock()
	live := s.live
	s.mu.Unlock()
	if live != nil {
		live.close(1001, "going away")
	}
}

// ---- observation ----

// Hellos returns the agent hellos received so far.
func (s *Server) Hellos() []protocol.AgentHello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.AgentHello(nil), s.hellos...)
}

// Heartbeats returns the heartbeats received so far.
func (s *Server) Heartbeats() []protocol.Heartbeat {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Heartbeat(nil), s.heartbeats...)
}

// Events returns every distinct event accepted so far, in arrival order.
func (s *Server) Events() []protocol.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Event(nil), s.events...)
}

// Batches returns every event batch received (including redeliveries).
func (s *Server) Batches() []protocol.EventBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.EventBatch(nil), s.batches...)
}

// Acks returns the acks the agent sent.
func (s *Server) Acks() []protocol.Ack {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Ack(nil), s.acks...)
}

// Enrolments returns the enrolment requests served.
func (s *Server) Enrolments() []protocol.EnrolRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.EnrolRequest(nil), s.enrolments...)
}

// Counters returns how many gap, duplicate and unsupported acks the agent sent,
// and how many sessions were established.
func (s *Server) Counters() (gap, dup, unsupported, connects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gapAcks, s.dupAcks, s.unsupp, s.connects
}

// Sent returns every envelope the server sent.
func (s *Server) Sent() []protocol.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Envelope(nil), s.sent...)
}

// Connected reports whether an agent session is currently established.
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live != nil && len(s.hellos) > 0
}

// Eventually polls cond until it holds or the timeout passes.
func (s *Server) Eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// ---- internals ----

func (s *Server) envLocked(typ string, payload any) protocol.Envelope {
	env, err := protocol.New(typ, payload, s.Now())
	if err != nil {
		s.t.Fatalf("fakeserver: %v", err)
	}
	return env
}

// sendLocked queues env to the live session (or the poll outbox).
func (s *Server) sendLocked(env protocol.Envelope) {
	s.sent = append(s.sent, env)
	switch {
	case s.live != nil && !s.live.pollMode:
		select {
		case s.live.out <- env:
		default:
			s.t.Errorf("fakeserver: session outbox full")
		}
	case s.pollSess != nil:
		s.pollOut = append(s.pollOut, env)
		select {
		case s.pollWake <- struct{}{}:
		default:
		}
	}
}

func (s *Server) serverHelloLocked() protocol.Envelope {
	rb := protocol.At(s.RotateBy)
	return s.envLocked(protocol.TypeHello, protocol.ServerHello{
		From: "server", ProtocolVersion: 1, ServerTime: protocol.At(s.Now().Add(s.ClockSkew)),
		HeartbeatSeconds: s.HeartbeatSeconds, ConfigVersion: s.cfg.ConfigVersion,
		RotateBy: &rb, RotateNow: s.rotateNow, Site: protocol.Site{ID: s.SiteID, Timezone: s.Timezone}, SnapshotVersion: s.version,
	})
}

// snapshotLocked sends the allow-list as parts.
func (s *Server) snapshotLocked() {
	ids := make([]string, 0, len(s.entries))
	for k := range s.entries {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	size := s.SnapshotPart
	parts := (len(ids) + size - 1) / size
	if parts == 0 {
		parts = 1
	}
	for p := 1; p <= parts; p++ {
		lo, hi := (p-1)*size, min(p*size, len(ids))
		es := make([]protocol.Entry, 0, hi-lo)
		for _, k := range ids[lo:hi] {
			es = append(es, s.entries[k])
		}
		s.sendLocked(s.envLocked(protocol.TypeSnapshot, protocol.Snapshot{Version: s.version, Part: p, Parts: parts, Site: protocol.Site{Timezone: s.Timezone}, Entries: es}))
	}
}

// syncLocked brings an agent at version have up to date.
func (s *Server) syncLocked(have int64) {
	switch {
	case have == s.version:
	case have < s.version && have >= s.baseVer:
		var batch []protocol.Change
		from := have
		flush := func(to int64) {
			if len(batch) == 0 {
				return
			}
			s.sendLocked(s.envLocked(protocol.TypeDelta, protocol.Delta{FromVersion: from, ToVersion: to, Changes: batch}))
			from, batch = to, nil
		}
		var cur int64
		for _, l := range s.log {
			if l.version <= have {
				continue
			}
			if l.version != cur && len(batch) >= s.DeltaMax {
				flush(cur)
			}
			cur = l.version
			batch = append(batch, l.change)
		}
		flush(s.version)
	default:
		s.snapshotLocked()
	}
}

func (s *Server) handleMessage(env protocol.Envelope) {
	p, err := env.Decode()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if errors.Is(err, protocol.ErrUnknownType) {
			s.unsupp++
			s.ackLocked(env.ID, protocol.AckUnsupported, nil)
		} else {
			s.t.Errorf("fakeserver: agent sent an invalid %s message: %v", env.Type, err)
			s.ackLocked(env.ID, protocol.AckError, map[string]string{"reason": err.Error()})
		}
		return
	}
	switch m := p.(type) {
	case *protocol.AgentHello:
		s.hellos = append(s.hellos, *m)
		s.connects++
		s.sendLocked(s.serverHelloLocked())
		s.rotateNow = false
		if m.ConfigVersion != s.cfg.ConfigVersion {
			s.sendLocked(s.configCmdLocked())
		}
		s.syncLocked(m.SnapshotVersion)
		for _, c := range s.commands {
			if c.result == nil {
				s.sendLocked(c.env)
			}
		}
	case *protocol.Heartbeat:
		s.heartbeats = append(s.heartbeats, *m)
	case *protocol.EventBatch:
		s.batches = append(s.batches, *m)
		det := protocol.EventAckDetail{Accepted: []string{}, Duplicates: []string{}, Rejected: []protocol.Rejection{}}
		for _, ev := range m.Events {
			switch {
			case len(s.knownPoint) > 0 && !s.knownPoint[ev.PointID]:
				det.Rejected = append(det.Rejected, protocol.Rejection{ID: ev.ID, Code: protocol.RejectUnknownPoint})
			case s.eventSeen[ev.ID]:
				det.Duplicates = append(det.Duplicates, ev.ID)
			default:
				s.eventSeen[ev.ID] = true
				s.events = append(s.events, ev)
				det.Accepted = append(det.Accepted, ev.ID)
			}
		}
		if s.dropEventAcks > 0 {
			s.dropEventAcks--
			return
		}
		s.ackLocked(env.ID, protocol.AckOK, det)
	case *protocol.Ack:
		s.acks = append(s.acks, *m)
		switch m.Status {
		case protocol.AckGap:
			s.gapAcks++
			s.snapshotLocked()
		case protocol.AckDuplicate:
			s.dupAcks++
		case protocol.AckUnsupported:
			s.unsupp++
		}
		if c, ok := s.commands[m.Ref]; ok {
			a := *m
			c.result = &a
		}
	default:
		s.ackLocked(env.ID, protocol.AckUnsupported, nil)
	}
}

func (s *Server) ackLocked(ref, status string, detail any) {
	a, err := protocol.NewAck(ref, status, detail)
	if err != nil {
		s.t.Fatal(err)
	}
	s.sendLocked(s.envLocked(protocol.TypeAck, a))
}

// ---- HTTP handlers ----

func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if !s.enrolTokens[req.EnrolmentToken] {
		s.mu.Unlock()
		http.Error(w, `{"title":"not found"}`, http.StatusNotFound) // one identical body for all failures
		return
	}
	delete(s.enrolTokens, req.EnrolmentToken)
	s.enrolments = append(s.enrolments, req)
	s.token = s.newAgentToken()
	s.revoked = false
	resp := protocol.EnrolResponse{
		AgentID: s.AgentID, AgentToken: s.token, OrgID: s.OrgID, SiteID: s.SiteID, ServerTime: protocol.At(s.Now()),
		WSURL: s.WSURL(), PollURL: s.PollURL(), ProtocolVersions: []int{1},
	}
	s.mu.Unlock()
	writeJSON(w, resp)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	if presented == s.prevToken && presented != s.token {
		// Idempotent per the design: the retired token inside its 10 minute
		// window gets the token its rotation already produced.
		tok := s.token
		s.mu.Unlock()
		writeJSON(w, protocol.RotateResponse{AgentToken: tok})
		return
	}
	s.prevToken, s.prevExpiry = s.token, s.Now().Add(10*time.Minute)
	s.token = s.newAgentToken()
	s.rotations++
	tok := s.token
	lose := s.dropRotate > 0
	if lose {
		s.dropRotate--
	}
	s.mu.Unlock()
	if lose {
		panic(http.ErrAbortHandler) // the response never reaches the agent
	}
	writeJSON(w, protocol.RotateResponse{AgentToken: tok})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.upgradeAttempts++
	if s.upgradeFailures != 0 {
		if s.upgradeFailures > 0 {
			s.upgradeFailures--
		}
		s.mu.Unlock()
		_, _ = w.Write([]byte("<html>proxy says hi</html>")) // 200, not 101
		return
	}
	s.mu.Unlock()
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.Subprotocol}, CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		return
	}
	conn.SetReadLimit(protocol.MaxFrameBytes + 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &session{out: make(chan protocol.Envelope, 1024), done: make(chan struct{})}
	sess.closeFn = func(code int, reason string) { _ = conn.Close(websocket.StatusCode(code), reason) }

	s.mu.Lock()
	if s.live != nil {
		old := s.live
		go old.close(protocol.CloseReplaced, "replaced by a newer session")
	}
	s.live = sess
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.live == sess {
			s.live = nil
		}
		s.mu.Unlock()
	}()

	go func() { // writer
		for {
			select {
			case env := <-sess.out:
				data, _ := env.MarshalJSON()
				if conn.Write(ctx, websocket.MessageText, data) != nil {
					return
				}
			case <-sess.done:
				// flush what is already queued, then stop
				for {
					select {
					case env := <-sess.out:
						data, _ := env.MarshalJSON()
						_ = conn.Write(ctx, websocket.MessageText, data)
					default:
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		env, err := protocol.ParseEnvelope(data)
		if err != nil {
			s.t.Errorf("fakeserver: agent sent an invalid frame: %v", err)
			continue
		}
		s.handleMessage(env)
	}
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req protocol.Poll
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Messages) > 0 {
		s.mu.Lock()
		s.pollReqs++
		s.mu.Unlock()
	}
	for _, env := range req.Messages {
		if env.Type == protocol.TypeHello {
			s.mu.Lock()
			if s.live != nil && !s.live.pollMode {
				s.live.close(protocol.CloseReplaced, "replaced")
			}
			s.pollSess = &session{pollMode: true, done: make(chan struct{})}
			s.live = s.pollSess
			s.pollOut = nil
			s.pollSeq = 0
			s.mu.Unlock()
		}
		s.mu.Lock()
		sess := s.pollSess
		s.mu.Unlock()
		if sess == nil {
			http.Error(w, "no session: send hello first", http.StatusConflict)
			return
		}
		s.handleMessage(env)
	}
	deadline := time.After(time.Duration(min(req.WaitSeconds, protocol.MaxPollWaitSeconds)) * time.Second)
	for {
		s.mu.Lock()
		out := s.pollOut
		s.pollOut = nil
		var seq int64
		if len(out) > 0 {
			s.pollSeq++
			seq = s.pollSeq
		}
		s.mu.Unlock()
		if len(out) > 0 || req.WaitSeconds == 0 {
			if out == nil {
				out = []protocol.Envelope{}
			}
			writeJSON(w, protocol.Poll{Messages: out, Seq: seq})
			return
		}
		select {
		case <-s.pollWake:
		case <-deadline:
			writeJSON(w, protocol.Poll{Messages: []protocol.Envelope{}})
			return
		case <-r.Context().Done():
			return
		}
	}
}

// PollRequests counts long-poll requests that carried messages from the agent.
func (s *Server) PollRequests() int { s.mu.Lock(); defer s.mu.Unlock(); return s.pollReqs }

// SetOffline makes every endpoint answer 503 and drops the live connection,
// like an unreachable server.
func (s *Server) SetOffline(v bool) {
	s.offline.Store(v)
	if v {
		s.DropConnection()
	}
}

// SendEnvelope sends an arbitrary message (e.g. an unknown type).
func (s *Server) SendEnvelope(typ string, payload any) protocol.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	env := s.envLocked(typ, payload)
	s.sendLocked(env)
	return env
}
