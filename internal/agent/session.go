package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

const (
	inflightTimeout = 30 * time.Second
	flushTick       = 2 * time.Second
)

type inflightBatch struct {
	ids    []string
	sentAt time.Time
}

// sessState is the agent's side of one server session.
type sessState struct {
	a      *Agent
	sess   transport.Session
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	failMu  sync.Mutex
	failErr error

	t0         time.Time
	startOnce  sync.Once
	readyOnce  sync.Once
	ready      chan struct{}
	wantSnap   int64
	wantCfg    int64
	helloKnown bool

	mu        sync.Mutex
	inflight  map[string]inflightBatch
	cursor    int64
	needRetry bool
}

func (s *sessState) fail(err error) {
	s.failMu.Lock()
	if s.failErr == nil {
		s.failErr = err
	}
	s.failMu.Unlock()
	s.cancel()
}

func (s *sessState) failure() error {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	return s.failErr
}

func (s *sessState) send(typ string, payload any) (protocol.Envelope, error) {
	env, err := protocol.New(typ, payload, s.a.now())
	if err != nil {
		return env, err
	}
	if err := s.sess.Send(s.ctx, env); err != nil {
		if s.ctx.Err() == nil {
			s.fail(err)
		}
		return env, err
	}
	return env, nil
}

func (s *sessState) ack(ref, status string, detail any) {
	p, err := protocol.NewAck(ref, status, detail)
	if err != nil {
		s.a.log.Error("build ack", "error", err)
		return
	}
	_, _ = s.send(protocol.TypeAck, p)
}

// session is the transport handler: hello, then the message loop.
func (a *Agent) session(ctx context.Context, sess transport.Session) error {
	sctx, cancel := context.WithCancel(ctx)
	s := &sessState{a: a, sess: sess, ctx: sctx, cancel: cancel, ready: make(chan struct{}), wantSnap: -1, wantCfg: -1, inflight: map[string]inflightBatch{}}
	defer func() {
		cancel()
		s.wg.Wait()
	}()
	if sess.Mode() == transport.ModeWebSocket {
		a.touchContact(sctx, true) // an authenticated upgrade is contact
	}
	hello, err := a.buildHello(sctx)
	if err != nil {
		return err
	}
	env, err := protocol.New(protocol.TypeHello, hello, a.now())
	if err != nil {
		return err
	}
	s.t0 = a.now()
	if err := sess.Send(sctx, env); err != nil {
		return err
	}
	a.log.Info("session started", "mode", sess.Mode(), "snapshot_version", hello.SnapshotVersion, "queue_depth", hello.QueueDepth)
	for {
		in, err := sess.Receive(sctx)
		if err != nil {
			if f := s.failure(); f != nil {
				return f
			}
			return err
		}
		a.touchContact(sctx, false)
		if err := s.handle(in); err != nil {
			return err
		}
		if f := s.failure(); f != nil {
			return f
		}
	}
}

func (s *sessState) handle(env protocol.Envelope) error {
	p, err := env.Decode()
	switch {
	case errors.Is(err, protocol.ErrUnknownType):
		s.a.log.Warn("unsupported message type", "type", env.Type)
		s.ack(env.ID, protocol.AckUnsupported, nil)
		return nil
	case err != nil:
		s.a.log.Warn("invalid message", "type", env.Type, "error", err)
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": truncate(err.Error(), 200)})
		return nil
	}
	switch m := p.(type) {
	case *protocol.ServerHello:
		return s.onHello(m)
	case *protocol.Snapshot:
		return s.onSnapshot(env, m)
	case *protocol.Delta:
		return s.onDelta(env, m)
	case *protocol.Ack:
		s.onAck(m)
		return nil
	case *protocol.Command:
		return s.onCommand(env, m)
	}
	s.ack(env.ID, protocol.AckUnsupported, nil)
	return nil
}

// ---- hello ----

func (s *sessState) onHello(m *protocol.ServerHello) error {
	a := s.a
	if m.ProtocolVersion != protocol.Version {
		return errors.New("server chose an unsupported protocol version")
	}
	// offset = server - agent at the round-trip midpoint (design 4.9)
	t1 := a.now()
	mid := s.t0.Add(t1.Sub(s.t0) / 2)
	off := m.ServerTime.Sub(mid)
	a.offsetMS.Store(off.Milliseconds())
	a.offsetKnown.Store(true)
	if off > clockSuspectAfter || off < -clockSuspectAfter {
		a.log.Warn("agent clock differs from the server's by more than 120 s", "offset_ms", off.Milliseconds())
	}
	a.touchContact(s.ctx, true)
	if m.Site.Timezone != "" {
		if cur, _ := a.st.Timezone(s.ctx); cur == "" {
			_ = a.st.SetMeta(s.ctx, store.MetaTimezone, m.Site.Timezone)
			a.refreshSettings(s.ctx)
		}
	}
	s.wantSnap, s.wantCfg, s.helloKnown = m.SnapshotVersion, m.ConfigVersion, true
	s.startOnce.Do(func() {
		interval := time.Duration(m.HeartbeatSeconds) * time.Second
		if a.o.HeartbeatEvery > 0 {
			interval = a.o.HeartbeatEvery
		}
		s.wg.Add(3)
		go func() { defer s.wg.Done(); s.heartbeats(interval) }()
		go func() { defer s.wg.Done(); s.flusher() }()
		go func() {
			defer s.wg.Done()
			select {
			case <-time.After(a.o.ReadyTimeout):
				s.readyOnce.Do(func() { close(s.ready) })
			case <-s.ctx.Done():
			}
		}()
	})
	s.checkReady()
	s.maybeRotate(m)
	return nil
}

// checkReady opens the event upload once config and allow-list match the
// server's hello (design 6.4: update first, then queued events).
func (s *sessState) checkReady() {
	if !s.helloKnown {
		return
	}
	sv, err1 := s.a.st.SnapshotVersion(s.ctx)
	cv, err2 := s.a.st.ConfigVersion(s.ctx)
	if err1 == nil && err2 == nil && sv >= s.wantSnap && cv >= s.wantCfg {
		s.readyOnce.Do(func() { close(s.ready) })
	}
}

func (s *sessState) maybeRotate(m *protocol.ServerHello) {
	a := s.a
	due := m.RotateNow || (m.RotateBy != nil && !a.now().Before(m.RotateBy.Add(-rotateWithin)))
	if !due || !a.rotating.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer a.rotating.Store(false)
		if err := a.rotateToken(s.ctx); err != nil {
			if s.ctx.Err() == nil {
				a.log.Error("token rotation failed", "error", err)
			}
			return
		}
		a.log.Info("agent token rotated")
	}()
}

// Rotation retry tunables (tests shorten the delay).
var (
	rotateRetryBase = 5 * time.Second
	rotateRetryMax  = 60 * time.Second
)

// rotateWindow is how long the server keeps the old token valid.
const rotateWindow = 10 * time.Minute

// rotateToken rotates with the token held at the start. If the response is
// lost (the server rotated, the agent never saw the new token) the old token
// is still valid for 10 minutes and rotation is idempotent server side for
// it, so the call is repeated with the old token until the window closes.
func (a *Agent) rotateToken(ctx context.Context) error {
	old, err := readToken(a.cfg.StateDir)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(rotateWindow)
	delay := rotateRetryBase
	for {
		err := rotate(ctx, a.client.HTTPClient(), a.cfg.StateDir, a.id, old)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil || errors.Is(err, transport.ErrUnauthorized) || errors.Is(err, transport.ErrRevoked) || time.Now().Add(delay).After(deadline) {
			return err
		}
		if cur, rerr := readToken(a.cfg.StateDir); rerr == nil && cur != old {
			return nil // somebody else (rotate-token on the CLI) already replaced it
		}
		a.log.Warn("token rotation failed, retrying with the current token", "error", err, "retry_in", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay = min(delay*2, rotateRetryMax)
	}
}

// ---- heartbeat ----

func (s *sessState) heartbeats(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		_, _ = s.send(protocol.TypeHeartbeat, s.a.buildHeartbeat(s.ctx))
		select {
		case <-t.C:
			pctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
			err := s.sess.Ping(pctx)
			cancel()
			if err != nil && s.ctx.Err() == nil {
				s.fail(err)
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// ---- snapshot / delta ----

func (s *sessState) onSnapshot(env protocol.Envelope, m *protocol.Snapshot) error {
	applied, err := s.a.st.ApplySnapshotPart(s.ctx, *m)
	if err != nil {
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
		return err
	}
	s.ack(env.ID, protocol.AckOK, map[string]any{"version": m.Version, "part": m.Part, "applied": applied})
	if applied {
		s.a.log.Info("snapshot applied", "version", m.Version, "parts", m.Parts)
		s.a.refreshSettings(s.ctx)
		s.checkReady()
	}
	return nil
}

func (s *sessState) onDelta(env protocol.Envelope, m *protocol.Delta) error {
	status, have, err := s.a.st.ApplyDelta(s.ctx, *m)
	if err != nil {
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
		return err
	}
	switch status {
	case store.DeltaApplied:
		s.ack(env.ID, protocol.AckOK, map[string]any{"version": have})
		s.checkReady()
	case store.DeltaDuplicate:
		s.ack(env.ID, protocol.AckDuplicate, map[string]any{"have_version": have})
	default:
		s.a.log.Warn("allow-list gap, asking for a snapshot", "have", have, "delta_from", m.FromVersion)
		s.ack(env.ID, protocol.AckGap, map[string]any{"have_version": have})
	}
	return nil
}

// ---- events ----

func (s *sessState) onAck(m *protocol.Ack) {
	s.mu.Lock()
	b, ok := s.inflight[m.Ref]
	delete(s.inflight, m.Ref)
	s.mu.Unlock()
	if !ok {
		return // acks of hello/heartbeat/commands carry nothing we track
	}
	if m.Status != protocol.AckOK {
		s.a.log.Warn("event batch not accepted", "status", m.Status)
		s.markRetry()
		return
	}
	var det protocol.EventAckDetail
	if err := json.Unmarshal(m.Detail, &det); err != nil {
		s.markRetry()
		return
	}
	done := map[string]bool{}
	for _, id := range det.Accepted {
		done[id] = true
	}
	for _, id := range det.Duplicates {
		done[id] = true
	}
	for _, r := range det.Rejected {
		switch r.Code {
		case protocol.RejectUnknownPoint, protocol.RejectInvalid:
			s.a.log.Warn("event rejected permanently, dropping", "event_id", r.ID, "code", r.Code)
			done[r.ID] = true
		default:
			s.a.log.Warn("event rejected, will retry", "event_id", r.ID, "code", r.Code)
		}
	}
	ids := make([]string, 0, len(done))
	retry := false
	for _, id := range b.ids {
		if done[id] {
			ids = append(ids, id)
		} else {
			retry = true
		}
	}
	if err := s.a.st.DeleteEvents(s.ctx, ids); err != nil && s.ctx.Err() == nil {
		s.a.log.Error("delete acked events", "error", err)
		retry = true
	}
	if retry {
		s.markRetry()
	}
	s.a.notifyFlush()
}

func (s *sessState) markRetry() {
	s.mu.Lock()
	s.needRetry = true
	s.mu.Unlock()
}

func (s *sessState) flusher() {
	select {
	case <-s.ready:
	case <-s.ctx.Done():
		return
	}
	t := time.NewTicker(flushTick)
	defer t.Stop()
	for {
		s.flush()
		select {
		case <-s.a.flushCh:
		case <-t.C:
			s.maintain()
		case <-s.ctx.Done():
			return
		}
	}
}

// maintain expires lost acks and restarts the upload from the oldest unacked
// event when a batch has to be retried.
func (s *sessState) maintain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for ref, b := range s.inflight {
		if now.Sub(b.sentAt) > inflightTimeout {
			delete(s.inflight, ref)
			s.needRetry = true
		}
	}
	// A held event whose settle failed must not stay out of the queue.
	if err := s.a.st.ReleaseStale(s.ctx, s.a.now()); err != nil && s.ctx.Err() == nil {
		s.a.log.Error("release stale held events", "error", err)
	}
	if s.needRetry && len(s.inflight) == 0 {
		s.cursor, s.needRetry = 0, false
	}
}

func (s *sessState) flush() {
	for s.ctx.Err() == nil {
		s.mu.Lock()
		full := len(s.inflight) >= maxInflightBatches
		cursor := s.cursor
		s.mu.Unlock()
		if full {
			return
		}
		batch, err := s.a.st.NextBatch(s.ctx, cursor, protocol.MaxEventBatch, maxBatchBytes)
		if err != nil {
			if s.ctx.Err() == nil {
				s.a.log.Error("read event queue", "error", err)
			}
			return
		}
		if len(batch) == 0 {
			return
		}
		evs := make([]protocol.Event, len(batch))
		ids := make([]string, len(batch))
		for i, q := range batch {
			evs[i], ids[i] = q.Event, q.Event.ID
		}
		env, err := protocol.New(protocol.TypeEvent, protocol.EventBatch{ClockOffsetMS: s.a.clockOffsetPtr(), Events: evs}, s.a.now())
		if err != nil {
			s.a.log.Error("build event batch", "error", err)
			return
		}
		// Register before sending so the ack can never overtake the bookkeeping.
		s.mu.Lock()
		s.inflight[env.ID] = inflightBatch{ids: ids, sentAt: time.Now()}
		s.cursor = batch[len(batch)-1].Seq
		s.mu.Unlock()
		if err := s.sess.Send(s.ctx, env); err != nil {
			if s.ctx.Err() == nil {
				s.fail(err)
			}
			return
		}
	}
}
