package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/driver"
	"github.com/openbekci/openbekci-agent/internal/driver/mock"
	"github.com/openbekci/openbekci-agent/internal/engine"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

// Tunables that tests shorten.
const (
	defaultReadyTimeout = 10 * time.Second
	contactPersistEvery = 10 * time.Second
	clockSuspectAfter   = 120 * time.Second
	maxClockOffset      = 24 * time.Hour
	maxCommandTTL       = 60 * time.Second
	rotateWithin        = 14 * 24 * time.Hour
	maxInflightBatches  = 5
	maxBatchBytes       = 512 << 10
	openTimeout         = 10 * time.Second
	mockInstance        = "mock"
)

// Options configure an Agent.
type Options struct {
	Config        *config.Config
	Registrations []driver.Registration
	Version       string
	Log           *slog.Logger
	// Clock is the agent's own clock; defaults to time.Now.
	Clock func() time.Time

	// Mock is `run --mock`: configured drivers are ignored and every driver
	// instance named by a point resolves to one scriptable mock driver.
	Mock       bool
	MockConfig mock.Config

	// HeartbeatEvery overrides the server's heartbeat interval (tests).
	HeartbeatEvery time.Duration
	// ReadyTimeout bounds the wait for config/snapshot before event upload.
	ReadyTimeout time.Duration
	// Transport lets tests tune the transport options.
	Transport func(*transport.Options)
}

// Agent is the running agent.
type Agent struct {
	o   Options
	cfg *config.Config
	log *slog.Logger

	st     *store.Store
	eng    *engine.Engine
	id     Identity
	start  time.Time
	client *transport.Client

	drivers map[string]*instance
	mockAll *mock.Driver

	mu   sync.RWMutex
	pcfg protocol.Config

	offsetMS    atomic.Int64
	offsetKnown atomic.Bool
	lastContact atomic.Int64 // unix ms
	lastPersist atomic.Int64 // unix ms
	flushCh     chan struct{}
	presentCh   chan driver.Presentation

	rotating atomic.Bool
}

type instance struct {
	name string
	typ  string
	drv  driver.Driver
	err  error
}

// New validates the configuration and builds the agent; hardware is touched in
// Run.
func New(o Options) (*Agent, error) {
	if o.Config == nil {
		return nil, errors.New("agent: config required")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.ReadyTimeout == 0 {
		o.ReadyTimeout = defaultReadyTimeout
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	a := &Agent{o: o, cfg: o.Config, log: o.Log, drivers: map[string]*instance{}, flushCh: make(chan struct{}, 1), presentCh: make(chan driver.Presentation, 64)}
	if o.Mock {
		m, err := mock.New(mockInstance, o.MockConfig, o.Log.With("driver", mockInstance))
		if err != nil {
			return nil, err
		}
		a.mockAll = m
	}
	return a, nil
}

// MockDriver returns the catch-all mock driver of `run --mock` (nil otherwise).
func (a *Agent) MockDriver() *mock.Driver { return a.mockAll }

func (a *Agent) now() time.Time { return a.o.Clock() }

// serverNow is the agent clock corrected by the measured server offset (used
// only to judge command expiry; decisions use the agent's own clock).
func (a *Agent) serverNow() time.Time {
	now := a.now()
	if a.offsetKnown.Load() {
		if off := time.Duration(a.offsetMS.Load()) * time.Millisecond; off > -maxClockOffset && off < maxClockOffset {
			return now.Add(off)
		}
	}
	return now
}

func (a *Agent) notifyFlush() {
	select {
	case a.flushCh <- struct{}{}:
	default:
	}
}

// touchContact records an authenticated server contact.
func (a *Agent) touchContact(ctx context.Context, force bool) {
	now := a.now()
	a.lastContact.Store(now.UnixMilli())
	last := a.lastPersist.Load()
	if force || now.UnixMilli()-last >= contactPersistEvery.Milliseconds() {
		a.lastPersist.Store(now.UnixMilli())
		if err := a.st.SetLastContact(ctx, now); err != nil && ctx.Err() == nil {
			a.log.Warn("persist last contact failed", "error", err)
		}
	}
}

func (a *Agent) lastContactTime() time.Time {
	ms := a.lastContact.Load()
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// Run runs the agent until ctx ends or the server revokes it. On revocation the
// local state is wiped and ErrRevoked is returned.
func (a *Agent) Run(ctx context.Context) error {
	if IsRevoked(a.cfg.StateDir) {
		return ErrRevoked
	}
	if _, err := readToken(a.cfg.StateDir); err != nil {
		return err
	}
	var err error
	a.id, err = readIdentity(a.cfg.StateDir)
	if err != nil {
		return err
	}
	a.start = a.now()
	a.st, err = store.Open(a.cfg.StateDir)
	if err != nil {
		return err
	}
	closed := false
	closeStore := func() {
		if !closed {
			closed = true
			_ = a.st.Close()
		}
	}
	defer closeStore()

	a.eng = engine.New(engine.Options{
		Store:       a.st,
		Clock:       a.now,
		LastContact: a.lastContactTime,
		Open:        a.openPoint,
		OnEvent:     a.notifyFlush,
		Log:         a.log,
	})
	if t, err := a.st.LastContact(ctx); err == nil && !t.IsZero() {
		a.lastContact.Store(t.UnixMilli())
		a.lastPersist.Store(t.UnixMilli())
	}
	if c, err := a.st.LoadConfig(ctx); err != nil {
		return fmt.Errorf("load config: %w", err)
	} else if c != nil {
		a.mu.Lock()
		a.pcfg = *c
		a.mu.Unlock()
	}
	a.refreshSettings(ctx)

	to := transport.Options{
		WSURL: a.id.WSURL, PollURL: a.id.PollURL, CAFile: a.cfg.CAFile,
		Token: func() (string, error) { return readToken(a.cfg.StateDir) },
		Log:   a.log.With("component", "transport"),
		// Pongs and empty poll answers are server contact too.
		OnContact: func() { a.touchContact(ctx, false) },
	}
	if a.o.Transport != nil {
		a.o.Transport(&to)
	}
	a.client, err = transport.NewClient(to)
	if err != nil {
		return err
	}

	if err := a.buildDrivers(); err != nil {
		return err
	}
	defer a.closeDrivers()

	wctx, stopWorkers := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, in := range a.drivers {
		if in.drv == nil {
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); a.subscribe(wctx, in) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); a.presentations(wctx) }()

	a.log.Info("agent started", "version", a.o.Version, "agent_id", a.id.AgentID, "mock", a.o.Mock)
	runErr := a.client.Run(wctx, a.session)
	stopWorkers()
	wg.Wait()

	switch {
	case errors.Is(runErr, transport.ErrRevoked):
		// Any 401 on an authenticated call means revoked: wipe everything.
		a.log.Warn("server rejected the agent token: revoked; wiping local state")
		closeStore()
		if err := WipeState(a.cfg.StateDir); err != nil {
			return fmt.Errorf("wipe state: %w", errors.Join(ErrRevoked, err))
		}
		return ErrRevoked
	case errors.Is(runErr, context.Canceled), errors.Is(runErr, context.DeadlineExceeded):
		if ctx.Err() != nil {
			return nil
		}
	}
	return runErr
}

// ---- configuration state ----

func (a *Agent) config() protocol.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pcfg
}

func (a *Agent) point(id string) (protocol.PointConfig, bool) {
	for _, p := range a.config().Points {
		if p.ID == id {
			return p, true
		}
	}
	return protocol.PointConfig{}, false
}

// refreshSettings pushes timezone, grace period and plate matching to the engine.
func (a *Agent) refreshSettings(ctx context.Context) {
	pc := a.config()
	loc := time.UTC
	if tz, err := a.st.Timezone(ctx); err == nil && tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		} else {
			a.log.Error("unknown timezone, using UTC", "timezone", tz)
		}
	}
	grace := a.cfg.OfflineGraceHours
	if pc.Settings.OfflineGraceHours > 0 {
		grace = pc.Settings.OfflineGraceHours
	}
	a.eng.SetSettings(engine.Settings{Location: loc, GraceHours: grace, PlateMatch: pc.Settings.PlateMatch})
}

// ---- drivers ----

func (a *Agent) buildDrivers() error {
	if a.mockAll != nil {
		a.drivers[mockInstance] = &instance{name: mockInstance, typ: "mock", drv: a.mockAll}
		return nil
	}
	for _, dc := range a.cfg.Drivers {
		in := &instance{name: dc.Name, typ: dc.Type}
		a.drivers[dc.Name] = in
		reg, ok := driver.Find(a.o.Registrations, dc.Type)
		if !ok {
			in.err = fmt.Errorf("unknown driver type %q", dc.Type)
			a.log.Error("driver not available", "instance", dc.Name, "error", in.err)
			continue
		}
		drv, err := reg.New(dc.Name, dc.Config, a.log.With("driver", dc.Name))
		if err != nil {
			in.err = err
			a.log.Error("driver not available", "instance", dc.Name, "error", err)
			continue
		}
		in.drv = drv
	}
	return nil
}

func (a *Agent) closeDrivers() {
	for _, in := range a.drivers {
		if in.drv != nil {
			_ = in.drv.Close()
		}
	}
}

// driverFor resolves an instance name; in mock mode every name resolves to the
// catch-all mock.
func (a *Agent) driverFor(name string) (driver.Driver, error) {
	if a.mockAll != nil {
		return a.mockAll, nil
	}
	in, ok := a.drivers[name]
	switch {
	case !ok:
		return nil, fmt.Errorf("driver instance %q is not configured in agent.yaml", name)
	case in.err != nil:
		return nil, fmt.Errorf("driver instance %q unavailable: %w", name, in.err)
	}
	return in.drv, nil
}

// openerFor returns the instance and channel that open a point: the local
// `points:` wiring if it matches, else the point's own driver_ref.
func (a *Agent) openerFor(p protocol.PointConfig) (string, string) {
	best, bestScore := config.OpenRef{Instance: p.DriverRef.Instance, Channel: p.DriverRef.Channel}, 0
	for _, w := range a.cfg.Points {
		if w.Point != p.DriverRef.Instance {
			continue
		}
		score := 1
		if w.Channel != "" {
			if w.Channel != p.DriverRef.Channel {
				continue
			}
			score = 2
		}
		if score > bestScore {
			best, bestScore = w.Open, score
		}
	}
	return best.Instance, best.Channel
}

// openPoint executes an open on the point's hardware.
func (a *Agent) openPoint(ctx context.Context, pointID string) error {
	p, ok := a.point(pointID)
	if !ok {
		return fmt.Errorf("unknown point %s", pointID)
	}
	inst, ch := a.openerFor(p)
	drv, err := a.driverFor(inst)
	if err != nil {
		return err
	}
	octx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	return drv.Open(octx, ch)
}

// driverStates reports every configured instance plus instances that points
// reference but agent.yaml lacks ("missing").
func (a *Agent) driverStates(ctx context.Context) []protocol.DriverState {
	out := []protocol.DriverState{}
	seen := map[string]bool{}
	names := make([]string, 0, len(a.drivers))
	for n := range a.drivers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		in := a.drivers[n]
		seen[n] = true
		switch {
		case in.err != nil:
			out = append(out, protocol.DriverState{Instance: n, State: driver.StateDown, Detail: truncate(in.err.Error(), 200)})
		default:
			hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			h := in.drv.Health(hctx)
			cancel()
			out = append(out, protocol.DriverState{Instance: n, State: h.State, Detail: truncate(h.Detail, 200)})
		}
	}
	if a.mockAll == nil {
		var missing []string
		for _, p := range a.config().Points {
			for _, ref := range []string{p.DriverRef.Instance, mustOpener(a, p)} {
				if ref != "" && !seen[ref] {
					seen[ref] = true
					missing = append(missing, ref)
				}
			}
		}
		sort.Strings(missing)
		for _, m := range missing {
			out = append(out, protocol.DriverState{Instance: m, State: driver.StateMissing, Detail: "not configured in agent.yaml"})
		}
	}
	return out
}

func mustOpener(a *Agent, p protocol.PointConfig) string { i, _ := a.openerFor(p); return i }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// subscribe streams one instance's presentations into the decision pipeline,
// restarting it with backoff if it fails.
func (a *Agent) subscribe(ctx context.Context, in *instance) {
	delay := time.Second
	for ctx.Err() == nil {
		err := in.drv.Subscribe(ctx, a.presentCh)
		switch {
		case errors.Is(err, driver.ErrNoEvents):
			return
		case ctx.Err() != nil:
			return
		}
		a.log.Error("driver subscription ended", "instance", in.name, "error", err, "retry_in", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		delay = min(delay*2, 30*time.Second)
	}
}

// pointFor maps a presentation to a point by (instance, channel).
func (a *Agent) pointFor(instance, channel string) (string, bool) {
	var exact, loose string
	catchAll := a.mockAll != nil && instance == mockInstance
	for _, p := range a.config().Points {
		if !p.Enabled {
			continue
		}
		if !catchAll && p.DriverRef.Instance != instance {
			continue
		}
		switch {
		case p.DriverRef.Channel == channel:
			if exact == "" {
				exact = p.ID
			}
		case p.DriverRef.Channel == "" && loose == "":
			loose = p.ID
		}
	}
	if exact != "" {
		return exact, true
	}
	return loose, loose != ""
}

// presentations is the decision pipeline: one presentation at a time, so a
// barrier is never driven twice at once.
func (a *Agent) presentations(ctx context.Context) {
	for {
		select {
		case p := <-a.presentCh:
			a.decide(ctx, p)
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) decide(ctx context.Context, p driver.Presentation) {
	pid, ok := a.pointFor(p.Instance, p.Channel)
	if !ok {
		a.log.Warn("presentation for a reader that no point uses; ignored", "instance", p.Instance, "channel", p.Channel)
		return
	}
	if _, err := a.eng.Handle(ctx, engine.Presentation{
		PointID: pid, Kind: p.Kind, Value: p.Value, Confidence: p.Confidence, At: p.At, RawRef: p.RawRef, Detail: p.Detail,
	}); err != nil && ctx.Err() == nil {
		a.log.Error("could not record decision", "point_id", pid, "error", err)
	}
}

// ---- hello / heartbeat builders ----

func (a *Agent) clockOffsetPtr() *int64 {
	if !a.offsetKnown.Load() {
		return nil
	}
	v := a.offsetMS.Load()
	return &v
}

func (a *Agent) buildHello(ctx context.Context) (protocol.AgentHello, error) {
	sv, err := a.st.SnapshotVersion(ctx)
	if err != nil {
		return protocol.AgentHello{}, err
	}
	cv, err := a.st.ConfigVersion(ctx)
	if err != nil {
		return protocol.AgentHello{}, err
	}
	q, err := a.st.QueueDepth(ctx)
	if err != nil {
		return protocol.AgentHello{}, err
	}
	return protocol.AgentHello{
		From: "agent", AgentID: a.id.AgentID, AgentVersion: a.o.Version, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		ProtocolVersions: []int{protocol.Version}, SnapshotVersion: sv, ConfigVersion: cv,
		Drivers: a.driverStates(ctx), QueueDepth: q, ClockOffsetMS: a.clockOffsetPtr(),
	}, nil
}

func (a *Agent) buildHeartbeat(ctx context.Context) (protocol.Heartbeat, error) {
	sv, err := a.st.SnapshotVersion(ctx)
	if err != nil {
		return protocol.Heartbeat{}, err
	}
	q, err := a.st.QueueDepth(ctx)
	if err != nil {
		return protocol.Heartbeat{}, err
	}
	dropped, err := a.st.DroppedEvents(ctx)
	if err != nil {
		return protocol.Heartbeat{}, err
	}
	suspect := false
	if a.offsetKnown.Load() {
		off := time.Duration(a.offsetMS.Load()) * time.Millisecond
		suspect = off > clockSuspectAfter || off < -clockSuspectAfter
	}
	states := a.driverStates(ctx)
	if raw, err := json.Marshal(states); err == nil {
		_ = a.st.SetMeta(ctx, store.MetaDriversStatus, string(raw))
	}
	return protocol.Heartbeat{
		SnapshotVersion: sv, QueueDepth: q, DroppedEvents: dropped, UptimeS: int64(a.now().Sub(a.start).Seconds()),
		ClockSuspect: suspect, ClockOffsetMS: a.clockOffsetPtr(), Drivers: states,
	}, nil
}

// StatusInfo is what `status` prints.
type StatusInfo struct {
	Identity        Identity
	Revoked         bool
	SnapshotVersion int64
	ConfigVersion   int64
	Entries         int
	QueueDepth      int64
	DroppedEvents   int64
	LastContact     time.Time
	Timezone        string
	Drivers         []protocol.DriverState
}

// ReadStatus reads the agent's persisted state without running it.
func ReadStatus(ctx context.Context, dir string) (StatusInfo, error) {
	var s StatusInfo
	if IsRevoked(dir) {
		s.Revoked = true
		return s, ErrRevoked
	}
	if _, err := readToken(dir); err != nil {
		return s, err
	}
	id, err := readIdentity(dir)
	if err != nil {
		return s, err
	}
	s.Identity = id
	st, err := store.Open(dir)
	if err != nil {
		return s, err
	}
	defer func() { _ = st.Close() }()
	if s.SnapshotVersion, err = st.SnapshotVersion(ctx); err != nil {
		return s, err
	}
	if s.ConfigVersion, err = st.ConfigVersion(ctx); err != nil {
		return s, err
	}
	if s.Entries, err = st.EntryCount(ctx); err != nil {
		return s, err
	}
	if s.QueueDepth, err = st.QueueDepth(ctx); err != nil {
		return s, err
	}
	s.DroppedEvents, _ = st.DroppedEvents(ctx)
	s.LastContact, _ = st.LastContact(ctx)
	s.Timezone, _ = st.Timezone(ctx)
	if raw, ok, _ := st.GetMeta(ctx, store.MetaDriversStatus); ok {
		_ = json.Unmarshal([]byte(raw), &s.Drivers)
	}
	return s, nil
}
