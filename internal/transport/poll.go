package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Long-poll tunables.
const (
	// sendInterval is the minimum spacing of send requests: everything the
	// agent wants to send in that time (acks above all) goes out in ONE
	// request, which keeps a multi-part snapshot far below the 4 requests per
	// second the server allows.
	sendInterval = 200 * time.Millisecond
	// maxSendBatch bounds the messages and bytes of one coalesced request.
	maxSendBatch = 64
	maxSendBytes = protocol.MaxFrameBytes
	// defaultHoleTimeout is how long a response may be missing from the
	// server's sequence before the session is restarted.
	defaultHoleTimeout = 10 * time.Second
)

var errSequenceHole = errors.New("transport: long-poll response sequence has a hole, restarting the session")

// pollSession emulates a session over POST /v1/agent/poll. Sends are coalesced
// (see sendInterval); once the first message (hello) is out, a background loop
// long-polls for server messages. Several requests are in flight at once, so
// the server numbers every non-empty response (Poll.Seq, from 1 per session)
// and the agent delivers messages in that order: delta N+1 can never overtake
// delta N. A hole that is not filled in time ends the session, and the new
// session's hello resynchronises everything. A session also ends on the first
// transport error, after which the client reconnects with hello.
type pollSession struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc

	in      chan protocol.Envelope
	outbox  chan *sendReq
	holeTTL time.Duration

	mu      sync.Mutex
	started bool
	err     error

	dmu     sync.Mutex // serialises delivery
	next    int64      // next sequence number to deliver
	pending map[int64][]protocol.Envelope
}

type sendReq struct {
	env  protocol.Envelope
	size int
	done chan error
}

func newPollSession(c *Client, parent context.Context) *pollSession {
	ctx, cancel := context.WithCancel(parent)
	p := &pollSession{
		c: c, ctx: ctx, cancel: cancel,
		in:      make(chan protocol.Envelope, 256),
		outbox:  make(chan *sendReq, 256),
		holeTTL: c.o.PollHoleTimeout,
		next:    1,
		pending: map[int64][]protocol.Envelope{},
	}
	if p.holeTTL == 0 {
		p.holeTTL = defaultHoleTimeout
	}
	go p.sender()
	return p
}

func (p *pollSession) Mode() string { return ModePoll }

func (p *pollSession) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.cancel()
}

func (p *pollSession) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *pollSession) exchange(ctx context.Context, msgs []protocol.Envelope, wait int) (protocol.Poll, error) {
	tok, err := p.c.token()
	if err != nil {
		return protocol.Poll{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, time.Duration(wait+20)*time.Second)
	defer cancel()
	if msgs == nil {
		msgs = []protocol.Envelope{}
	}
	var resp protocol.Poll
	if err := doJSON(rctx, p.c.hc, p.c.o.PollURL, tok, protocol.Poll{Messages: msgs, WaitSeconds: wait}, &resp); err != nil {
		return protocol.Poll{}, err
	}
	p.c.contact() // any 2xx answer, even an empty one, is contact
	return resp, nil
}

// accept delivers one response's messages in the server's sequence order.
func (p *pollSession) accept(resp protocol.Poll) {
	if len(resp.Messages) == 0 {
		return
	}
	p.dmu.Lock()
	defer p.dmu.Unlock()
	if resp.Seq == 0 { // a server that does not number responses: arrival order
		p.deliver(resp.Messages)
		return
	}
	if resp.Seq < p.next {
		return // already delivered (duplicate)
	}
	p.pending[resp.Seq] = resp.Messages
	for {
		msgs, ok := p.pending[p.next]
		if !ok {
			break
		}
		delete(p.pending, p.next)
		p.next++
		p.deliver(msgs)
	}
	if len(p.pending) > 0 {
		p.watchHole(p.next)
	}
}

// watchHole restarts the session if sequence number want is still missing
// after holeTTL.
func (p *pollSession) watchHole(want int64) {
	go func() {
		t := time.NewTimer(p.holeTTL)
		defer t.Stop()
		select {
		case <-t.C:
		case <-p.ctx.Done():
			return
		}
		p.dmu.Lock()
		stuck := p.next == want && len(p.pending) > 0
		p.dmu.Unlock()
		if stuck {
			p.c.o.Log.Warn("long-poll response missing from the sequence", "want", want)
			p.fail(fmt.Errorf("%w (missing seq %d)", errSequenceHole, want))
		}
	}()
}

func (p *pollSession) deliver(msgs []protocol.Envelope) {
	for _, m := range msgs {
		if err := m.Validate(); err != nil {
			p.c.o.Log.Warn("ignoring invalid poll message", "error", err)
			continue
		}
		select {
		case p.in <- m:
		case <-p.ctx.Done():
			return
		}
	}
}

// Send queues env for the next coalesced request and waits for its outcome.
func (p *pollSession) Send(ctx context.Context, env protocol.Envelope) error {
	if err := p.failure(); err != nil {
		return err
	}
	data, err := env.MarshalJSON()
	if err != nil {
		return err
	}
	r := &sendReq{env: env, size: len(data), done: make(chan error, 1)}
	select {
	case p.outbox <- r:
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return p.sessionErr()
	}
	select {
	case err := <-r.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return p.sessionErr()
	}
}

func (p *pollSession) sessionErr() error {
	if err := p.failure(); err != nil {
		return err
	}
	return errors.New("transport: poll session ended")
}

// sender is the single goroutine that posts messages: at most one request per
// sendInterval, carrying everything queued meanwhile. The first request (hello)
// goes out at once and starts the long-poll loop when it succeeds.
func (p *pollSession) sender() {
	var last time.Time
	for {
		var first *sendReq
		select {
		case first = <-p.outbox:
		case <-p.ctx.Done():
			return
		}
		if wait := sendInterval - time.Since(last); !last.IsZero() && wait > 0 {
			select {
			case <-time.After(wait):
			case <-p.ctx.Done():
				first.done <- p.sessionErr()
				return
			}
		}
		batch, size := []*sendReq{first}, first.size
	drain:
		for len(batch) < maxSendBatch {
			select {
			case r := <-p.outbox:
				if size+r.size > maxSendBytes {
					p.requeue(r) // it leads the next request
					break drain
				}
				batch, size = append(batch, r), size+r.size
			default:
				break drain
			}
		}
		msgs := make([]protocol.Envelope, len(batch))
		for i, r := range batch {
			msgs[i] = r.env
		}
		resp, err := p.exchange(p.ctx, msgs, 0)
		last = time.Now()
		if err != nil {
			if p.ctx.Err() == nil {
				p.fail(err)
			}
			for _, r := range batch {
				r.done <- err
			}
			continue
		}
		p.accept(resp)
		p.startLoop()
		for _, r := range batch {
			r.done <- nil
		}
	}
}

func (p *pollSession) requeue(r *sendReq) {
	select {
	case p.outbox <- r:
	default:
		r.done <- errors.New("transport: poll outbox full")
	}
}

func (p *pollSession) startLoop() {
	p.mu.Lock()
	start := !p.started
	p.started = true
	p.mu.Unlock()
	if start {
		go p.loop()
	}
}

func (p *pollSession) loop() {
	for p.ctx.Err() == nil {
		began := time.Now()
		resp, err := p.exchange(p.ctx, nil, p.c.o.PollWait)
		if err != nil {
			if p.ctx.Err() == nil {
				p.fail(err)
			}
			return
		}
		p.accept(resp)
		// Do not hammer a server that answers empty polls immediately
		// (poll limit is 4/s per agent).
		if len(resp.Messages) == 0 && time.Since(began) < time.Second {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-p.ctx.Done():
			}
		}
	}
}

func (p *pollSession) Receive(ctx context.Context) (protocol.Envelope, error) {
	select {
	case m := <-p.in:
		return m, nil
	default:
	}
	select {
	case m := <-p.in:
		return m, nil
	case <-ctx.Done():
		return protocol.Envelope{}, ctx.Err()
	case <-p.ctx.Done():
		return protocol.Envelope{}, p.sessionErr()
	}
}

// Ping is a no-op: a long poll session's liveness is its next response.
func (p *pollSession) Ping(context.Context) error { return p.failure() }

func (p *pollSession) Close(int, string) error {
	p.cancel()
	return nil
}
