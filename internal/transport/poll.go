package transport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// pollSession emulates a session over POST /v1/agent/poll. Every Send is posted
// at once (wait_seconds 0); once the first message (hello) is out, a background
// loop long-polls for server messages. A session ends on the first transport
// error, after which the client reconnects and starts a new session with hello.
type pollSession struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc

	in chan protocol.Envelope

	mu      sync.Mutex
	started bool
	err     error
}

func newPollSession(c *Client, parent context.Context) *pollSession {
	ctx, cancel := context.WithCancel(parent)
	return &pollSession{c: c, ctx: ctx, cancel: cancel, in: make(chan protocol.Envelope, 256)}
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

func (p *pollSession) exchange(ctx context.Context, msgs []protocol.Envelope, wait int) ([]protocol.Envelope, error) {
	tok, err := p.c.token()
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, time.Duration(wait+20)*time.Second)
	defer cancel()
	if msgs == nil {
		msgs = []protocol.Envelope{}
	}
	var resp protocol.Poll
	if err := doJSON(rctx, p.c.hc, p.c.o.PollURL, tok, protocol.Poll{Messages: msgs, WaitSeconds: wait}, &resp); err != nil {
		return nil, err
	}
	return resp.Messages, nil
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

func (p *pollSession) Send(ctx context.Context, env protocol.Envelope) error {
	if err := p.failure(); err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	msgs, err := p.exchange(sctx, []protocol.Envelope{env}, 0)
	if err != nil {
		if p.ctx.Err() == nil && ctx.Err() == nil {
			p.fail(err)
		}
		return err
	}
	p.deliver(msgs)
	p.mu.Lock()
	start := !p.started
	p.started = true
	p.mu.Unlock()
	if start {
		go p.loop()
	}
	return nil
}

func (p *pollSession) loop() {
	for p.ctx.Err() == nil {
		began := time.Now()
		msgs, err := p.exchange(p.ctx, nil, p.c.o.PollWait)
		if err != nil {
			if p.ctx.Err() == nil {
				p.fail(err)
			}
			return
		}
		p.deliver(msgs)
		// Do not hammer a server that answers empty polls immediately
		// (poll limit is 4/s per agent).
		if len(msgs) == 0 && time.Since(began) < time.Second {
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
		if err := p.failure(); err != nil {
			return protocol.Envelope{}, err
		}
		return protocol.Envelope{}, errors.New("transport: poll session ended")
	}
}

// Ping is a no-op: a long poll session's liveness is its next response.
func (p *pollSession) Ping(context.Context) error { return p.failure() }

func (p *pollSession) Close(int, string) error {
	p.cancel()
	return nil
}
