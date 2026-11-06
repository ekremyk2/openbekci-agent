// Package transport connects the agent to the server: an outbound WebSocket
// (subprotocol openbekci.agent.v1) with an HTTPS long-poll fallback, automatic
// reconnect with jittered exponential backoff, and the plain-HTTP enrol and
// rotate calls. It knows envelopes but not their meaning.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Mode names of a Session.
const (
	ModeWebSocket = "websocket"
	ModePoll      = "poll"
)

// Session is one established connection. Send and Ping are safe for
// concurrent use; Receive must be called from one goroutine.
type Session interface {
	Send(ctx context.Context, env protocol.Envelope) error
	Receive(ctx context.Context) (protocol.Envelope, error)
	// Ping checks liveness (WebSocket ping; a no-op for long-poll).
	Ping(ctx context.Context) error
	Mode() string
	// Close ends the session; code is a WebSocket close code (ignored by poll).
	Close(code int, reason string) error
}

// Handler runs one session. Returning ends it; the client reconnects unless the
// error is ErrRevoked or the context is done. ErrUnauthorized makes the client
// wait UnauthorizedRetry and try again.
type Handler func(ctx context.Context, s Session) error

// Options configure a Client.
type Options struct {
	// WSURL is the wss:// (or https://) WebSocket endpoint; PollURL the https
	// long-poll endpoint.
	WSURL, PollURL string
	// Token returns the current agent token; it is called before every
	// connection attempt and request so a rotated token file is picked up.
	Token  func() (string, error)
	CAFile string

	Backoff Backoff
	// HealthyAfter is how long a session must last before the backoff resets
	// (default 60 s).
	HealthyAfter time.Duration
	// ProxyFailures is the number of consecutive proxy-like upgrade failures
	// before dropping to long-poll (default 3).
	ProxyFailures int
	// WSRetry is how often WebSocket is retried while in long-poll mode
	// (default 10 minutes).
	WSRetry time.Duration
	// PollWait is wait_seconds of a long poll (default 25).
	PollWait int

	Log *slog.Logger
	// OnContact is called for every sign that the server is alive and
	// authenticated us: a successful WebSocket ping/pong and every 2xx
	// long-poll answer, including empty ones.
	OnContact func()
	// UnauthorizedRetry is how long to wait after a bare 401 before trying
	// again (default 60 s). The token file is re-read for every attempt.
	UnauthorizedRetry time.Duration
	// OnUnauthorized is told about every bare 401.
	OnUnauthorized func(err error)
	// OnModeChange is told when the client falls back to or leaves long-poll.
	OnModeChange func(mode string)
}

// Client maintains the connection.
type Client struct {
	o  Options
	hc *http.Client
}

// NewClient validates options and builds a client.
func NewClient(o Options) (*Client, error) {
	for _, u := range []struct{ name, v string }{{"WSURL", o.WSURL}, {"PollURL", o.PollURL}} {
		pu, err := url.Parse(u.v)
		if err != nil || pu.Host == "" || (pu.Scheme != "https" && pu.Scheme != "wss") {
			return nil, fmt.Errorf("transport: %s %q must be an https/wss URL", u.name, u.v)
		}
	}
	if o.Token == nil {
		return nil, errors.New("transport: Token required")
	}
	if o.Backoff.Min == 0 {
		o.Backoff = DefaultBackoff()
	}
	if o.HealthyAfter == 0 {
		o.HealthyAfter = 60 * time.Second
	}
	if o.ProxyFailures == 0 {
		o.ProxyFailures = 3
	}
	if o.WSRetry == 0 {
		o.WSRetry = 10 * time.Minute
	}
	if o.PollWait == 0 {
		o.PollWait = 25
	}
	if o.UnauthorizedRetry == 0 {
		o.UnauthorizedRetry = 60 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	hc, err := NewHTTPClient(o.CAFile)
	if err != nil {
		return nil, err
	}
	return &Client{o: o, hc: hc}, nil
}

func (c *Client) contact() {
	if c.o.OnContact != nil {
		c.o.OnContact()
	}
}

// HTTPClient returns the verified-TLS client for plain HTTP calls.
func (c *Client) HTTPClient() *http.Client { return c.hc }

// Run connects, runs h for each session, and reconnects with backoff until ctx
// ends (returning ctx.Err()) or the server revokes the agent (ErrRevoked). A
// bare 401 never ends it: it is reported and retried every UnauthorizedRetry.
func (c *Client) Run(ctx context.Context, h Handler) error {
	var (
		bo        = c.o.Backoff
		proxyFail int
		pollUntil time.Time // while in the future: long-poll mode
		fallback  bool
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		useWS := !time.Now().Before(pollUntil)
		if useWS && fallback {
			c.o.Log.Info("retrying websocket after long-poll period")
		}

		var (
			sess    Session
			err     error
			sctx    = ctx
			release = func() {}
		)
		if useWS {
			sess, err = c.dialWS(ctx)
		} else {
			sctx, release = context.WithDeadline(ctx, pollUntil)
			sess = newPollSession(c, sctx)
		}
		if err != nil {
			release()
			if errors.Is(err, ErrRevoked) {
				return err
			}
			if errors.Is(err, ErrUnauthorized) {
				if !c.unauthorized(ctx, err) {
					return ctx.Err()
				}
				continue
			}
			if isProxyLike(err) {
				proxyFail++
				limit := c.o.ProxyFailures
				if fallback {
					limit = 1 // a single failed probe sends us back to long-poll
				}
				if proxyFail >= limit {
					c.o.Log.Warn("websocket upgrade keeps failing, using long-poll", "error", err, "retry_websocket_in", c.o.WSRetry)
					pollUntil = time.Now().Add(c.o.WSRetry)
					proxyFail = 0
					if !fallback && c.o.OnModeChange != nil {
						c.o.OnModeChange(ModePoll)
					}
					fallback = true
					continue
				}
			}
			if !c.sleep(ctx, c.delay(&bo, err)) {
				return ctx.Err()
			}
			continue
		}

		if useWS {
			proxyFail = 0
			if fallback {
				fallback = false
				if c.o.OnModeChange != nil {
					c.o.OnModeChange(ModeWebSocket)
				}
			}
		}
		start := time.Now()
		herr := h(sctx, sess)
		_ = sess.Close(1000, "")
		release()
		switch {
		case errors.Is(herr, ErrRevoked):
			return herr
		case ctx.Err() != nil:
			return ctx.Err()
		}
		if errors.Is(herr, ErrUnauthorized) {
			if !c.unauthorized(ctx, herr) {
				return ctx.Err()
			}
			continue
		}
		if time.Since(start) >= c.o.HealthyAfter {
			bo.Reset()
		}
		c.o.Log.Info("session ended", "mode", sess.Mode(), "error", herr)
		if !c.sleep(ctx, c.delay(&bo, herr)) {
			return ctx.Err()
		}
	}
}

// unauthorized reports a bare 401 and waits UnauthorizedRetry; false when ctx
// ended first.
func (c *Client) unauthorized(ctx context.Context, err error) bool {
	c.o.Log.Error("server rejected the agent token (HTTP 401); not treating it as revocation, retrying", "retry_in", c.o.UnauthorizedRetry)
	if c.o.OnUnauthorized != nil {
		c.o.OnUnauthorized(err)
	}
	return c.sleep(ctx, c.o.UnauthorizedRetry)
}

// delay is the next backoff, stretched to honour Retry-After.
func (c *Client) delay(bo *Backoff, err error) time.Duration {
	d := bo.Next()
	var ra *RetryAfterError
	if errors.As(err, &ra) && ra.After > d {
		d = ra.After
	}
	if errors.Is(err, errRateLimitedClose) && d < 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) token() (string, error) {
	tok, err := c.o.Token()
	if err != nil {
		return "", fmt.Errorf("transport: read token: %w", err)
	}
	return strings.TrimSpace(tok), nil
}
