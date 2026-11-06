package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/openbekci/openbekci-agent/internal/protocol"
)

var errRateLimitedClose = errors.New("transport: server closed the socket: rate limited (4429)")

// upgradeError is a failed WebSocket handshake.
type upgradeError struct {
	status int // 0 when no HTTP answer was received
	err    error
}

func (e *upgradeError) Error() string { return "transport: websocket upgrade: " + e.err.Error() }
func (e *upgradeError) Unwrap() error { return e.err }

// isProxyLike reports whether err looks like a proxy blocking the upgrade: a
// non-101 answer, or a connection reset/EOF before the handshake finished.
// Refused connections and timeouts mean "server down", not "proxy".
func isProxyLike(err error) bool {
	var ue *upgradeError
	if !errors.As(err, &ue) {
		return false
	}
	if ue.status != 0 {
		return true
	}
	s := strings.ToLower(ue.err.Error())
	return errors.Is(ue.err, io.EOF) || errors.Is(ue.err, io.ErrUnexpectedEOF) ||
		strings.Contains(s, "reset by peer") || strings.Contains(s, "connection reset") ||
		strings.Contains(s, "forcibly closed") || strings.Contains(s, "eof")
}

type wsSession struct {
	conn    *websocket.Conn
	log     interface{ Warn(string, ...any) }
	contact func()
}

func (c *Client) dialWS(ctx context.Context) (Session, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dctx, c.o.WSURL, &websocket.DialOptions{
		HTTPClient:      c.hc,
		HTTPHeader:      http.Header{"Authorization": []string{"Bearer " + tok}},
		Subprotocols:    []string{protocol.Subprotocol},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		if resp != nil {
			defer func() { _ = resp.Body.Close() }()
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				return nil, ErrRevoked
			case http.StatusTooManyRequests, http.StatusServiceUnavailable:
				return nil, &RetryAfterError{Status: resp.StatusCode, After: retryAfter(resp)}
			}
			return nil, &upgradeError{status: resp.StatusCode, err: err}
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() || ctx.Err() != nil {
			return nil, err
		}
		return nil, &upgradeError{err: err}
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return nil, fmt.Errorf("transport: server did not select subprotocol %s", protocol.Subprotocol)
	}
	conn.SetReadLimit(protocol.MaxFrameBytes + 4096)
	return &wsSession{conn: conn, log: c.o.Log, contact: c.contact}, nil
}

func (s *wsSession) Mode() string { return ModeWebSocket }

func (s *wsSession) Send(ctx context.Context, env protocol.Envelope) error {
	data, err := env.MarshalJSON()
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxFrameBytes {
		return fmt.Errorf("transport: frame of %d bytes exceeds the 1 MiB limit", len(data))
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.conn.Write(wctx, websocket.MessageText, data)
}

func (s *wsSession) Receive(ctx context.Context) (protocol.Envelope, error) {
	for {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			switch websocket.CloseStatus(err) {
			case protocol.CloseRevoked:
				return protocol.Envelope{}, ErrRevoked
			case protocol.CloseNoCommonVersion:
				return protocol.Envelope{}, ErrUpdateRequired
			case protocol.CloseRateLimited:
				return protocol.Envelope{}, errRateLimitedClose
			}
			return protocol.Envelope{}, err
		}
		if typ != websocket.MessageText {
			s.log.Warn("ignoring non-text websocket frame")
			continue
		}
		env, err := protocol.ParseEnvelope(data)
		if err != nil {
			s.log.Warn("ignoring invalid frame", "error", err)
			continue
		}
		return env, nil
	}
}

// Ping sends a WebSocket ping; the answering pong is proof of contact.
func (s *wsSession) Ping(ctx context.Context) error {
	if err := s.conn.Ping(ctx); err != nil {
		return err
	}
	s.contact()
	return nil
}

func (s *wsSession) Close(code int, reason string) error {
	if code < 1000 {
		code = 1000
	}
	if len(reason) > 100 {
		reason = reason[:100]
	}
	err := s.conn.Close(websocket.StatusCode(code), reason)
	if err != nil && (websocket.CloseStatus(err) != -1 || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}
