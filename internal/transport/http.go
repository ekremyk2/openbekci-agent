package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

// Errors of the transport layer.
var (
	// ErrRevoked means the server authenticated the end of this agent's
	// life: it closed the WebSocket with 4401 or sent command revoked. Only
	// this wipes local state.
	ErrRevoked = errors.New("transport: agent revoked by the server")
	// ErrUnauthorized is a bare HTTP 401. A WAF, captive portal, proxy or a
	// server auth-cache miss during a deploy answers it too, so it never
	// wipes anything: the agent is quarantined and retries.
	ErrUnauthorized = errors.New("transport: server answered 401 unauthorized")
	// ErrUpdateRequired means the server closed with 4426: no common protocol
	// version.
	ErrUpdateRequired = errors.New("transport: no common protocol version, agent update required")
	// ErrNotFound is returned by enrolment for an unknown, expired or used token.
	ErrNotFound = errors.New("transport: enrolment token unknown, expired or already used")
)

// RetryAfterError reports a 429/503 answer; Run waits at least After.
type RetryAfterError struct {
	Status int
	After  time.Duration
}

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("transport: server answered %d, retry after %s", e.Status, e.After)
}

// LoadRootCAs returns the system roots plus, when caFile is set, the
// certificates in that PEM file (private CA, design section 8).
func LoadRootCAs(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s: no certificates found", caFile)
		}
	}
	return pool, nil
}

// NewHTTPClient builds the HTTP client used for every call: certificate
// verification is always on (there is no insecure option). The client has no
// overall Timeout (WebSocket dialing requires that); callers use contexts.
func NewHTTPClient(caFile string) (*http.Client, error) {
	pool, err := LoadRootCAs(caFile)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tr.TLSHandshakeTimeout = 10 * time.Second
	return &http.Client{
		Transport: tr,
		// Agent endpoints never redirect. Following one would re-send the
		// bearer token (to a plaintext http:// URL, to another host), so every
		// redirect is refused and surfaces as an unexpected status.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func retryAfter(resp *http.Response) time.Duration {
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
		if t, err := http.ParseTime(s); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return 0
}

// statusError maps a non-2xx answer to the transport's error values.
func statusError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return &RetryAfterError{Status: resp.StatusCode, After: retryAfter(resp)}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("transport: unexpected status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
}

func doJSON(ctx context.Context, hc *http.Client, url, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusNotFound && token == "" {
			return ErrNotFound
		}
		return statusError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// Enrol exchanges a one-time enrolment token for an agent credential. url is
// the full enrolment endpoint.
func Enrol(ctx context.Context, hc *http.Client, url string, req protocol.EnrolRequest) (protocol.EnrolResponse, error) {
	var resp protocol.EnrolResponse
	if err := doJSON(ctx, hc, url, "", req, &resp); err != nil {
		return protocol.EnrolResponse{}, err
	}
	if resp.AgentToken == "" || resp.AgentID == "" {
		return protocol.EnrolResponse{}, errors.New("transport: enrolment response without agent credential")
	}
	return resp, nil
}

// Rotate asks the server for a new agent token (POST .../token:rotate).
func Rotate(ctx context.Context, hc *http.Client, url, currentToken string) (string, error) {
	var resp protocol.RotateResponse
	if err := doJSON(ctx, hc, url, currentToken, struct{}{}, &resp); err != nil {
		return "", err
	}
	if resp.AgentToken == "" {
		return "", errors.New("transport: rotate response without token")
	}
	return resp.AgentToken, nil
}
