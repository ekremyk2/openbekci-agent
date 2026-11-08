package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/openbekci/openbekci-agent/internal/driver"
)

// HTTPChannel configures one relay channel reached over HTTP. Shelly Gen1:
// on_url "http://10.0.0.50/relay/0?turn=on&timer=1" with no off_url (the
// device switches itself off); Gen2: "http://10.0.0.50/rpc/Switch.Set?id=0&on=true&toggle_after=1".
// A generic device gives both on_url and off_url.
type HTTPChannel struct {
	OnURL     string            `json:"on_url"`
	OffURL    string            `json:"off_url,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	TimeoutMS int               `json:"timeout_ms,omitempty"`
}

// HTTPConfig is the http section of the relay driver.
type HTTPConfig struct {
	Channels map[string]HTTPChannel `json:"channels"`
}

type httpSwitch struct {
	chans  map[string]HTTPChannel
	client *http.Client
}

// privateOnly rejects connections to anything but loopback, link-local and
// private (RFC 1918 / ULA) addresses; relays live on the site LAN.
func privateOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("relay: unresolved address %q", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("relay: %s is not a private/LAN address", ip)
}

func newHTTP(cfg HTTPConfig) (*httpSwitch, error) {
	if len(cfg.Channels) == 0 {
		return nil, errors.New("http: no channels")
	}
	for name, c := range cfg.Channels {
		if err := validateURL(c.OnURL); err != nil {
			return nil, fmt.Errorf("http channel %q on_url: %w", name, err)
		}
		if c.OffURL != "" {
			if err := validateURL(c.OffURL); err != nil {
				return nil, fmt.Errorf("http channel %q off_url: %w", name, err)
			}
		}
		switch c.Method {
		case "", http.MethodGet, http.MethodPost, http.MethodPut:
		default:
			return nil, fmt.Errorf("http channel %q: unsupported method %q", name, c.Method)
		}
		if c.TimeoutMS < 0 {
			return nil, fmt.Errorf("http channel %q: negative timeout_ms", name)
		}
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, Control: privateOnly}
	return &httpSwitch{
		chans: cfg.Channels,
		client: &http.Client{Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
			Proxy:             nil, // never route LAN relay traffic through a proxy
		}},
	}, nil
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	return nil
}

func (h *httpSwitch) Channels() []string { return sortedKeys(h.chans) }

func (h *httpSwitch) call(ctx context.Context, c HTTPChannel, target string) error {
	timeout := time.Duration(c.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return err
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("device answered %s", resp.Status)
	}
	return nil
}

func (h *httpSwitch) On(ctx context.Context, ch string) error {
	return h.call(ctx, h.chans[ch], h.chans[ch].OnURL)
}

func (h *httpSwitch) Off(ctx context.Context, ch string) error {
	c := h.chans[ch]
	if c.OffURL == "" {
		return nil // the device resets itself (e.g. Shelly timer=)
	}
	return h.call(ctx, c, c.OffURL)
}

// Health checks TCP reachability of every channel's device (never sends a
// request that could switch a relay).
func (h *httpSwitch) Health(ctx context.Context) driver.Health {
	var down []string
	for _, name := range h.Channels() {
		u, _ := url.Parse(h.chans[name].OnURL)
		host := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			host = net.JoinHostPort(u.Hostname(), port)
		}
		dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		c, err := (&net.Dialer{}).DialContext(dctx, "tcp", host)
		cancel()
		if err != nil {
			down = append(down, name)
			continue
		}
		_ = c.Close()
	}
	switch {
	case len(down) == 0:
		return driver.Health{State: driver.StateOK}
	case len(down) == len(h.chans):
		return driver.Health{State: driver.StateDown, Detail: "relay device unreachable"}
	}
	return driver.Health{State: driver.StateDegraded, Detail: fmt.Sprintf("channels unreachable: %v", down)}
}

func (h *httpSwitch) Close() error {
	h.client.CloseIdleConnections()
	return nil
}
