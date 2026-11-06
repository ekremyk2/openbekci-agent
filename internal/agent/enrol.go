package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/fsutil"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/store"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

// EnrolOptions are the inputs of Enrol.
type EnrolOptions struct {
	Server string // base URL, https
	Token  string // obk_enr_...
	// Org and Site select the org/site-scoped endpoint
	// (POST /v1/orgs/{org}/sites/{site}/agents:enrol). When both are empty the
	// flat endpoint POST /v1/agent/enrol is used, where the token alone
	// identifies the site.
	Org, Site string
	Version   string
}

// EnrolURL builds the enrolment endpoint.
func (o EnrolOptions) EnrolURL() (string, error) {
	if err := config.ValidateServerURL(o.Server); err != nil {
		return "", err
	}
	base := strings.TrimRight(o.Server, "/")
	switch {
	case o.Org == "" && o.Site == "":
		return base + "/v1/agent/enrol", nil
	case o.Org != "" && o.Site != "":
		return base + "/v1/orgs/" + url.PathEscape(o.Org) + "/sites/" + url.PathEscape(o.Site) + "/agents:enrol", nil
	}
	return "", errors.New("--org and --site must be given together")
}

// Enrol exchanges the one-time token for an agent credential and stores it in
// cfg.StateDir (token file mode 0600, written before success is reported). Any
// previous state of the directory is discarded: a new enrolment is a new agent.
func Enrol(ctx context.Context, cfg *config.Config, o EnrolOptions) (Identity, error) {
	if !strings.HasPrefix(o.Token, "obk_enr_") {
		return Identity{}, errors.New("enrolment token must start with obk_enr_")
	}
	endpoint, err := o.EnrolURL()
	if err != nil {
		return Identity{}, err
	}
	hc, err := transport.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return Identity{}, err
	}
	host, _ := os.Hostname()
	ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := transport.Enrol(ectx, hc, endpoint, protocol.EnrolRequest{
		EnrolmentToken: o.Token, Hostname: host, Platform: runtime.GOOS + "/" + runtime.GOARCH, AgentVersion: o.Version,
	})
	if err != nil {
		return Identity{}, fmt.Errorf("enrol: %w", err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return Identity{}, err
	}
	if err := fsutil.SecureDir(cfg.StateDir); err != nil {
		return Identity{}, err
	}
	// Start from an empty store: stale allow-list or queue belong to a former
	// agent. The key file may stay.
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = st.Close() }()
	if err := st.Wipe(ctx); err != nil {
		return Identity{}, err
	}
	id := Identity{AgentID: resp.AgentID, OrgID: resp.OrgID, SiteID: resp.SiteID, WSURL: resp.WSURL, PollURL: resp.PollURL, EnrolledAt: time.Now().UTC()}
	if err := writeIdentity(cfg.StateDir, id); err != nil {
		return Identity{}, err
	}
	if err := st.SetLastContact(ctx, time.Now()); err != nil {
		return Identity{}, err
	}
	// The token goes to disk last: its presence means "enrolled".
	if err := writeToken(cfg.StateDir, resp.AgentToken); err != nil {
		return Identity{}, err
	}
	if err := os.Remove(filepath.Join(cfg.StateDir, RevokedFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Identity{}, err
	}
	return id, nil
}

// RotateToken asks the server for a new token and replaces the token file
// atomically. A running service re-reads the file on its next connection, and
// the server keeps the old token valid for 10 minutes.
func RotateToken(ctx context.Context, cfg *config.Config) error {
	tok, err := readToken(cfg.StateDir)
	if err != nil {
		return err
	}
	id, err := readIdentity(cfg.StateDir)
	if err != nil {
		return err
	}
	hc, err := transport.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return err
	}
	return rotate(ctx, hc, cfg.StateDir, id, tok)
}

func rotate(ctx context.Context, hc *http.Client, dir string, id Identity, tok string) error {
	url, err := id.RotateURL()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	next, err := transport.Rotate(rctx, hc, url, tok)
	if err != nil {
		return err
	}
	// Temp file, fsync, rename: a crash between the server answer and the
	// rename leaves the old token, which the server still accepts for 10 minutes.
	return writeToken(dir, next)
}
