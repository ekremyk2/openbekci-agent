// Package agent wires the protocol, transport, store, engine and drivers into
// the running on-site agent, and implements enrolment, token rotation and the
// revocation wipe.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openbekci/openbekci-agent/internal/fsutil"
	"github.com/openbekci/openbekci-agent/internal/store"
)

// State directory file names.
const (
	TokenFile    = "agent.token"
	IdentityFile = "identity.json"
	RevokedFile  = "revoked"
)

// Errors.
var (
	// ErrNotEnrolled means the state directory holds no agent token.
	ErrNotEnrolled = errors.New("agent is not enrolled: run `openbekci-agent enrol` first")
	// ErrRevoked means the server revoked this agent; its state was wiped and it
	// must be enrolled again.
	ErrRevoked = errors.New("agent was revoked by the server: local state wiped, enrol again with a new token")
)

// Identity is what enrolment learned about this agent (no secrets).
type Identity struct {
	AgentID    string    `json:"agent_id"`
	OrgID      string    `json:"org_id"`
	SiteID     string    `json:"site_id"`
	WSURL      string    `json:"ws_url"`
	PollURL    string    `json:"poll_url"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// RotateURL is the token rotation endpoint on the poll URL's origin.
func (i Identity) RotateURL() (string, error) {
	u, err := url.Parse(i.PollURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid poll_url %q", i.PollURL)
	}
	return u.Scheme + "://" + u.Host + "/v1/agent/token:rotate", nil
}

func readToken(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, TokenFile))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotEnrolled
	}
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", ErrNotEnrolled
	}
	return tok, nil
}

func writeToken(dir, token string) error {
	return fsutil.WriteFileAtomic(filepath.Join(dir, TokenFile), []byte(token+"\n"), 0o600)
}

func readIdentity(dir string) (Identity, error) {
	var id Identity
	b, err := os.ReadFile(filepath.Join(dir, IdentityFile))
	if errors.Is(err, fs.ErrNotExist) {
		return id, ErrNotEnrolled
	}
	if err != nil {
		return id, err
	}
	return id, json.Unmarshal(b, &id)
}

func writeIdentity(dir string, id Identity) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, IdentityFile), b, 0o600)
}

// IsRevoked reports whether the state directory carries the revoked marker.
func IsRevoked(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, RevokedFile))
	return err == nil
}

// WipeState deletes the allow-list, queue, config and token (design 4.11) and
// leaves a marker so the agent refuses to start until re-enrolled. The store
// must be closed first.
func WipeState(dir string) error {
	var errs []error
	for _, name := range []string{store.DBFile, store.DBFile + "-wal", store.DBFile + "-shm", "store.key", TokenFile, IdentityFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	// Leftovers of a crashed atomic write still hold a token or identity.
	for _, pat := range []string{TokenFile + ".tmp-*", IdentityFile + ".tmp-*", "store.key.tmp-*"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, m := range matches {
			if err := os.Remove(m); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	marker := []byte(time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(filepath.Join(dir, RevokedFile), marker, 0o600); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
