package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openbekci/openbekci-agent/internal/fsutil"
)

const keyFile = "store.key"

// sealer encrypts row values with AES-256-GCM and derives a blind index key so
// that encrypted values can still be looked up by equality.
type sealer struct {
	aead     cipher.AEAD
	indexKey []byte
}

// ErrKeyUnusable means store.key is missing (while a database exists), empty,
// truncated or unreadable. It is fatal on purpose: silently creating a new key
// would make every encrypted plate and queued event undecryptable.
var ErrKeyUnusable = errors.New("store: encryption key unusable")

func keyProblem(path, what string) error {
	return fmt.Errorf("%w: %s %s, so the encrypted allow-list and event queue in this state directory cannot be read. "+
		"The agent refuses to create a new key because that would silently discard them. Recovery: restore store.key from a backup; "+
		"if there is none, stop the agent, delete store.db, store.db-wal, store.db-shm and store.key from %s and run `openbekci-agent enrol` "+
		"with a new enrolment token (queued events are lost; the allow-list is re-synced from the server)",
		ErrKeyUnusable, path, what, filepath.Dir(path))
}

// loadOrCreateKey reads dir/store.key (32 random bytes, owner-only). A key is
// created only for a brand-new store (no database yet), atomically (temp file,
// fsync, rename), so a crash cannot leave a 0-byte key behind.
func loadOrCreateKey(dir string) (*sealer, error) {
	path := filepath.Join(dir, keyFile)
	key, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if fi, serr := os.Stat(filepath.Join(dir, DBFile)); serr == nil && fi.Size() > 0 {
			return nil, keyProblem(path, "is missing")
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(path, key, 0o600); err != nil {
			return nil, fmt.Errorf("store: create key: %w", err)
		}
	case err != nil:
		return nil, keyProblem(path, "cannot be read ("+err.Error()+")")
	case len(key) != 32:
		return nil, keyProblem(path, fmt.Sprintf("has %d bytes instead of 32", len(key)))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("openbekci-agent/blind-index/v1"))
	return &sealer{aead: aead, indexKey: mac.Sum(nil)}, nil
}

// seal returns nonce||ciphertext; aad binds the ciphertext to its row.
func (s *sealer) seal(plain []byte, aad string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

// ErrCorrupt marks a row that cannot be decrypted or parsed.
var ErrCorrupt = errors.New("store: corrupt record")

func (s *sealer) open(blob []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrCorrupt)
	}
	plain, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt: %w", ErrCorrupt, err)
	}
	return plain, nil
}

// index returns the deterministic blind index of (kind, value).
func (s *sealer) index(kind, value string) []byte {
	mac := hmac.New(sha256.New, s.indexKey)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
