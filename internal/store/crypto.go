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
)

const keyFile = "store.key"

// sealer encrypts row values with AES-256-GCM and derives a blind index key so
// that encrypted values can still be looked up by equality.
type sealer struct {
	aead     cipher.AEAD
	indexKey []byte
}

// loadOrCreateKey reads dir/store.key (32 random bytes, mode 0600), creating it
// on first use.
func loadOrCreateKey(dir string) (*sealer, error) {
	path := filepath.Join(dir, keyFile)
	key, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: create key: %w", err)
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("store: read key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("store: %s has %d bytes, want 32", path, len(key))
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

func (s *sealer) open(blob []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return nil, errors.New("store: ciphertext too short")
	}
	plain, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("store: decrypt: %w", err)
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
