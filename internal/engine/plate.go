// Package engine is the local decision engine: it decides allow/deny for a
// credential presentation from the allow-list alone, using the agent's own
// clock and the site timezone, and turns every decision into a queued event.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// turkish maps Turkish letters to their Latin base (design section 7.4).
var turkish = strings.NewReplacer(
	"İ", "I", "ı", "I", "Ş", "S", "ş", "S", "Ç", "C", "ç", "C",
	"Ğ", "G", "ğ", "G", "Ö", "O", "ö", "O", "Ü", "U", "ü", "U",
)

// NormalizePlate is the single plate normalization function shared with the
// server: Unicode NFKC, Turkish letters to Latin, ASCII upper-case, then
// everything except A-Z and 0-9 removed. The empty result means "invalid".
func NormalizePlate(s string) string {
	s = norm.NFKC.String(s)
	s = turkish.Replace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// QRPrefix is the visitor QR token prefix.
const QRPrefix = "obk1."

// QRValue converts a scanned visitor QR string ("obk1.<token>") to the
// credential value: hex(sha256(token)). ok is false for other shapes.
func QRValue(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	token, found := strings.CutPrefix(raw, QRPrefix)
	if !found || token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), true
}

// confusable lists the OCR-confusable character pairs of tolerant matching.
var confusable = map[[2]byte]bool{}

func init() {
	for _, p := range []string{"O0", "I1", "B8", "S5", "Z2", "G6"} {
		confusable[[2]byte{p[0], p[1]}] = true
		confusable[[2]byte{p[1], p[0]}] = true
	}
}

// ocrNeighbour reports whether a and b have equal length and differ in exactly
// one position whose two characters are a known OCR confusable pair.
func ocrNeighbour(a, b string) bool {
	if len(a) != len(b) || a == b {
		return false
	}
	diff := 0
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		diff++
		if diff > 1 || !confusable[[2]byte{a[i], b[i]}] {
			return false
		}
	}
	return diff == 1
}
