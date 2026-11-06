package transport

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// A redirect (same host https to http, or to another host) must never carry
// the bearer token anywhere.
func TestRedirectsAreRefusedAndTokenNeverResent(t *testing.T) {
	var leaked atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/v1/agent/token:rotate", http.StatusTemporaryRedirect)
	}))
	defer tlsSrv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	hc, err := NewHTTPClient(caFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Rotate(context.Background(), hc, tlsSrv.URL+"/v1/agent/token:rotate", "obk_agt_secret")
	if err == nil {
		t.Fatal("a redirect must be an error")
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("the redirect target received %d request(s): the bearer token was re-sent", n)
	}
}
