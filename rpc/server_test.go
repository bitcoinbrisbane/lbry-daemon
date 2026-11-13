package rpc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lbry/daemon/auth"
	"lbry/daemon/blob"
	"lbry/daemon/settings"
	"lbry/daemon/wallet"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Setenv("ADMIN_USERNAME", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("LBRY_ALLOWED_ORIGIN", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default_wallet"), []byte(`{"name":"Smoke","accounts":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	walletManager, _ := wallet.NewManager(dir)
	server := CreateServer(settings.InitializeConfiguration(), &auth.AuthManager{}, &blob.BlobManager{}, nil, walletManager)
	return server.httpServer.Handler
}

func call(handler http.Handler, remote, host, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://"+host+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"wallet_list","params":{}}`))
	req.RemoteAddr = remote
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestWalletListAuth(t *testing.T) {
	handler := newTestHandler(t)

	rec := call(handler, "127.0.0.1:4000", "localhost:5279", "")
	if !strings.Contains(rec.Body.String(), `"default_wallet"`) || !strings.Contains(rec.Body.String(), `"Smoke"`) {
		t.Errorf("loopback client should list wallets, got %s", rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("no CORS header expected without an Origin, got %q", got)
	}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"remote address": call(handler, "203.0.113.9:4000", "localhost:5279", ""),
		"foreign host":   call(handler, "127.0.0.1:4000", "evil.example:5279", ""),
		"foreign origin": call(handler, "127.0.0.1:4000", "localhost:5279", "https://evil.example"),
	} {
		if strings.Contains(rec.Body.String(), "default_wallet") || !strings.Contains(rec.Body.String(), "Not permitted") {
			t.Errorf("%s should be refused, got %s", name, rec.Body.String())
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
			t.Errorf("%s: wildcard CORS header must not be sent", name)
		}
	}
}
