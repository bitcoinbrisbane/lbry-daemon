package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func request(remote, host, origin string) *http.Request {
	req := httptest.NewRequest("POST", "http://"+host+"/", nil)
	req.RemoteAddr = remote
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestLoopbackIsAdmin(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("LBRY_ALLOWED_ORIGIN", "")
	manager := &AuthManager{}
	for _, tc := range []struct {
		name, remote, host, origin string
		want                       bool
	}{
		{"ipv4 loopback", "127.0.0.1:5000", "localhost:5279", "", true},
		{"ipv6 loopback", "[::1]:5000", "[::1]:5279", "", true},
		{"loopback ip host", "127.0.0.1:5000", "127.0.0.1:5279", "", true},
		{"remote address", "192.168.1.5:5000", "localhost:5279", "", false},
		{"dns rebinding host", "127.0.0.1:5000", "evil.example:5279", "", false},
		{"browser origin not allowed", "127.0.0.1:5000", "localhost:5279", "https://evil.example", false},
	} {
		if _, ok := manager.ValidateAdminUser(request(tc.remote, tc.host, tc.origin)); ok != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, ok, tc.want)
		}
	}
}

func TestAllowedOrigin(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "")
	t.Setenv("LBRY_ALLOWED_ORIGIN", "http://localhost:1337")
	manager := &AuthManager{}
	if _, ok := manager.ValidateAdminUser(request("127.0.0.1:5000", "localhost:5279", "http://localhost:1337")); !ok {
		t.Error("configured origin should be allowed")
	}
	if _, ok := manager.ValidateAdminUser(request("127.0.0.1:5000", "localhost:5279", "http://other")); ok {
		t.Error("other origin should be rejected")
	}
}

func TestBasicAuth(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "admin")
	t.Setenv("ADMIN_PASSWORD", "s3cret")
	manager := &AuthManager{}
	remote := request("203.0.113.9:4000", "node.example:5279", "")
	if _, ok := manager.ValidateAdminUser(remote); ok {
		t.Error("remote without credentials must be rejected")
	}
	remote.SetBasicAuth("admin", "wrong")
	if _, ok := manager.ValidateAdminUser(remote); ok {
		t.Error("wrong password must be rejected")
	}
	remote.SetBasicAuth("admin", "s3cret")
	if _, ok := manager.ValidateAdminUser(remote); !ok {
		t.Error("right credentials must be accepted from any address")
	}
}

func TestEmptyCredentialsNeverMatch(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "")
	t.Setenv("ADMIN_PASSWORD", "")
	manager := &AuthManager{}
	remote := request("203.0.113.9:4000", "node.example:5279", "")
	remote.SetBasicAuth("", "")
	if _, ok := manager.ValidateAdminUser(remote); ok {
		t.Error("empty configured credentials must not authenticate")
	}
}
