package auth

import "crypto/subtle"
import "net"
import "net/http"
import "os"
import "strings"

type AuthManager struct {
	Users []User
}

type User struct {
}

func (authManager *AuthManager) WantsRPCAuthentication() bool {
	return true
}

func (authManager *AuthManager) IsAdminUser(username string, password string) bool {
	adminUsername, adminPassword := getAdminUsername(), getAdminPassword()
	if adminUsername == "" || adminPassword == "" {
		return false // never accept empty credentials
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(adminUsername))
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(adminPassword))
	return userOK&passOK == 1
}

// func (authManager *AuthManager) ValidateUnauthenticatedUser() {
// 	return true // TODO: Make only true when dangerous endpoints should be freely accessible
// }

func (authManager *AuthManager) ValidateGuest(req *http.Request) (*User, bool) {
	return nil, true
}

func (authManager *AuthManager) ValidateUser(req *http.Request) (*User, bool) {
	return authManager.ValidateAdminUser(req)
}

// ValidateAdminUser decides whether a request may use the wallet and file
// methods. The daemon has no user accounts, so "user" and "admin" are the same.
//
//   - A request with the right ADMIN_USERNAME / ADMIN_PASSWORD (HTTP basic
//     auth) is admin, from any address.
//   - Otherwise only a request from a loopback address is admin, and only if its
//     Host header names a loopback host (stops DNS rebinding) and any Origin
//     header is the configured allowed origin (stops other web pages).
func (authManager *AuthManager) ValidateAdminUser(req *http.Request) (*User, bool) {
	username, password, hasBasic := req.BasicAuth()
	if hasBasic && authManager.IsAdminUser(username, password) {
		return &User{}, true
	}
	if isLoopbackAddress(req.RemoteAddr) && isLoopbackHost(req.Host) && authManager.IsOriginAllowed(req.Header.Get("Origin")) {
		return &User{}, true
	}
	return nil, false
}

// IsOriginAllowed reports whether a browser Origin may call the API. A request
// without an Origin header (curl, the Electron main process) is allowed. The
// allowed origin comes from LBRY_ALLOWED_ORIGIN; "*" allows every origin.
func (authManager *AuthManager) IsOriginAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	allowed := os.Getenv("LBRY_ALLOWED_ORIGIN")
	return allowed != "" && (allowed == "*" || allowed == origin)
}

func isLoopbackAddress(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackHost(hostHeader string) bool {
	host, _, err := net.SplitHostPort(hostHeader)
	if err != nil {
		host = strings.Trim(hostHeader, "[]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getAdminUsername() string {
	return os.Getenv("ADMIN_USERNAME")
}

func getAdminPassword() string {
	return os.Getenv("ADMIN_PASSWORD")
}
