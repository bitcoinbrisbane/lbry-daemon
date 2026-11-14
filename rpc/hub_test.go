package rpc

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lbry/daemon/auth"
	"lbry/daemon/wallet"
)

// fakeHub listens on address and answers every request line with reply(). A nil reply makes it accept
// the connection and then stay silent, like a hub address that is down.
func fakeHub(t *testing.T, address string, reply func(line string) string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", address, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil || reply == nil {
					time.Sleep(time.Minute) // silent
					return
				}
				conn.Write([]byte(reply(line) + "\n"))
			}()
		}
	}()
}

func useHubAddresses(t *testing.T, addrs ...string) {
	t.Helper()
	previousLookup, previousCall := lookupHost, hubCallTimeout
	lookupHost = func(string) ([]string, error) { return addrs, nil }
	hubCallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { lookupHost, hubCallTimeout = previousLookup, previousCall })
}

func TestSendJSONSkipsASilentAddress(t *testing.T) {
	fakeHub(t, "127.0.0.2:50001", nil)
	fakeHub(t, "127.0.0.1:50001", func(string) string { return `{"jsonrpc":"2.0","id":1,"result":"ok"}` })
	useHubAddresses(t, "127.0.0.2", "127.0.0.1")

	start := time.Now()
	resp, err := SendJSON("hub.example", 50001, map[string]any{"method": "x"})
	if err != nil || resp["result"] != "ok" {
		t.Fatalf("got %v, %v", resp, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v; the silent address was not given up on", time.Since(start))
	}
}

func TestSendJSONFailsWhenNoAddressAnswers(t *testing.T) {
	fakeHub(t, "127.0.0.2:50001", nil)
	useHubAddresses(t, "127.0.0.2")
	if resp, err := SendJSON("hub.example", 50001, map[string]any{}); err == nil {
		t.Fatalf("expected an error, got %v", resp)
	}
}

func TestSendJSONRejectsAReplyThatIsNotJSON(t *testing.T) {
	fakeHub(t, "127.0.0.1:50001", func(string) string { return "not json" })
	useHubAddresses(t, "127.0.0.1")
	if _, err := SendJSON("hub.example", 50001, map[string]any{}); err == nil {
		t.Fatal("expected an error")
	}
}

func claimSearch(t *testing.T, params map[string]any) (int, map[string]any) {
	t.Helper()
	server := RPCServer{authManager: &auth.AuthManager{}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:40000"
	w := httptest.NewRecorder()
	handleJSONRPCMessageClaimSearch(server, w, req, params)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return w.Code, body
}

func TestClaimSearchEmptyResult(t *testing.T) {
	empty := base64.StdEncoding.EncodeToString(nil)
	fakeHub(t, "127.0.0.1:50001", func(string) string { return `{"jsonrpc":"2.0","id":1,"result":"` + empty + `"}` })
	useHubAddresses(t, "127.0.0.1")

	_, body := claimSearch(t, map[string]any{"page": 3.0, "page_size": 5.0})
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	if items, _ := result["items"].([]any); len(items) != 0 {
		t.Fatalf("items: %v", result["items"])
	}
	if result["page"] != 3.0 || result["page_size"] != 5.0 || result["total_items"] != 0.0 {
		t.Fatalf("pagination not echoed: %v", result)
	}
}

func TestClaimSearchDefaultsToSDKPagination(t *testing.T) {
	empty := base64.StdEncoding.EncodeToString(nil)
	fakeHub(t, "127.0.0.1:50001", func(string) string { return `{"jsonrpc":"2.0","id":1,"result":"` + empty + `"}` })
	useHubAddresses(t, "127.0.0.1")

	_, body := claimSearch(t, map[string]any{})
	result := body["result"].(map[string]any)
	if result["page"] != 1.0 || result["page_size"] != 10.0 {
		t.Fatalf("defaults: %v", result)
	}
}

func TestClaimSearchReportsHubFailures(t *testing.T) {
	cases := map[string]func(string) string{
		"hub error":  func(string) string { return `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"bad query"}}` },
		"not base64": func(string) string { return `{"jsonrpc":"2.0","id":1,"result":"%%%"}` },
		"no result":  func(string) string { return `{"jsonrpc":"2.0","id":1}` },
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			fakeHub(t, "127.0.0.1:50001", reply)
			useHubAddresses(t, "127.0.0.1")
			_, body := claimSearch(t, map[string]any{})
			errBody, ok := body["error"].(map[string]any)
			if !ok || errBody["code"] != 502.0 {
				t.Fatalf("expected a 502 error response, got %v", body)
			}
		})
	}
}

func TestClaimSearchWhenNoHubIsReachable(t *testing.T) {
	fakeHub(t, "127.0.0.2:50001", nil)
	useHubAddresses(t, "127.0.0.2")
	_, body := claimSearch(t, map[string]any{})
	if errBody, ok := body["error"].(map[string]any); !ok || errBody["code"] != 502.0 {
		t.Fatalf("expected a 502 error response, got %v", body)
	}
}

func TestDisplayTxIDReversesWithoutMutating(t *testing.T) {
	wire := []byte{0x01, 0x02, 0x03}
	if got := displayTxID(wire); got != "030201" {
		t.Fatalf("got %s", got)
	}
	if wire[0] != 1 || wire[2] != 3 {
		t.Fatalf("input was modified: %v", wire)
	}
}

func TestConvertSurvivesMissingTransaction(t *testing.T) {
	claim := safeConvertProtobufToClaim(map[int]any{1: []byte{0x01, 0x02, 0x03}}, map[string]any{})
	if claim["txid"] != "030201" || claim["type"] != "claim" {
		t.Fatalf("got %v", claim)
	}
	// A transaction entry of the wrong shape must not panic either.
	claim = safeConvertProtobufToClaim(map[int]any{1: []byte{0x01}}, map[string]any{"01": "nope"})
	if claim["txid"] != "01" {
		t.Fatalf("got %v", claim)
	}
}

func TestHubSearchParamsUseOffsetAndLimit(t *testing.T) {
	got := hubSearchParams(map[string]any{"page": 3.0, "page_size": 5.0, "text": "x"}, 3, 5)
	if got["offset"] != 10.0 || got["limit"] != 5.0 || got["text"] != "x" {
		t.Fatalf("got %v", got)
	}
	if _, has := got["page"]; has {
		t.Fatalf("page should not reach the hub: %v", got)
	}
	if _, has := got["page_size"]; has {
		t.Fatalf("page_size should not reach the hub: %v", got)
	}
}

func TestPaginationCapsPageSizeAtFifty(t *testing.T) {
	if _, size := paginationFrom(map[string]any{"page_size": 500.0}); size != 50 {
		t.Fatalf("got %v", size)
	}
}

type stubHub struct{ err error }

func (h stubHub) Call(method string, params any) (any, error) {
	if h.err != nil {
		return nil, h.err
	}
	if method == "blockchain.scripthash.get_history" {
		return []any{}, nil
	}
	return map[string]any{"confirmed": 0.0, "unconfirmed": 0.0}, nil
}

func walletBalanceServer(t *testing.T, hub wallet.Hub) RPCServer {
	t.Helper()
	dir := t.TempDir()
	raw := `{"name":"My Wallet","accounts":[{"name":"a","public_key":"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"}]}`
	if err := os.WriteFile(filepath.Join(dir, "default_wallet"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := wallet.NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	return RPCServer{authManager: &auth.AuthManager{}, walletManager: manager, hub: hub}
}

func walletBalance(t *testing.T, server RPCServer, params map[string]any) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Host = "localhost:5279" // the auth manager only trusts loopback hosts
	w := httptest.NewRecorder()
	handleJSONRPCMessageWalletBalance(server, w, req, params)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return body
}

func TestWalletBalanceShape(t *testing.T) {
	body := walletBalance(t, walletBalanceServer(t, stubHub{}), map[string]any{})
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	if result["total"] != "0.0" || result["available"] != "0.0" || result["reserved"] != "0.0" {
		t.Fatalf("%v", result)
	}
	if subtotals, _ := result["reserved_subtotals"].(map[string]any); subtotals["claims"] != "0.0" || subtotals["supports"] != "0.0" || subtotals["tips"] != "0.0" {
		t.Fatalf("%v", result)
	}
}

func TestWalletBalanceErrorCodes(t *testing.T) {
	cases := map[string]struct {
		hub    wallet.Hub
		params map[string]any
		code   float64
	}{
		"unknown wallet":     {stubHub{}, map[string]any{"wallet_id": "nope"}, 400},
		"bad wallet_id":      {stubHub{}, map[string]any{"wallet_id": 5.0}, 400},
		"bad confirmations":  {stubHub{}, map[string]any{"confirmations": "x"}, 400},
		"too many":           {stubHub{}, map[string]any{"confirmations": 3.0}, 400},
		"hub failure is 502": {stubHub{err: errors.New("down")}, map[string]any{}, 502},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := walletBalance(t, walletBalanceServer(t, c.hub), c.params)
			if e, ok := body["error"].(map[string]any); !ok || e["code"] != c.code {
				t.Fatalf("got %v", body)
			}
		})
	}
}
