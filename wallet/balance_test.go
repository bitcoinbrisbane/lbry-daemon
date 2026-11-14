package wallet

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

type fakeHub struct {
	mu        sync.Mutex
	history   map[string]int     // scripthash -> number of history entries
	confirmed map[string]float64 // scripthash -> dewies
	pending   map[string]float64
	fail      error
	calls     int
}

func (h *fakeHub) Call(method string, params any) (any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if h.fail != nil {
		return nil, h.fail
	}
	scripthash := params.([]any)[0].(string)
	switch method {
	case "blockchain.scripthash.get_history":
		out := make([]any, h.history[scripthash])
		for i := range out {
			out[i] = map[string]any{"tx_hash": "00", "height": 1.0}
		}
		return out, nil
	case "blockchain.scripthash.get_balance":
		return map[string]any{"confirmed": h.confirmed[scripthash], "unconfirmed": h.pending[scripthash]}, nil
	}
	return nil, fmt.Errorf("unexpected method %s", method)
}

func newFakeHub() *fakeHub {
	return &fakeHub{history: map[string]int{}, confirmed: map[string]float64{}, pending: map[string]float64{}}
}

// fund gives the address at chain/index a balance and a history.
func (h *fakeHub) fund(t *testing.T, chain, index uint32, confirmed, pending float64) {
	t.Helper()
	list, err := DeriveAddresses(bipXpub0H, chain, index, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.history[list[0].ScriptHash] = 2
	h.confirmed[list[0].ScriptHash] = confirmed
	h.pending[list[0].ScriptHash] = pending
}

func balanceManager(t *testing.T) *WalletManager {
	dir := t.TempDir()
	writeWallet(t, dir, "default_wallet", walletFile{Name: "My Wallet", Accounts: []account{{Name: "a", PublicKey: bipXpub0H}}})
	writeWallet(t, dir, "locked", walletFile{Name: "Locked", Accounts: []account{{
		Name: "enc", Encrypted: true, PublicKey: bipXpub0H, Seed: aesEncrypt("pw", "seed", testIV), PrivateKey: aesEncrypt("pw", "key", testIV),
	}}})
	writeWallet(t, dir, "empty", walletFile{Name: "No accounts"})
	manager, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestBalanceEmptyWallet(t *testing.T) {
	hub := newFakeHub()
	balance, err := balanceManager(t).Balance(nil, hub, "", 0)
	if err != nil || balance != (Balance{}) {
		t.Fatalf("%+v %v", balance, err)
	}
	// With no used address, one batch per chain is enough: 20 receiving + 6 change history lookups.
	if hub.calls != DefaultReceivingGap+DefaultChangeGap {
		t.Fatalf("expected %d hub calls, got %d", DefaultReceivingGap+DefaultChangeGap, hub.calls)
	}
}

func TestBalanceSumsBothChains(t *testing.T) {
	hub := newFakeHub()
	hub.fund(t, ReceivingChain, 0, 150000000, 0)
	hub.fund(t, ReceivingChain, 3, 25000000, 5000000)
	hub.fund(t, ChangeChain, 1, 1, 0)
	manager := balanceManager(t)

	balance, err := manager.Balance(nil, hub, "default_wallet", 0)
	if err != nil || balance.Total != 150000000+25000000+5000000+1 || balance.Available != balance.Total || balance.Reserved != 0 {
		t.Fatalf("%+v %v", balance, err)
	}
	confirmedOnly, err := manager.Balance(nil, hub, "default_wallet", 1)
	if err != nil || confirmedOnly.Total != 150000000+25000000+1 {
		t.Fatalf("%+v %v", confirmedOnly, err)
	}
}

func TestBalanceWorksOnALockedWallet(t *testing.T) {
	hub := newFakeHub()
	hub.fund(t, ReceivingChain, 0, 100, 0)
	if balance, err := balanceManager(t).Balance(nil, hub, "locked", 0); err != nil || balance.Total != 100 {
		t.Fatalf("%+v %v", balance, err)
	}
}

func TestBalanceKeepsScanningPastTheGap(t *testing.T) {
	hub := newFakeHub()
	hub.fund(t, ReceivingChain, 15, 10, 0)
	hub.fund(t, ReceivingChain, 34, 20, 0) // found because 15 pushes the scan into a second, then third batch
	hub.fund(t, ReceivingChain, 80, 40, 0) // 45+ addresses after the last used one: beyond the gap, not found
	balance, err := balanceManager(t).Balance(nil, hub, "", 0)
	if err != nil || balance.Total != 30 {
		t.Fatalf("%+v %v", balance, err)
	}
}

func TestBalanceErrors(t *testing.T) {
	manager := balanceManager(t)
	if _, err := manager.Balance(nil, newFakeHub(), "missing", 0); !errors.Is(err, ErrWalletNotFound) {
		t.Fatalf("unknown wallet: %v", err)
	}
	for _, confirmations := range []int{2, 6, -1} {
		if _, err := manager.Balance(nil, newFakeHub(), "", confirmations); !errors.Is(err, ErrUnsupportedConfirmations) {
			t.Fatalf("confirmations %d: %v", confirmations, err)
		}
	}
	hub := newFakeHub()
	hub.fail = errors.New("hub down")
	if balance, err := manager.Balance(nil, hub, "", 0); err == nil {
		t.Fatalf("a hub failure must not become a zero balance: %+v", balance)
	}
	if balance, err := manager.Balance(nil, newFakeHub(), "empty", 0); err != nil || balance != (Balance{}) {
		t.Fatalf("wallet without accounts: %+v %v", balance, err)
	}
}

func TestFormatLBC(t *testing.T) {
	for dewies, want := range map[int64]string{
		0: "0.0", 1: "0.00000001", 100000000: "1.0", 150000000: "1.5", 123456789: "1.23456789",
		1000000000000: "10000.0", -50000000: "-0.5",
	} {
		if got := FormatLBC(dewies); got != want {
			t.Errorf("FormatLBC(%d) = %s, want %s", dewies, got, want)
		}
	}
}
