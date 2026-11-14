package wallet

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"lbry/daemon/auth"
)

// Hub is a wallet-server connection: one JSON-RPC call, returning the decoded "result".
type Hub interface {
	Call(method string, params any) (any, error)
}

var (
	// ErrWalletNotFound is returned for a wallet id that is not loaded.
	ErrWalletNotFound = errors.New("wallet does not exist")
	// ErrUnsupportedConfirmations is returned for a confirmations value the hub cannot answer.
	ErrUnsupportedConfirmations = errors.New("confirmations above 1 are not supported yet")
)

// Balance is an amount in dewies (1 LBC = 100,000,000 dewies).
//
// Reserved (value locked in claims, supports and tips) is not worked out yet, so it is always zero
// and Available equals Total. That overstates what can be spent by the amount held in claims.
type Balance struct {
	Total     int64
	Available int64
	Reserved  int64
}

const (
	// maxAddressesPerChain bounds the gap scan, so a hub that reports every address as used cannot
	// make one request run forever.
	maxAddressesPerChain = 2000
	// hubParallelism limits concurrent hub calls from one balance request.
	hubParallelism = 8
)

// Balance adds up the wallet's addresses with the hub. confirmations is 0 to include unconfirmed
// transactions or 1 for confirmed ones only (lbry-sdk's wallet_balance default is 0). It only needs
// public keys, so it works on a locked wallet.
func (walletManager *WalletManager) Balance(user *auth.User, hub Hub, id string, confirmations int) (Balance, error) {
	if confirmations < 0 || confirmations > 1 {
		return Balance{}, ErrUnsupportedConfirmations
	}
	walletManager.mutex.Lock()
	wallet := walletManager.resolve(id)
	var xpubs []string
	if wallet != nil {
		for _, account := range wallet.accounts {
			if account.PublicKey != "" {
				xpubs = append(xpubs, account.PublicKey)
			}
		}
	}
	walletManager.mutex.Unlock()
	if id != "" && wallet == nil {
		return Balance{}, ErrWalletNotFound
	}

	var total int64
	for _, xpub := range xpubs {
		for _, chain := range []uint32{ReceivingChain, ChangeChain} {
			gap := DefaultReceivingGap
			if chain == ChangeChain {
				gap = DefaultChangeGap
			}
			amount, err := scanChain(hub, xpub, chain, gap, confirmations)
			if err != nil {
				return Balance{}, err
			}
			total += amount
		}
	}
	return Balance{Total: total, Available: total}, nil
}

// scanChain sums a chain's balance, extending the scan until `gap` addresses in a row have no history.
func scanChain(hub Hub, xpub string, chain uint32, gap int, confirmations int) (int64, error) {
	var sum int64
	lastUsed := -1
	for start := 0; start < maxAddressesPerChain; start += gap {
		addresses, err := DeriveAddresses(xpub, chain, uint32(start), gap)
		if err != nil {
			return 0, err
		}
		results, err := queryAddresses(hub, addresses, confirmations)
		if err != nil {
			return 0, err
		}
		for i, result := range results {
			sum += result.amount
			if result.used {
				lastUsed = start + i
			}
		}
		if start+gap-1-lastUsed >= gap {
			break
		}
	}
	return sum, nil
}

type addressResult struct {
	amount int64
	used   bool
}

func queryAddresses(hub Hub, addresses []Address, confirmations int) ([]addressResult, error) {
	results := make([]addressResult, len(addresses))
	errs := make([]error, len(addresses))
	var wg sync.WaitGroup
	slots := make(chan struct{}, hubParallelism)
	for i := range addresses {
		wg.Add(1)
		slots <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-slots }()
			results[i], errs[i] = queryAddress(hub, addresses[i], confirmations)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func queryAddress(hub Hub, address Address, confirmations int) (addressResult, error) {
	history, err := hub.Call("blockchain.scripthash.get_history", []any{address.ScriptHash})
	if err != nil {
		return addressResult{}, err
	}
	items, isList := history.([]any)
	if !isList {
		return addressResult{}, fmt.Errorf("the wallet server sent an unexpected history for %s", address.Address)
	}
	result := addressResult{used: len(items) > 0}
	if !result.used {
		return result, nil // no history, so no balance
	}

	balance, err := hub.Call("blockchain.scripthash.get_balance", []any{address.ScriptHash})
	if err != nil {
		return addressResult{}, err
	}
	fields, isMap := balance.(map[string]any)
	confirmed, confirmedOK := fields["confirmed"].(float64)
	unconfirmed, unconfirmedOK := fields["unconfirmed"].(float64)
	if !isMap || !confirmedOK || !unconfirmedOK {
		return addressResult{}, fmt.Errorf("the wallet server sent an unexpected balance for %s", address.Address)
	}
	result.amount = int64(confirmed)
	if confirmations == 0 {
		result.amount += int64(unconfirmed)
	}
	return result, nil
}

// FormatLBC writes dewies as lbry-sdk does (satoshis_to_coins): at least one decimal, no trailing zeros.
func FormatLBC(dewies int64) string {
	sign := ""
	if dewies < 0 {
		sign, dewies = "-", -dewies
	}
	fraction := strings.TrimRight(fmt.Sprintf("%08d", dewies%100000000), "0")
	if fraction == "" {
		fraction = "0"
	}
	return sign + strconv.FormatInt(dewies/100000000, 10) + "." + fraction
}
