package wallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Receiving and change chains of an account, and the gaps lbry-sdk generates by default
// (lbry/wallet/account.py: KeyPath, AddressManager).
const (
	ReceivingChain uint32 = 0
	ChangeChain    uint32 = 1

	DefaultReceivingGap = 20
	DefaultChangeGap    = 6
)

// lbry-sdk lbry/wallet/ledger.py, MainNetLedger.
var (
	extendedPublicKeyVersion = []byte{0x04, 0x88, 0xb2, 0x1e} // "xpub"
	pubkeyAddressVersion     = byte(0x55)
)

// Address is one address of an account.
type Address struct {
	Address    string
	ScriptHash string // what the wallet server indexes by: sha256 of the output script, reversed, hex
	Chain      uint32
	Index      uint32
}

// extendedKey is a BIP32 extended public key.
type extendedKey struct {
	key       *secp256k1.PublicKey
	chainCode []byte
}

func parseExtendedPublicKey(xpub string) (*extendedKey, error) {
	raw, version, err := base58.CheckDecode(xpub)
	if err != nil {
		return nil, fmt.Errorf("extended public key is not valid base58check: %w", err)
	}
	// base58.CheckDecode splits off a one-byte version, so put it back to see all four bytes.
	full := append([]byte{version}, raw...)
	if len(full) != 78 {
		return nil, fmt.Errorf("extended public key has %d bytes, want 78", len(full))
	}
	if !bytes.Equal(full[:4], extendedPublicKeyVersion) {
		return nil, errors.New("not an extended public key (xpub)")
	}
	key, err := secp256k1.ParsePubKey(full[45:78])
	if err != nil {
		return nil, fmt.Errorf("extended public key holds an invalid public key: %w", err)
	}
	return &extendedKey{key: key, chainCode: full[13:45]}, nil
}

// child derives the non-hardened child at index (BIP32 CKDpub).
func (parent *extendedKey) child(index uint32) (*extendedKey, error) {
	if index >= 1<<31 {
		return nil, errors.New("a public key cannot derive a hardened child")
	}
	mac := hmac.New(sha512.New, parent.chainCode)
	mac.Write(parent.key.SerializeCompressed())
	var serialized [4]byte
	binary.BigEndian.PutUint32(serialized[:], index)
	mac.Write(serialized[:])
	sum := mac.Sum(nil)

	var tweak secp256k1.ModNScalar
	if overflow := tweak.SetByteSlice(sum[:32]); overflow || tweak.IsZero() {
		return nil, errors.New("derivation produced an invalid key; use the next index")
	}
	var tweakPoint, parentPoint, childPoint secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tweak, &tweakPoint)
	parent.key.AsJacobian(&parentPoint)
	secp256k1.AddNonConst(&tweakPoint, &parentPoint, &childPoint)
	if (childPoint.X.IsZero() && childPoint.Y.IsZero()) || childPoint.Z.IsZero() {
		return nil, errors.New("derivation produced the point at infinity; use the next index")
	}
	childPoint.ToAffine()
	return &extendedKey{
		key:       secp256k1.NewPublicKey(&childPoint.X, &childPoint.Y),
		chainCode: sum[32:],
	}, nil
}

// DeriveAddresses returns count addresses of chain (ReceivingChain or ChangeChain), starting at
// index start, from an account's extended public key. Only public keys are used.
func DeriveAddresses(xpub string, chain uint32, start uint32, count int) ([]Address, error) {
	if chain > ChangeChain {
		return nil, fmt.Errorf("unknown chain %d", chain)
	}
	root, err := parseExtendedPublicKey(xpub)
	if err != nil {
		return nil, err
	}
	chainKey, err := root.child(chain)
	if err != nil {
		return nil, err
	}
	addresses := make([]Address, 0, count)
	for i := 0; i < count; i++ {
		index := start + uint32(i)
		key, err := chainKey.child(index)
		if err != nil {
			return nil, fmt.Errorf("address %d/%d: %w", chain, index, err)
		}
		hash := btcutil.Hash160(key.key.SerializeCompressed())
		addresses = append(addresses, Address{
			Address:    base58.CheckEncode(hash, pubkeyAddressVersion),
			ScriptHash: scriptHash(hash),
			Chain:      chain,
			Index:      index,
		})
	}
	return addresses, nil
}

// scriptHash is the wallet-server index key of a pay-to-pubkey-hash output.
func scriptHash(hash160 []byte) string {
	script := append(append([]byte{0x76, 0xa9, 0x14}, hash160...), 0x88, 0xac)
	sum := sha256.Sum256(script)
	for i, j := 0, len(sum)-1; i < j; i, j = i+1, j-1 {
		sum[i], sum[j] = sum[j], sum[i]
	}
	return hex.EncodeToString(sum[:])
}
