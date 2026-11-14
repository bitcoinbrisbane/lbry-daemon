package wallet

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// BIP32 test vector 1: the xpub of m/0H, and m/0H/1, which is its non-hardened child 1.
const (
	bipXpub0H   = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	bipXpub0H_1 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
)

func TestChildMatchesBIP32Vector(t *testing.T) {
	parent, err := parseExtendedPublicKey(bipXpub0H)
	if err != nil {
		t.Fatal(err)
	}
	child, err := parent.child(1)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parseExtendedPublicKey(bipXpub0H_1)
	if err != nil {
		t.Fatal(err)
	}
	if !child.key.IsEqual(expected.key) || string(child.chainCode) != string(expected.chainCode) {
		t.Fatal("derived child does not match the BIP32 vector")
	}
}

// Expected values computed independently with a pure-Python BIP32 implementation (checked against the
// vector above) using the LBRY version byte 0x55.
func TestDeriveAddressesVectors(t *testing.T) {
	cases := []struct {
		chain uint32
		index uint32
		addr  string
		hash  string
	}{
		{0, 0, "bPexZuD3kqHDrGwWTaaLMX4xsSQCochuYD", "96f6782e9a2649780ed342ac7b047a5314c92daee8b81c4e53614f535318e2c3"},
		{0, 2, "bQkccmLwQJqYUMYAcQqnPFptAUSDYadZTw", "a73332c6bca42f72a5ee0a6d5f535418a419513431100f25d5d05422de3c283c"},
		{1, 0, "bVp8LpwEkvJFpJLAT9jKSFn3Z281nH4wcm", "67e04a85a7965baa250d73548672be562a8987331d1c16cb362c1e3d85a9de6b"},
		{1, 1, "bH1DYJPcf715MuGpwcK3a6w2CXp7hW5zgo", "c61d1c42d573355332b519f4e5847fdc2a79eecb3d0d27671b6575f9ac8b35ed"},
	}
	for _, c := range cases {
		got, err := DeriveAddresses(bipXpub0H, c.chain, c.index, 1)
		if err != nil || len(got) != 1 {
			t.Fatalf("chain %d index %d: %v %v", c.chain, c.index, got, err)
		}
		if got[0].Address != c.addr || got[0].ScriptHash != c.hash || got[0].Chain != c.chain || got[0].Index != c.index {
			t.Errorf("chain %d index %d: got %+v", c.chain, c.index, got[0])
		}
		if !strings.HasPrefix(got[0].Address, "b") {
			t.Errorf("LBRY addresses start with b: %s", got[0].Address)
		}
	}
}

func TestDeriveAddressesRange(t *testing.T) {
	list, err := DeriveAddresses(bipXpub0H, ReceivingChain, 0, DefaultReceivingGap)
	if err != nil || len(list) != 20 {
		t.Fatalf("%d %v", len(list), err)
	}
	later, _ := DeriveAddresses(bipXpub0H, ReceivingChain, 5, 3)
	for i, a := range later {
		if a != list[5+i] {
			t.Fatalf("start offset gave a different address at %d", i)
		}
	}
}

func TestDeriveAddressesRejectsBadInput(t *testing.T) {
	notXpub := base58.CheckEncode(make([]byte, 77), 0x04) // right length, wrong version
	for name, xpub := range map[string]string{
		"empty":         "",
		"not base58":    "0OIl",
		"bad checksum":  bipXpub0H[:len(bipXpub0H)-1] + "x",
		"wrong version": notXpub,
		"short payload": base58.CheckEncode([]byte{1, 2, 3}, 4),
	} {
		if _, err := DeriveAddresses(xpub, ReceivingChain, 0, 1); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := DeriveAddresses(bipXpub0H, 2, 0, 1); err == nil {
		t.Error("chain 2 should be rejected")
	}
	if _, err := DeriveAddresses(bipXpub0H, ReceivingChain, 1<<31, 1); err == nil {
		t.Error("hardened index should be rejected")
	}
}
