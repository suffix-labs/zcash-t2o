package pczt

import (
	"bytes"
	"testing"
)

// TestRoundTripEmpty tests serialization of an empty PCZT
func TestRoundTripEmpty(t *testing.T) {
	// Create minimal PCZT
	pczt := &PCZT{
		Global: Global{
			TxVersion:         V5TxVersion,
			VersionGroupID:    V5VersionGroupID,
			ConsensusBranchID: 0xC2D6D0B4, // NU5
			ExpiryHeight:      2500000,
			CoinType:          133, // Mainnet
			TxModifiable:      0xFF,
			Proprietary:       make(map[string][]byte),
		},
		Transparent: TransparentBundle{
			Inputs:  []TransparentInput{},
			Outputs: []TransparentOutput{},
		},
		Sapling: SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
			Anchor:   [32]byte{},
		},
		Orchard: OrchardBundle{
			Actions:  []OrchardAction{},
			Flags:    OrchardFlagsEnabled,
			ValueSum: ValueBalance{Magnitude: 0, IsNegative: false},
			Anchor:   [32]byte{},
		},
	}

	checkRoundTrip(t, pczt)
}

// TestRoundTripWithTransparentInput tests serialization with a transparent input
func TestRoundTripWithTransparentInput(t *testing.T) {
	pczt := &PCZT{
		Global: Global{
			TxVersion:         V5TxVersion,
			VersionGroupID:    V5VersionGroupID,
			ConsensusBranchID: 0xC2D6D0B4,
			ExpiryHeight:      2500000,
			CoinType:          133,
			TxModifiable:      FlagTransparentInputsModifiable,
			Proprietary:       make(map[string][]byte),
		},
		Transparent: TransparentBundle{
			Inputs: []TransparentInput{
				{
					PrevoutTxID:        [32]byte{1, 2, 3},
					PrevoutIndex:       0,
					Value:              100_000_000,
					ScriptPubKey:       []byte{0x76, 0xA9, 0x14}, // P2PKH prefix
					SighashType:        SighashAll,
					PartialSignatures:  make(map[[33]byte][]byte),
					Bip32Derivation:    make(map[[33]byte]Zip32Derivation),
					Ripemd160Preimages: make(map[[20]byte][]byte),
					Sha256Preimages:    make(map[[32]byte][]byte),
					Hash160Preimages:   make(map[[20]byte][]byte),
					Hash256Preimages:   make(map[[32]byte][]byte),
					Proprietary:        make(map[string][]byte),
				},
			},
			Outputs: []TransparentOutput{},
		},
		Sapling: SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
			Anchor:   [32]byte{},
		},
		Orchard: OrchardBundle{
			Actions:  []OrchardAction{},
			Flags:    OrchardFlagsEnabled,
			ValueSum: ValueBalance{Magnitude: 0, IsNegative: false},
			Anchor:   [32]byte{},
		},
	}

	checkRoundTrip(t, pczt)
}

// TestRoundTripWithOrchardAction tests serialization with Orchard actions
func TestRoundTripWithOrchardAction(t *testing.T) {
	rcv := [32]byte{5, 6, 7}
	value := uint64(100_000)
	rho := [32]byte{8, 9, 10}
	rseed := [32]byte{11, 12, 13}
	alpha := [32]byte{14, 15, 16}
	dummySk := [32]byte{17, 18, 19}
	recipient := [43]byte{20, 21, 22}

	pczt := &PCZT{
		Global: Global{
			TxVersion:         V5TxVersion,
			VersionGroupID:    V5VersionGroupID,
			ConsensusBranchID: 0xC2D6D0B4,
			ExpiryHeight:      2500000,
			CoinType:          133,
			TxModifiable:      0,
			Proprietary:       make(map[string][]byte),
		},
		Transparent: TransparentBundle{
			Inputs:  []TransparentInput{},
			Outputs: []TransparentOutput{},
		},
		Sapling: SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
			Anchor:   [32]byte{},
		},
		Orchard: OrchardBundle{
			Actions: []OrchardAction{
				{
					CvNet: [32]byte{1, 2, 3},
					Spend: OrchardSpend{
						Nullifier:   [32]byte{4, 5, 6},
						Rk:          [32]byte{7, 8, 9},
						Value:       &value,
						Rho:         &rho,
						Alpha:       &alpha,
						DummySk:     &dummySk,
						Proprietary: make(map[string][]byte),
					},
					Output: OrchardOutput{
						Cmx:           [32]byte{10, 11, 12},
						EphemeralKey:  [32]byte{13, 14, 15},
						EncCiphertext: make([]byte, 580),
						OutCiphertext: make([]byte, 80),
						Recipient:     &recipient,
						Value:         &value,
						Rseed:         &rseed,
						Proprietary:   make(map[string][]byte),
					},
					Rcv: &rcv,
				},
			},
			Flags:    OrchardFlagsEnabled,
			ValueSum: ValueBalance{Magnitude: 100_000, IsNegative: false},
			Anchor:   [32]byte{},
		},
	}

	checkRoundTrip(t, pczt)
}

// TestRoundTripWithSignatures tests serialization with partial signatures
func TestRoundTripWithSignatures(t *testing.T) {
	pubkey := [33]byte{2, 3, 4} // Compressed pubkey
	signature := []byte{0x30, 0x44, 0x02, 0x20} // DER signature prefix

	pczt := &PCZT{
		Global: Global{
			TxVersion:         V5TxVersion,
			VersionGroupID:    V5VersionGroupID,
			ConsensusBranchID: 0xC2D6D0B4,
			ExpiryHeight:      2500000,
			CoinType:          133,
			TxModifiable:      0,
			Proprietary:       make(map[string][]byte),
		},
		Transparent: TransparentBundle{
			Inputs: []TransparentInput{
				{
					PrevoutTxID:  [32]byte{1, 2, 3},
					PrevoutIndex: 0,
					Value:        100_000_000,
					ScriptPubKey: []byte{0x76, 0xA9, 0x14},
					SighashType:  SighashAll,
					PartialSignatures: map[[33]byte][]byte{
						pubkey: signature,
					},
					Bip32Derivation:    make(map[[33]byte]Zip32Derivation),
					Ripemd160Preimages: make(map[[20]byte][]byte),
					Sha256Preimages:    make(map[[32]byte][]byte),
					Hash160Preimages:   make(map[[20]byte][]byte),
					Hash256Preimages:   make(map[[32]byte][]byte),
					Proprietary:        make(map[string][]byte),
				},
			},
			Outputs: []TransparentOutput{},
		},
		Sapling: SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
			Anchor:   [32]byte{},
		},
		Orchard: OrchardBundle{
			Actions:  []OrchardAction{},
			Flags:    OrchardFlagsEnabled,
			ValueSum: ValueBalance{Magnitude: 0, IsNegative: false},
			Anchor:   [32]byte{},
		},
	}

	checkRoundTrip(t, pczt)
}

// TestSerializeDeserialize tests the basic serialize/deserialize flow
func TestSerializeDeserialize(t *testing.T) {
	original := &PCZT{
		Global: Global{
			TxVersion:         V5TxVersion,
			VersionGroupID:    V5VersionGroupID,
			ConsensusBranchID: 0xC2D6D0B4,
			ExpiryHeight:      2500000,
			CoinType:          133,
			TxModifiable:      0xFF,
			Proprietary:       make(map[string][]byte),
		},
		Transparent: TransparentBundle{
			Inputs:  []TransparentInput{},
			Outputs: []TransparentOutput{},
		},
		Sapling: SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
		},
		Orchard: OrchardBundle{
			Actions: []OrchardAction{},
			Flags:   OrchardFlagsEnabled,
		},
	}

	// Serialize
	serialized, err := Serialize(original)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("Serialized data is empty")
	}

	// Should start with "PCZT" magic bytes
	if !bytes.HasPrefix(serialized, []byte("PCZT")) {
		t.Errorf("Missing PCZT magic bytes, got: %x", serialized[:4])
	}

	// Deserialize
	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	// Verify key fields match
	if deserialized.Global.TxVersion != original.Global.TxVersion {
		t.Errorf("TxVersion mismatch: %d != %d", deserialized.Global.TxVersion, original.Global.TxVersion)
	}

	if deserialized.Global.ConsensusBranchID != original.Global.ConsensusBranchID {
		t.Errorf("ConsensusBranchID mismatch: %x != %x", deserialized.Global.ConsensusBranchID, original.Global.ConsensusBranchID)
	}

	if deserialized.Global.ExpiryHeight != original.Global.ExpiryHeight {
		t.Errorf("ExpiryHeight mismatch: %d != %d", deserialized.Global.ExpiryHeight, original.Global.ExpiryHeight)
	}
}

// checkRoundTrip is the main round-trip test helper
// This matches the pattern from librustzcash/pczt/tests/end_to_end.rs
func checkRoundTrip(t *testing.T, pczt *PCZT) {
	t.Helper()

	// First serialization
	bytes1, err := Serialize(pczt)
	if err != nil {
		t.Fatalf("First serialization failed: %v", err)
	}

	// Parse/deserialize
	parsed, err := Deserialize(bytes1)
	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	// Second serialization
	bytes2, err := Serialize(parsed)
	if err != nil {
		t.Fatalf("Second serialization failed: %v", err)
	}

	// They must be identical
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatalf("Round-trip serialization failed: bytes differ\nFirst:  %x\nSecond: %x", bytes1[:min(len(bytes1), 100)], bytes2[:min(len(bytes2), 100)])
	}

	t.Logf("✓ Round-trip test passed (%d bytes)", len(bytes1))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
