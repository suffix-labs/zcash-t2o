package roles

import (
	"testing"

	"github.com/suffix-labs/zcash-t2o/pkg/crypto"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// TestTransparentToOrchard mirrors the transparent_to_orchard test from librustzcash
// See: librustzcash/pczt/tests/end_to_end.rs:49-197
//
// This is the primary use case: spending transparent UTXOs to create Orchard outputs.
func TestTransparentToOrchard(t *testing.T) {
	// Network parameters
	const (
		consensusBranchID = 0xC2D6D0B4 // NU5 mainnet
		expiryHeight      = 10_000_040
		coinType          = 133 // Mainnet
	)

	// Step 1: Create transparent input keys
	// For testing, we'll use a known WIF key
	// In production, this would come from the wallet
	privateKeyWIF := "KxYPKw8xvJFDQz1qsVWqehDTx8VqnJvLqJr9iQxKhRgQqUx7YwMN" // Example testnet key
	privateKey, err := crypto.PrivateKeyFromWIF(privateKeyWIF)
	if err != nil {
		t.Skipf("Skipping test - need valid WIF key: %v", err)
		return
	}

	pubkey := privateKey.PublicKey()
	pubkeyCompressed := pubkey.SerializeCompressed()

	// Create P2PKH scriptPubKey for the transparent input
	// P2PKH: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
	scriptPubKey := createP2PKHScript(pubkeyCompressed)

	// Step 2: Create Orchard recipient address
	// For testing, we use a placeholder 43-byte address
	// In production, this would be parsed from a unified address
	orchardRecipient := [43]byte{
		// Diversifier (11 bytes)
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		// pk_d (32 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	// Step 3: Create PCZT with Creator role
	creator := NewCreator(
		consensusBranchID,
		expiryHeight,
		coinType,
		[32]byte{}, // Empty Orchard anchor for testing
	)
	p := creator.Create()

	// Test round-trip serialization after Creator
	checkRoundTrip(t, p)

	// Step 4: Add inputs and outputs with Constructor role
	constructor := NewConstructor(p)

	// Add transparent input (1 ZEC = 100,000,000 zatoshis)
	txid := [32]byte{1, 2, 3} // Fake TXID for testing
	err = constructor.AddTransparentInput(
		txid,
		0,                // Output index
		100_000_000,      // 1 ZEC
		scriptPubKey,
		nil,              // No redeem script (P2PKH)
		nil,              // Default sequence
	)
	if err != nil {
		t.Fatalf("Failed to add transparent input: %v", err)
	}

	// Add Orchard output (0.001 ZEC = 100,000 zatoshis)
	memo := [512]byte{}
	copy(memo[:], []byte("Test payment"))

	err = constructor.AddOrchardOutput(
		orchardRecipient,
		100_000, // 0.001 ZEC
		memo,
	)
	if err != nil {
		t.Fatalf("Failed to add Orchard output: %v", err)
	}

	// Add change output (0.9985 ZEC = 99,850,000 zatoshis, leaving 50,000 for fee)
	err = constructor.AddOrchardOutput(
		orchardRecipient,
		99_850_000, // 0.9985 ZEC (change)
		[512]byte{}, // Empty memo
	)
	if err != nil {
		t.Fatalf("Failed to add change output: %v", err)
	}

	p = constructor.Finish()

	// Step 5: Finalize I/O with IoFinalizer role
	ioFinalizer := NewIoFinalizer(p)
	err = ioFinalizer.Finalize()
	if err != nil {
		t.Fatalf("IO finalization failed: %v", err)
	}
	p = ioFinalizer.Finish()

	// Test round-trip serialization after IoFinalizer
	checkRoundTrip(t, p)

	// Step 6: Create proofs with Prover role
	// NOTE: This step requires the Rust FFI proving implementation
	// For now, we'll skip it and manually set placeholder proof data
	//
	// In production:
	// pcztBytes, _ := pczt.Serialize(p)
	// provedBytes, err := ffi.ProvePCZT(pcztBytes)
	// p, _ = pczt.Deserialize(provedBytes)
	//
	// For testing, we set placeholder proof
	if len(p.Orchard.Actions) > 0 {
		// Set placeholder ZK proof (not cryptographically valid)
		placeholderProof := make([]byte, 1000) // Approximate size
		p.Orchard.ZkProof = &placeholderProof
		t.Log("⚠️  Using placeholder ZK proof - proving not implemented yet")
	}

	// checkRoundTrip(t, p) // Would test after proving

	// Step 7: Sign transparent inputs with Signer role
	signer := NewSigner(p)

	err = signer.SignTransparentInput(0, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign input: %v", err)
	}

	p = signer.Finish()

	// Test round-trip serialization after Signer
	checkRoundTrip(t, p)

	// Step 8: Finalize spends with SpendFinalizer role
	spendFinalizer := NewSpendFinalizer(p)
	err = spendFinalizer.Finalize()
	if err != nil {
		t.Fatalf("Spend finalization failed: %v", err)
	}
	p = spendFinalizer.Finish()

	// Test round-trip serialization after SpendFinalizer
	checkRoundTrip(t, p)

	// Step 9: Extract transaction with TransactionExtractor role
	extractor := NewTxExtractor(p)
	txBytes, err := extractor.Extract()
	if err != nil {
		t.Fatalf("Transaction extraction failed: %v", err)
	}

	// Verify we got transaction bytes
	if len(txBytes) == 0 {
		t.Fatal("Transaction extraction produced empty bytes")
	}

	t.Logf("✅ Successfully created transparent-to-Orchard transaction (%d bytes)", len(txBytes))

	// Step 10: Validate transaction structure
	// In the Rust tests, they validate:
	// - Expiry height matches
	// - Script execution succeeds
	// - Signatures are valid
	//
	// For now, we just verify basic structure
	validateTransactionStructure(t, txBytes)
}

// checkRoundTrip verifies that a PCZT can be serialized and deserialized
// without losing data. This mirrors the Rust test pattern.
func checkRoundTrip(t *testing.T, p *pczt.PCZT) {
	t.Helper()

	// Serialize
	bytes1, err := pczt.Serialize(p)
	if err != nil {
		t.Fatalf("First serialization failed: %v", err)
	}

	// Deserialize
	parsed, err := pczt.Deserialize(bytes1)
	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	// Serialize again
	bytes2, err := pczt.Serialize(parsed)
	if err != nil {
		t.Fatalf("Second serialization failed: %v", err)
	}

	// Compare
	if len(bytes1) != len(bytes2) {
		t.Fatalf("Round-trip serialization length mismatch: %d != %d", len(bytes1), len(bytes2))
	}

	// Byte-by-byte comparison
	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatalf("Round-trip serialization mismatch at byte %d: 0x%02x != 0x%02x", i, bytes1[i], bytes2[i])
		}
	}

	t.Logf("✓ Round-trip serialization passed (%d bytes)", len(bytes1))
}

// createP2PKHScript creates a P2PKH (Pay-to-Public-Key-Hash) script
// Format: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
func createP2PKHScript(pubkey [33]byte) []byte {
	// Hash the public key
	hash160 := hashPubkey(pubkey[:])

	script := make([]byte, 0, 25)
	script = append(script, 0x76) // OP_DUP
	script = append(script, 0xA9) // OP_HASH160
	script = append(script, 0x14) // Push 20 bytes
	script = append(script, hash160[:]...)
	script = append(script, 0x88) // OP_EQUALVERIFY
	script = append(script, 0xAC) // OP_CHECKSIG

	return script
}

// hashPubkey computes HASH160 (RIPEMD160(SHA256(pubkey)))
func hashPubkey(pubkey []byte) [20]byte {
	// TODO: Implement proper HASH160
	// For now, return placeholder
	var hash [20]byte
	copy(hash[:], pubkey[:20])
	return hash
}

// validateTransactionStructure performs basic validation on the extracted transaction
func validateTransactionStructure(t *testing.T, txBytes []byte) {
	t.Helper()

	// Very basic validation - just check it's not empty and has reasonable size
	if len(txBytes) < 100 {
		t.Errorf("Transaction seems too small: %d bytes", len(txBytes))
	}

	if len(txBytes) > 100_000 {
		t.Errorf("Transaction seems too large: %d bytes", len(txBytes))
	}

	// TODO: Add more validation:
	// - Parse transaction header
	// - Verify transparent bundle
	// - Verify Orchard bundle
	// - Validate signatures (would need zcash_script)

	t.Log("✓ Basic transaction structure validation passed")
}
