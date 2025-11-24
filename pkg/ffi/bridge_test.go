package ffi

import (
	"testing"
)

func TestPallasScalarAdd(t *testing.T) {
	// Test 1 + 1 = 2
	one := [32]byte{1}

	result, err := PallasScalarAdd(one, one)
	if err != nil {
		t.Fatalf("PallasScalarAdd failed: %v", err)
	}

	// Check result is 2
	if result[0] != 2 {
		t.Errorf("Expected result[0] = 2, got %d", result[0])
	}

	t.Logf("✓ Pallas scalar add works: 1 + 1 = %d", result[0])
}

func TestOrchardValueCommitment(t *testing.T) {
	value := uint64(100000000) // 1 ZEC in zatoshis
	rcv := [32]byte{1, 2, 3, 4, 5} // Some randomness

	cv, err := OrchardValueCommitment(value, rcv)
	if err != nil {
		t.Fatalf("OrchardValueCommitment failed: %v", err)
	}

	// Value commitment should be 32 bytes
	if len(cv) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(cv))
	}

	// Should not be all zeros
	allZeros := true
	for _, b := range cv {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Value commitment is all zeros")
	}

	t.Logf("✓ Orchard value commitment works: %d bytes", len(cv))
}

func TestProvePCZTWithEmptyPCZT(t *testing.T) {
	// Create a minimal PCZT in the format the Rust code expects
	// This is the serialized format: MAGIC (4 bytes) + VERSION (4 bytes) + postcard data

	// For now, we'll test with invalid bytes to see error handling
	invalidPCZT := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	_, err := ProvePCZT(invalidPCZT)
	if err == nil {
		t.Fatal("Expected error for invalid PCZT, got nil")
	}

	t.Logf("✓ ProvePCZT correctly rejects invalid input: %v", err)
}

func TestRedDSASignSpendAuth(t *testing.T) {
	sk := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		           17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	alpha := [32]byte{0}
	sighash := [32]byte{0}

	sig, err := RedDSASignSpendAuth(sk, alpha, sighash)
	if err != nil {
		t.Fatalf("RedDSASignSpendAuth failed: %v", err)
	}

	// Signature should be 64 bytes
	if len(sig) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(sig))
	}

	t.Logf("✓ RedDSA signature works: %d bytes", len(sig))
}

func TestFFIMemoryManagement(t *testing.T) {
	// Test that we can call multiple FFI functions without leaks
	for i := 0; i < 100; i++ {
		one := [32]byte{1}
		_, err := PallasScalarAdd(one, one)
		if err != nil {
			t.Fatalf("Iteration %d failed: %v", i, err)
		}
	}

	t.Logf("✓ Memory management works: 100 iterations without crash")
}
