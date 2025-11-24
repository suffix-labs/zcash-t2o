# Testing Guide

This document provides comprehensive testing instructions for the zcash-t2o library.

## Prerequisites

- Go 1.21 or later
- Rust toolchain (cargo, rustc)
- CGO enabled
- Linux or macOS (Windows not yet tested)

## Quick Test

```bash
# Build and test everything
./scripts/test.sh
```

## Detailed Testing Steps

### 1. Rust FFI Library Tests

The Rust library provides Orchard cryptographic operations. Test it first:

```bash
cd pkg/ffi/rust

# Build the library
cargo build --release

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_pallas_scalar_add
cargo test test_error_handling

# Check build artifacts
ls -lh target/release/libzcash_t2o_ffi.{a,so,dylib}
```

**Expected output:**
```
running 2 tests
test tests::test_error_handling ... ok
test tests::test_pallas_scalar_add ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**Files created:**
- `target/release/libzcash_t2o_ffi.a` - Static library for linking
- `target/release/libzcash_t2o_ffi.so` (Linux) or `.dylib` (macOS) - Dynamic library

### 2. Go FFI Bridge Tests

Test the CGO bridge between Go and Rust:

```bash
cd ../../..  # Back to project root

# Set library paths
export CGO_LDFLAGS="-L${PWD}/pkg/ffi/rust/target/release"
export LD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release:$LD_LIBRARY_PATH"

# On macOS, also set:
export DYLD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release"

# Test FFI package
go test -v ./pkg/ffi
```

**Expected output:**
```
=== RUN   TestPallasScalarAdd
--- PASS: TestPallasScalarAdd (0.00s)
=== RUN   TestOrchardValueCommitment
--- PASS: TestOrchardValueCommitment (0.00s)
PASS
ok      github.com/suffix-labs/zcash-t2o/pkg/ffi       0.123s
```

### 3. Individual Package Tests

Test each package independently:

```bash
# PCZT serialization tests
go test -v ./pkg/pczt

# Crypto tests (ZIP 244, secp256k1)
go test -v ./pkg/crypto

# PCZT roles tests
go test -v ./pkg/roles

# ZIP 321 parser tests
go test -v ./pkg/zip321

# Public API tests
go test -v ./pkg/api
```

### 4. Integration Tests

Run all tests together:

```bash
# All packages
go test ./...

# With verbose output
go test -v ./...

# With coverage
go test -cover ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 5. CLI Tool Tests

Test the CLI manually:

```bash
# Build CLI
go build -o zcash-t2o ./cmd/zcash-t2o

# Run commands
./zcash-t2o version
./zcash-t2o parse-uri "zcash:tmAddr123?amount=1.5&memo=test"
./zcash-t2o help
```

## Writing New Tests

### Rust FFI Test Example

Add to `pkg/ffi/rust/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchard_note_commitment() {
        unsafe {
            let recipient = [0u8; 43];
            let value = 100000000; // 1 ZEC
            let rseed = [1u8; 32];
            let rho = [2u8; 32];
            let mut cmx_out = [0u8; 32];

            let result = ffi_orchard_note_commitment(
                recipient.as_ptr(),
                value,
                rseed.as_ptr(),
                rho.as_ptr(),
                cmx_out.as_mut_ptr(),
            );

            // Note: This will fail with invalid data, but tests the FFI
            // Real test would use valid Orchard addresses
            assert!(result != FFIErrorCode::Ok || cmx_out != [0u8; 32]);
        }
    }
}
```

### Go FFI Test Example

Add to `pkg/ffi/bridge_test.go`:

```go
package ffi

import (
    "testing"
)

func TestOrchardNoteCommitment(t *testing.T) {
    // Test data (not cryptographically valid, just tests FFI)
    recipient := [43]byte{}
    value := uint64(100000000)
    rseed := [32]byte{1, 2, 3}
    rho := [32]byte{4, 5, 6}

    cmx, err := OrchardNoteCommitment(recipient, value, rseed, rho)

    // May fail with invalid data, but tests that FFI works
    if err == nil {
        if len(cmx) != 32 {
            t.Errorf("Expected 32 bytes, got %d", len(cmx))
        }
        t.Logf("Note commitment: %x", cmx)
    } else {
        t.Logf("Expected error with invalid data: %v", err)
    }
}

func TestRedDSASignSpendAuth(t *testing.T) {
    sk := [32]byte{1, 2, 3}
    alpha := [32]byte{4, 5, 6}
    sighash := [32]byte{7, 8, 9}

    sig, err := RedDSASignSpendAuth(sk, alpha, sighash)
    if err != nil {
        t.Fatalf("RedDSASignSpendAuth failed: %v", err)
    }

    if len(sig) != 64 {
        t.Errorf("Expected 64-byte signature, got %d", len(sig))
    }

    t.Logf("Signature: %x", sig)
}
```

### API Integration Test Example

Add to `pkg/api/api_test.go`:

```go
package api

import (
    "testing"
)

func TestProposeTransaction(t *testing.T) {
    proposal := &TransactionProposal{
        ConsensusBranchID: 0xC2D6D0B4, // NU5
        ExpiryHeight:      2500000,
        CoinType:          1, // Testnet
        OrchardAnchor:     [32]byte{},
        TransparentInputs: []TransparentInput{},
        OrchardOutputs:    []OrchardOutput{},
    }

    pcztBytes, err := ProposeTransaction(proposal)
    if err != nil {
        t.Fatalf("ProposeTransaction failed: %v", err)
    }

    if len(pcztBytes) < 10 {
        t.Error("PCZT too small")
    }

    t.Logf("Created PCZT: %d bytes", len(pcztBytes))
}

func TestVerifyBeforeSigning(t *testing.T) {
    // Create minimal valid PCZT
    proposal := &TransactionProposal{
        ConsensusBranchID: 0xC2D6D0B4,
        ExpiryHeight:      2500000,
        CoinType:          1,
        OrchardAnchor:     [32]byte{},
    }

    pcztBytes, _ := ProposeTransaction(proposal)

    // Should pass verification (even though empty)
    err := VerifyBeforeSigning(pcztBytes)

    // May fail due to no inputs, but tests the function
    t.Logf("Verification result: %v", err)
}
```

## Troubleshooting

### CGO Linking Errors

**Problem:** `undefined reference to 'ffi_*'`

**Solution:**
```bash
# Verify library was built
ls pkg/ffi/rust/target/release/libzcash_t2o_ffi.a

# Check symbols
nm pkg/ffi/rust/target/release/libzcash_t2o_ffi.a | grep ffi_

# Set correct paths
export CGO_LDFLAGS="-L${PWD}/pkg/ffi/rust/target/release"

# Try building again
go clean -cache
go build ./pkg/ffi
```

### Library Not Found at Runtime

**Problem:** `error while loading shared libraries: libzcash_t2o_ffi.so: cannot open shared object file`

**Solution:**
```bash
# Linux
export LD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release:$LD_LIBRARY_PATH"

# macOS
export DYLD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release:$DYLD_LIBRARY_PATH"

# Or use static linking (edit CGO_LDFLAGS in bridge.go)
```

### Rust Build Failures

**Problem:** `error: failed to compile`

**Solution:**
```bash
# Update Rust
rustup update

# Clean and rebuild
cd pkg/ffi/rust
cargo clean
cargo build --release

# Check Rust version
rustc --version  # Should be 1.70+
```

### Go Module Issues

**Problem:** `package github.com/suffix-labs/zcash-t2o/pkg/ffi: no Go files`

**Solution:**
```bash
# Make sure you're in the right directory
cd /path/to/zcash-t2o

# Verify module path
grep module go.mod

# Update dependencies
go mod tidy
go mod download
```

## Continuous Integration

For CI/CD pipelines:

```yaml
# .github/workflows/test.yml example
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Set up Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Build Rust FFI
        run: |
          cd pkg/ffi/rust
          cargo build --release
          cargo test

      - name: Run Go tests
        run: |
          export CGO_LDFLAGS="-L${PWD}/pkg/ffi/rust/target/release"
          export LD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release"
          go test -v ./...
```

## Performance Testing

Benchmark critical operations:

```go
// pkg/crypto/zip244_bench_test.go
package crypto

import "testing"

func BenchmarkGetSignatureHash(b *testing.B) {
    // Setup test PCZT
    // ...

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := GetSignatureHash(testPCZT, 0, SighashAll)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

Run benchmarks:
```bash
go test -bench=. ./pkg/crypto
go test -bench=. -benchmem ./...
```

## Test Data

Test vectors and fixtures should be placed in:
- `testdata/` - General test data
- `testdata/fixtures/` - Known-good test vectors from Rust tests
- `testdata/vectors/` - ZIP specification test vectors

Example:
```
testdata/
├── fixtures/
│   ├── valid_pczt_1.bin
│   ├── valid_pczt_2.bin
│   └── invalid_pczt.bin
├── vectors/
│   ├── zip244_sighash_vectors.json
│   └── zip321_uri_vectors.json
└── keys/
    ├── test_private_key.wif
    └── test_address.txt
```

## Code Coverage Goals

- `pkg/pczt`: 80%+ (serialization critical)
- `pkg/crypto`: 90%+ (security critical)
- `pkg/roles`: 70%+ (integration heavy)
- `pkg/api`: 80%+ (public interface)
- `pkg/ffi`: 60%+ (FFI complexity)

Check coverage:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```
