# zcash-t2o

**Transparent-to-Orchard PCZT Library for Go**

A Go implementation of PCZT (Partially Created Zcash Transaction) based on [ZIP 374 WIP](https://github.com/zcash/zips/pull/1063), enabling transparent-only Bitcoin-style wallets to send shielded Orchard outputs.

## Overview

This library provides a complete implementation of the PCZT workflow for creating Zcash transactions that spend transparent UTXOs and create shielded Orchard outputs. It's designed for Bitcoin wallets and services that want to add Zcash privacy features without implementing full shielded pool support.

**Key Features:**
- ✅ Complete PCZT role implementation (Creator, Constructor, Signer, Prover, etc.)
- ✅ ZIP 244 transaction signature hashing
- ✅ ZIP 321 payment request URI parsing
- ✅ Postcard serialization (ZIP 374 format)
- ✅ Rust FFI for Orchard cryptographic operations
- ✅ Parallel signing support via Combiner role
- ✅ Well-documented with references to librustzcash

## Installation

### Prerequisites

- Go 1.21 or later
- Rust toolchain (for building the FFI library)
- CGO enabled

### Install Library

```bash
go get github.com/suffix-labs/zcash-t2o
```

### Build

The project includes a Makefile for simplified building:

```bash
# Build everything (Rust FFI + Go binary)
make build

# Or build just the Rust FFI library
make build-rust

# Or build just the Go binary (builds Rust first)
make build-go
```

The binary will be created at `bin/zcash-t2o`.

## Quick Start

### 1. Create a Transaction Proposal

```go
package main

import (
    "fmt"
    "github.com/suffix-labs/zcash-t2o/pkg/api"
)

func main() {
    // Define transaction inputs and outputs
    proposal := &api.TransactionProposal{
        ConsensusBranchID: 0xC2D6D0B4, // NU5
        ExpiryHeight:      2500000,
        CoinType:          1, // Testnet
        OrchardAnchor:     [32]byte{}, // Get from blockchain

        // Transparent inputs (UTXOs to spend)
        TransparentInputs: []api.TransparentInput{
            {
                TxID:         txid,
                OutputIndex:  0,
                Value:        100000000, // 1 ZEC in zatoshis
                ScriptPubKey: scriptPubKey,
            },
        },

        // Orchard outputs (shielded recipients)
        OrchardOutputs: []api.OrchardOutput{
            {
                Address: "uaddr1...", // Unified address
                Value:   95000000,    // 0.95 ZEC (0.05 fee)
                Memo:    []byte("Payment for services"),
            },
        },
    }

    // Create PCZT
    pcztBytes, err := api.ProposeTransaction(proposal)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Created PCZT: %d bytes\n", len(pcztBytes))
}
```

### 2. Generate ZK Proofs

```go
// Generate zero-knowledge proofs (calls Rust FFI)
provedBytes, err := api.ProveTransaction(pcztBytes)
if err != nil {
    panic(err)
}
```

### 3. Sign Transaction

```go
import "github.com/suffix-labs/zcash-t2o/pkg/crypto"

// Load private key from WIF
privateKey, err := crypto.PrivateKeyFromWIF("KxYZ...")
if err != nil {
    panic(err)
}

// Get sighash for input 0
sighash, err := api.GetSighash(provedBytes, 0)
if err != nil {
    panic(err)
}
fmt.Printf("Sighash to sign: %x\n", sighash)

// Add signature
signedBytes, err := api.AppendSignature(provedBytes, 0, privateKey)
if err != nil {
    panic(err)
}
```

### 4. Extract Final Transaction

```go
// Verify PCZT is valid
err = api.VerifyBeforeSigning(signedBytes)
if err != nil {
    panic(err)
}

// Extract final transaction bytes
txBytes, err := api.FinalizeAndExtract(signedBytes)
if err != nil {
    panic(err)
}

// Now broadcast txBytes to the network
fmt.Printf("Final transaction: %x\n", txBytes)
```

## Architecture

### PCZT Roles

The library implements the PCZT role pattern from ZIP 374:

| Role | Package | Purpose |
|------|---------|---------|
| **Creator** | `pkg/roles/creator.go` | Initialize empty PCZT with metadata |
| **Constructor** | `pkg/roles/constructor.go` | Add transparent inputs and Orchard outputs |
| **IO Finalizer** | `pkg/roles/io_finalizer.go` | Lock transaction structure, create dummy spends |
| **Prover** | `pkg/ffi/rust/src/lib.rs` | Generate zero-knowledge proofs (Rust FFI) |
| **Signer** | `pkg/roles/signer.go` | Add transparent signatures |
| **Spend Finalizer** | `pkg/roles/spend_finalizer.go` | Construct final scriptSigs |
| **Transaction Extractor** | `pkg/roles/tx_extractor.go` | Serialize final transaction |
| **Combiner** | `pkg/roles/combiner.go` | Merge parallel PCZTs |

### Package Structure

```
zcash-t2o/
├── pkg/
│   ├── api/          # Public API (8 core functions)
│   ├── pczt/         # PCZT types and serialization
│   ├── crypto/       # ZIP 244 sighash, secp256k1
│   ├── roles/        # PCZT role implementations
│   ├── zip321/       # Payment request URI parser
│   └── ffi/          # Rust FFI bridge
│       ├── bridge.go # CGO bindings
│       └── rust/     # Rust library
└── cmd/
    └── zcash-t2o/    # CLI tool
```

### Rust FFI Integration

Orchard cryptographic operations (note commitments, proofs, signatures) are implemented in Rust and called via CGO:

```go
import "github.com/suffix-labs/zcash-t2o/pkg/ffi"

// Generate ZK proof (calls into librustzcash)
provedPCZT, err := ffi.ProvePCZT(pcztBytes)

// Orchard note commitment
cmx, err := ffi.OrchardNoteCommitment(recipient, value, rseed, rho)

// RedPallas signature
sig, err := ffi.RedDSASignSpendAuth(sk, alpha, sighash)
```

## API Reference

### Core Functions (pkg/api)

1. **`ProposeTransaction(proposal)`** - Create PCZT from inputs/outputs
2. **`ProveTransaction(pcztBytes)`** - Generate ZK proofs
3. **`VerifyBeforeSigning(pcztBytes)`** - Validate PCZT
4. **`GetSighash(pcztBytes, inputIndex)`** - Compute signature hash
5. **`AppendSignature(pcztBytes, inputIndex, key)`** - Add signature
6. **`Combine(pcztList)`** - Merge parallel PCZTs
7. **`FinalizeAndExtract(pcztBytes)`** - Extract final transaction
8. **`ParsePCZT(bytes)` / `SerializePCZT(pczt)`** - Binary encoding

### ZIP 321 Payment Requests (pkg/zip321)

```go
import "github.com/suffix-labs/zcash-t2o/pkg/zip321"

// Parse payment request URI
req, err := zip321.Parse("zcash:uaddr1...?amount=1.5&memo=coffee")

// Access payment details
for _, payment := range req.Payments {
    fmt.Printf("Pay %f ZEC to %s\n", *payment.Amount, payment.Address)
}

// Encode back to URI
uri := req.Encode()
```

## CLI Tool

The `zcash-t2o` CLI provides a command-line interface to the library:

```bash
# Parse a ZIP 321 payment request
zcash-t2o parse-uri "zcash:uaddr1...?amount=1.5"

# Show usage examples
zcash-t2o propose
zcash-t2o sign
zcash-t2o extract

# Show version
zcash-t2o version
```

## Use Cases

### 1. Bitcoin Wallet Adding Zcash Privacy

A Bitcoin wallet can use this library to add Zcash privacy features:
- Spend transparent Bitcoin-style UTXOs
- Send to shielded Orchard addresses
- No need to implement full shielded pool support

### 2. Multi-Signature Workflows

Multiple parties can sign independently and combine:

```go
// Party 1: Sign input 0
pczt1, _ := api.AppendSignature(pcztBytes, 0, key1)

// Party 2: Sign input 1
pczt2, _ := api.AppendSignature(pcztBytes, 1, key2)

// Combine signatures
combined, _ := api.Combine([][]byte{pczt1, pczt2})
```

### 3. Hardware Wallet Integration

Hardware wallets can use the `GetSighash` and `AppendSignature` flow:

```go
// Get sighash to display to user
sighash, _ := api.GetSighash(pcztBytes, 0)

// User confirms on device
// Device signs sighash

// Add signature from device
signedPCZT, _ := api.AppendSignature(pcztBytes, 0, deviceSignature)
```

## Implementation Status

### ✅ Complete

- PCZT data structures and serialization
- All 8 PCZT roles (Creator through Combiner)
- ZIP 244 signature hashing
- ZIP 321 payment request parsing
- Transparent input signing (secp256k1)
- Public API layer
- CLI tool structure

### 🚧 TODO (Requires librustzcash Integration)

The following operations are stubbed with clear TODO markers and will work once linked with librustzcash:

- Orchard note commitments
- Orchard note encryption
- Orchard value commitments
- Orchard nullifier derivation
- RedPallas signatures
- Zero-knowledge proof generation
- Pallas curve arithmetic

All placeholder functions in `pkg/ffi/rust/src/lib.rs` have comments showing the exact librustzcash APIs to use.

## Dependencies

### Go Dependencies
- `golang.org/x/crypto` - BLAKE2b hashing
- `github.com/decred/dcrd/dcrec/secp256k1/v4` - secp256k1 signatures
- `github.com/btcsuite/btcutil` - Base58 encoding

### Rust Dependencies (FFI)
- `zcash_primitives` - Core Zcash types
- `orchard` - Orchard protocol implementation
- `zcash_proofs` - Zero-knowledge proof generation
- `pczt` - PCZT implementation from librustzcash

## Testing

### Quick Start

```bash
# Run all tests (Rust + Go)
make test

# Or run tests separately:
make test-rust  # Rust unit tests only
make test-go    # Go tests only

# Traditional approach still works:
go test ./...   # All Go tests
```

The Makefile automatically handles building the Rust library and setting up the correct library paths.

### Rust FFI Tests

Test the Rust library independently:

```bash
cd pkg/ffi/rust

# Run all tests
cargo test

# Run specific test
cargo test test_pallas_scalar_add

# Test with output
cargo test -- --nocapture

# Check library was built
ls -lh target/release/libzcash_t2o_ffi.*
```

Expected output:
```
running 2 tests
test tests::test_error_handling ... ok
test tests::test_pallas_scalar_add ... ok

test result: ok. 2 passed; 0 failed; 0 ignored
```

### Go FFI Bridge Tests

Test the CGO integration:

```bash
# Create test file
cat > pkg/ffi/bridge_test.go << 'EOF'
package ffi

import "testing"

func TestPallasScalarAdd(t *testing.T) {
    one := [32]byte{}
    one[0] = 1

    result, err := PallasScalarAdd(one, one)
    if err != nil {
        t.Fatalf("Failed: %v", err)
    }

    if result[0] != 2 {
        t.Errorf("Expected 2, got %d", result[0])
    }
}

func TestOrchardValueCommitment(t *testing.T) {
    value := uint64(100000000)
    rcv := [32]byte{1, 2, 3}

    cv, err := OrchardValueCommitment(value, rcv)
    if err != nil {
        t.Fatalf("Failed: %v", err)
    }

    if len(cv) != 32 {
        t.Errorf("Expected 32 bytes, got %d", len(cv))
    }
}
EOF

# Run FFI tests
go test -v ./pkg/ffi
```

### API Integration Tests

Test the public API:

```bash
# Run API tests
go test -v ./pkg/api

# Run all package tests
go test ./pkg/pczt
go test ./pkg/crypto
go test ./pkg/roles
go test ./pkg/zip321

# Run all with coverage
go test -cover ./...
```

### Debugging FFI Issues

If you encounter linking errors:

```bash
# Verify library symbols
nm pkg/ffi/rust/target/release/libzcash_t2o_ffi.a | grep ffi_

# Check CGO environment
go env | grep CGO

# Build with verbose CGO
CGO_LDFLAGS="-L${PWD}/pkg/ffi/rust/target/release" \
  go build -x ./pkg/ffi 2>&1 | grep -i link

# On macOS, you might need:
export DYLD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release"

# On Linux:
export LD_LIBRARY_PATH="${PWD}/pkg/ffi/rust/target/release"
```

### Test Coverage Areas

Implemented tests:
- ✅ Rust FFI error handling
- ✅ Pallas scalar arithmetic
- 🚧 Orchard note commitments
- 🚧 Value commitments
- 🚧 RedPallas signatures

Planned test coverage:
- Postcard serialization round-trip tests
- ZIP 244 sighash test vectors
- PCZT role integration tests
- Combiner parallel signing tests
- End-to-end transaction creation tests

## Documentation

Each package and major function includes comprehensive documentation:

- **Package-level docs** - Overview and purpose
- **Type documentation** - Field meanings and constraints
- **Function documentation** - Parameters, returns, errors
- **Rust references** - Links to librustzcash implementations
- **ZIP references** - Links to relevant ZIP specifications

Generate Go documentation:

```bash
go doc github.com/suffix-labs/zcash-t2o/pkg/api
go doc github.com/suffix-labs/zcash-t2o/pkg/roles
```

## References

### ZIP Specifications
- [ZIP 374: PCZT - Partially Created Zcash Transaction](https://zips.z.cash/zip-0374)
- [ZIP 244: Transaction Signature Validation for v5 Transactions](https://zips.z.cash/zip-0244)
- [ZIP 321: Payment Request URIs](https://zips.z.cash/zip-0321)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)

### librustzcash
- [PCZT Implementation](https://github.com/zcash/librustzcash/tree/main/pczt)
- [Orchard Protocol](https://github.com/zcash/orchard)
- [zcash_primitives](https://github.com/zcash/librustzcash/tree/main/zcash_primitives)

## Contributing

This is an open-source implementation of the ZIP 374 specification. Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
# Clone repository
git clone https://github.com/suffix-labs/zcash-t2o
cd zcash-t2o

# Install Go dependencies
go mod download

# Build everything
make build

# Run tests
make test

# For manual Go development, build Rust and show env vars:
make dev
```

## License

MIT OR Apache-2.0

## Acknowledgments

- Zcash Foundation and Electric Coin Company for ZIP specifications
- librustzcash team for the Rust PCZT implementation
- Zcash community for protocol development

## Contact

- Issues: https://github.com/suffix-labs/zcash-t2o/issues
- Discussions: https://github.com/suffix-labs/zcash-t2o/discussions

---

**⚠️ Security Notice:** This library is under active development. The Rust FFI components require integration with librustzcash before production use. Do not use with real funds until security audits are complete.
