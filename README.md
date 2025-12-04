# zcash-t2o

**Transparent-to-Orchard PCZT Library for Go**

A Go implementation of PCZT (Partially Created Zcash Transaction) based on [ZIP 374](https://github.com/zcash/zips/pull/1063), enabling Bitcoin-style wallets to send shielded Orchard outputs.

**Key Features:**
- Complete PCZT role implementation (Creator, Constructor, Signer, Prover, etc.)
- ZIP 244 transaction signature hashing and ZIP 321 payment URIs
- Rust FFI for Orchard cryptographic operations
- Multi-signature support via Combiner role

## Installation

**Prerequisites:** Go 1.21+, Rust toolchain, CGO enabled

```bash
# Install library
go get github.com/suffix-labs/zcash-t2o

# Build (Rust FFI + Go binary)
make build
```

## Quick Start

```go
import "github.com/suffix-labs/zcash-t2o/pkg/api"

// 1. Create PCZT from transparent inputs to Orchard outputs
proposal := &api.TransactionProposal{
    ConsensusBranchID: 0xC2D6D0B4, // NU5
    ExpiryHeight:      2500000,
    CoinType:          1, // Testnet
    TransparentInputs: []api.TransparentInput{...},
    OrchardOutputs:    []api.OrchardOutput{...},
}
pcztBytes, _ := api.ProposeTransaction(proposal)

// 2. Generate zero-knowledge proofs
provedBytes, _ := api.ProveTransaction(pcztBytes)

// 3. Sign transparent inputs
sighash, _ := api.GetSighash(provedBytes, 0)
signedBytes, _ := api.AppendSignature(provedBytes, 0, privateKey)

// 4. Extract and broadcast final transaction
txBytes, _ := api.FinalizeAndExtract(signedBytes)
```

See `pkg/roles/integration_test.go` for complete examples.

## Architecture

**PCZT Roles:** Creator → Constructor → IO Finalizer → Prover → Signer → Spend Finalizer → Transaction Extractor (+ Combiner for parallel signing)

**Package Structure:**
- `pkg/api/` - Public API (8 core functions)
- `pkg/pczt/` - PCZT types and serialization
- `pkg/crypto/` - ZIP 244 sighash, secp256k1
- `pkg/roles/` - PCZT role implementations
- `pkg/zip321/` - Payment request URI parser
- `pkg/ffi/` - Rust FFI bridge (Orchard crypto operations)

## API Reference

**Core Functions:** `ProposeTransaction`, `ProveTransaction`, `VerifyBeforeSigning`, `GetSighash`, `AppendSignature`, `Combine`, `FinalizeAndExtract`, `ParsePCZT`/`SerializePCZT`

**ZIP 321:** Parse and encode payment request URIs (`pkg/zip321`)

**CLI Tool:** `zcash-t2o parse-uri`, `propose`, `sign`, `extract`, `version`

## Use Cases

- **Bitcoin wallets** - Add Zcash privacy without implementing full shielded pool support
- **Multi-signature** - Multiple parties sign independently and combine via `Combine()`
- **Hardware wallets** - Get sighash for user confirmation, add signature from device

## Implementation Status

### ✅ Complete

- PCZT data structures, serialization, and all 8 PCZT roles
- ZIP 244 signature hashing and ZIP 321 payment URIs
- Transparent input signing (secp256k1)
- **Rust FFI integration:**
  - Zero-knowledge proof generation via librustzcash
  - Orchard note commitments and encryption
  - Orchard value commitments
  - RedPallas signatures (spend auth and binding)
  - Pallas curve arithmetic
  - Dummy spend generation for T2O transactions
- Integration tests for end-to-end transparent-to-Orchard flows

### 🚧 TODO

- **Testing:** Additional edge case coverage and mainnet validation
- **Documentation:** API examples and troubleshooting guide
- **Performance:** Benchmark proof generation and transaction building
- **Security:** External audit before production use

## Dependencies

**Go:** `golang.org/x/crypto`, `github.com/decred/dcrd/dcrec/secp256k1/v4`, `github.com/btcsuite/btcutil`

**Rust (FFI):** `orchard`, `zcash_primitives`, `zcash_proofs`, `pczt`, `reddsa`

## Testing

```bash
# Run all tests (Rust + Go)
make test

# Run specific tests
make test-rust  # Rust only
make test-go    # Go only
go test ./pkg/roles  # Specific package

# With coverage
go test -cover ./...
```

See `pkg/roles/integration_test.go` for end-to-end examples.

## References

**ZIPs:** [374 (PCZT)](https://zips.z.cash/zip-0374) | [244 (Signatures)](https://zips.z.cash/zip-0244) | [321 (Payment URIs)](https://zips.z.cash/zip-0321) | [225 (Transaction Format)](https://zips.z.cash/zip-0225)

**librustzcash:** [PCZT](https://github.com/zcash/librustzcash/tree/main/pczt) | [Orchard](https://github.com/zcash/orchard) | [Primitives](https://github.com/zcash/librustzcash/tree/main/zcash_primitives)

## Contributing

```bash
git clone https://github.com/suffix-labs/zcash-t2o
cd zcash-t2o
make build
make test
```

Contributions welcome! Please add tests for new functionality.

## License

MIT OR Apache-2.0

---

**⚠️ Security Notice:** This library is under active development. Do not use with real funds until security audits are complete.

**Issues:** https://github.com/suffix-labs/zcash-t2o/issues
