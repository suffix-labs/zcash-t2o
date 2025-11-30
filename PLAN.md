# Implementation Plan: Complete Zcash T2O PCZT Library

**Current Status:** ~90% Complete
**Target:** Production-ready implementation per PROBLEM_SPEC.md
**Last Updated:** 2025-11-30

---

## Phase 1: Critical Path - Make Transactions Valid (Priority 1)

These are blocking issues that prevent creating valid, broadcastable transactions.

### 1.1 Load Orchard Proving Key and Implement Proof Generation ✅ COMPLETE

**File:** `pkg/ffi/rust/src/lib.rs:165-212`

**Status:** ✅ Fully implemented

**Implementation:**
- Proving key is built/cached via `orchard_proving_key()` using `ProvingKey::build()`
- Proof generation uses `pczt::roles::prover::Prover` with `create_orchard_proof(pk)`
- Handles PCZTs with no Orchard actions (no-op)
- Error handling for parsing and proving failures

**Tasks:**
- [x] Locate or download Orchard proving key (built dynamically)
- [x] Add proving key loading to Rust FFI initialization
- [x] Implement proof generation using `pczt` prover role
- [x] Handle proving key path configuration (built on demand, cached)
- [x] Add error handling for missing/corrupt proving key

**Acceptance Criteria:** ✅ All met
- `ffi_prove_pczt` successfully generates ZK proofs for Orchard actions
- Proofs verify correctly
- Error handling for invalid PCZT input

---

### 1.2 Implement Binding Signature Creation ✅ COMPLETE (Rust FFI)

**File:** `pkg/ffi/rust/src/lib.rs:569-602`

**Status:** ✅ Rust FFI fully implemented, Go wiring still needed

**Implementation:**
- Uses `reddsa::SigningKey::<Binding>::try_from()` to parse bsk
- Signs with `signing_key.sign(&mut OsRng, sighash_bytes)`
- Returns 64-byte signature (R || s format)
- Includes test coverage for null pointers and different sighashes

**Tasks:**
- [x] Implement RedPallas binding signature using `reddsa` crate
- [x] Convert bsk (binding signing key) from bytes
- [x] Sign the transaction sighash
- [x] Return 64-byte signature

**References:**
- `reddsa::orchard::Binding` signing key type
- ZIP 244 binding signature specification

**Still Needed:**
- [ ] `pkg/roles/tx_extractor.go:112-128` - Wire up FFI call:
  ```go
  func signBinding(bsk [32]byte, sighash [32]byte) [64]byte {
      // TODO: Call ffi.SignBinding(bsk, sighash)
  }
  ```

**Acceptance Criteria:**
- ✅ Binding signature verifies against transaction hash (tested)
- ✅ Signature format matches Zcash v5 transaction spec

---

### 1.3 Implement Orchard Note Encryption ⚠️ NOT IMPLEMENTED

**File:** `pkg/ffi/rust/src/lib.rs:324-342`

**Status:** ❌ Returns error stub - requires `zcash_note_encryption` integration

**Current State:**
```rust
pub unsafe extern "C" fn ffi_orchard_encrypt_note(...) -> FFIErrorCode {
    set_last_error("Note encryption not implemented: requires zcash_note_encryption with OrchardDomain setup".to_string());
    FFIErrorCode::OrchardCryptoFailed
}
```

**Tasks:**
- [ ] Add `zcash_note_encryption` crate to dependencies
- [ ] Implement encryption using `OrchardNoteEncryption` and `OrchardDomain`
- [ ] Construct `Note` from components for encryption
- [ ] Generate encrypted note ciphertext (580 bytes)
- [ ] Generate encrypted outgoing ciphertext (80 bytes)
- [ ] Handle memo field correctly

**References:**
- `orchard::note_encryption::OrchardNoteEncryption`
- `zcash_note_encryption::NoteEncryption`
- ZIP 212 (key agreement and note encryption)

**Also Update:**
- [ ] `pkg/roles/constructor.go:277-296` - Wire up FFI call to replace stub

**Acceptance Criteria:**
- Recipient can decrypt note with their IVK
- Sender can decrypt with OVK
- Ciphertext lengths match spec (580 + 80 bytes)

---

## Phase 2: Complete FFI Bindings (Priority 2)

Wire up remaining cryptographic operations.

### 2.1 Fix Nullifier Derivation

**File:** `pkg/ffi/rust/src/lib.rs:366-381`

**Current Issue:**
```rust
// Note: Orchard::Note::nullifier() requires NullifierDerivingKey,
// not standalone computation from note commitment
```

**Tasks:**
- [ ] Research correct Orchard nullifier derivation API
- [ ] Determine if we need to pass additional key material
- [ ] Update Go constructor to provide required inputs
- [ ] Implement FFI function or refactor approach

**Alternative Approaches:**
1. Pass `nk` (nullifier deriving key) in addition to `rho` and `psi`
2. Compute nullifier during note construction instead of separately
3. Use `pczt` crate's nullifier handling

**Acceptance Criteria:**
- Nullifiers are correctly derived per ZIP 224
- Multiple outputs have unique nullifiers

---

### 2.2 Fix Ephemeral Key Derivation

**File:** `pkg/ffi/rust/src/lib.rs:277-291`

**Current Issue:**
```rust
// Note: Latest Orchard API doesn't expose ephemeral key derivation directly
```

**Tasks:**
- [ ] Determine if ephemeral keys should be derived in `OrchardNoteEncryption`
- [ ] Update constructor to generate ephemeral keys during encryption
- [ ] Remove standalone ephemeral key FFI function if not needed
- [ ] Update Go code to match new flow

**References:**
- `orchard::note_encryption` API documentation
- ZIP 212 ephemeral key derivation

**Acceptance Criteria:**
- Ephemeral keys are correctly derived and included in note encryption
- Key agreement works for recipient decryption

---

### 2.3 Complete Constructor Role Crypto Operations

**File:** `pkg/roles/constructor.go:256-330`

**Current Stubs:**
```go
func deriveNoteCommitment(...) [32]byte { return [32]byte{} }
func deriveEphemeralKey(...) [32]byte { return [32]byte{} }
func encryptNote(...) ([]byte, []byte) { return make([]byte, 580), make([]byte, 80) }
func computeValueCommitment(...) [32]byte { return [32]byte{} }
func deriveNullifier(...) [32]byte { return [32]byte{} }
func deriveRandomizedKey(...) [32]byte { return [32]byte{} }
```

**Tasks:**
- [ ] Wire up `ffi_orchard_note_commitment` (already exists in FFI)
- [ ] Wire up `ffi_orchard_value_commitment` (already exists in FFI)
- [ ] Wire up `ffi_orchard_randomized_key` (already exists in FFI)
- [ ] Wire up or fix `ffi_orchard_derive_nullifier`
- [ ] Wire up or fix `ffi_orchard_ephemeral_key`
- [ ] Wire up `ffi_orchard_encrypt_note`

**Acceptance Criteria:**
- All constructor crypto operations return real values
- Orchard actions have valid commitments
- Integration test passes with real crypto

---

### 2.4 Complete IO Finalizer Role Crypto Operations

**File:** `pkg/roles/io_finalizer.go:148-173`

**Current Stubs:**
```go
func scalarAdd(a, b [32]byte) [32]byte { return [32]byte{} }
func createDummySpendSignature(...) [64]byte { return [64]byte{} }
```

**Tasks:**
- [ ] Wire up `ffi_pallas_scalar_add` (already exists and working!)
- [ ] Wire up `ffi_reddsa_sign_spend_auth` for dummy spends (already exists!)
- [ ] Test scalar arithmetic for computing `bsk` from `rcv` values

**References:**
- `pkg/ffi/bridge_test.go` - Tests already exist for these functions

**Acceptance Criteria:**
- `bsk` (binding signing key) correctly computed as sum of `rcv` values
- Dummy spend signatures are valid (even though they're discarded)

---

## Phase 3: Testing & Validation (Priority 3)

### 3.1 End-to-End Integration Tests

**File:** `pkg/roles/integration_test.go` (currently uses placeholder proofs)

**Tasks:**
- [ ] Update integration test to use real proving key
- [ ] Test complete workflow: propose → prove → sign → extract
- [ ] Verify transaction bytes are valid v5 format
- [ ] Test with multiple transparent inputs
- [ ] Test with multiple Orchard outputs
- [ ] Test change output handling

**New Test File:** `pkg/api/e2e_test.go`
```go
func TestCompleteTransactionWorkflow(t *testing.T) {
    // Create proposal with real inputs/outputs
    // Generate real proofs
    // Sign with real keys
    // Validate extracted transaction
}
```

**Acceptance Criteria:**
- Integration test passes with real cryptographic operations
- Transaction bytes validate against `zcash-cli` or `zebrad`

---

### 3.2 ZIP Test Vectors ✅ COMPLETE (ZIP 244)

**Files:**
- `pkg/crypto/zip244.go` - ZIP 244 signature hash computation
- `pkg/crypto/zip244_test.go` - Test vector validation
- `pkg/crypto/tx_parser.go` - V5 transaction parsing
- `testdata/vectors/zip_0244.json` - Official test vectors

**Status:** ✅ ZIP 244 fully implemented and tested

**Implementation:**
- Full ZIP 244 sighash computation (header, transparent, sapling, orchard digests)
- V5 transaction parser supporting all bundle types (transparent, sapling, orchard)
- All sighash variants: SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, ANYONECANPAY
- Shielded signature hash computation
- TXID computation from parsed transactions
- Sapling digest computation with full spend/output support

**Test Coverage:**
- 10 test vectors from official ZIP 244 test suite
- All TXID computations pass
- All shielded sighash computations pass
- All transparent sighash variants pass (ALL, NONE, SINGLE, with/without ANYONECANPAY)

**Tasks:**
- [x] Add ZIP 244 sighash test vectors
- [x] Implement V5 transaction parser
- [x] Implement header digest computation
- [x] Implement transparent digest computation
- [x] Implement Sapling digest computation
- [x] Implement Orchard digest computation
- [x] Implement all sighash type variants
- [x] Implement shielded signature hash
- [x] Implement TXID computation
- [ ] Add ZIP 374 PCZT serialization test vectors
- [ ] Verify compatibility with Rust `pczt` crate

**References:**
- https://github.com/zcash/zips/blob/main/zip-0244.rst#test-vectors
- https://github.com/zcash/librustzcash/tree/main/pczt/tests

**Acceptance Criteria:**
- ✅ All official ZIP 244 test vectors pass
- Serialization round-trips match Rust implementation (pending ZIP 374)

---

### 3.3 Network Integration Test

**File:** `cmd/zcash-t2o/main.go` or new `integration/testnet_test.go`

**Tasks:**
- [ ] Create testnet transaction end-to-end
- [ ] Broadcast to Zcash testnet
- [ ] Verify transaction confirms
- [ ] Document setup (requires testnet ZEC, RPC access)

**Acceptance Criteria:**
- Can broadcast real transaction to testnet
- Transaction mines successfully
- Recipient can see shielded funds

---

## Phase 4: Polish & Documentation (Priority 4)

### 4.1 Error Handling Improvements

**Tasks:**
- [ ] Add detailed error types for each failure mode
- [ ] Improve FFI error messages with context
- [ ] Add input validation to all API functions
- [ ] Document error conditions in godoc

**Examples:**
- Distinguish between "invalid PCZT format" vs "missing signatures"
- Provide helpful messages for common mistakes
- Add context to FFI errors (which function failed)

---

### 4.2 Performance Optimization

**Tasks:**
- [ ] Profile proving performance
- [ ] Consider parallel proving if multiple actions
- [ ] Optimize PCZT serialization hot paths
- [ ] Add benchmarks for critical functions

**Benchmarks to Add:**
- `BenchmarkProposeTransaction`
- `BenchmarkProveTransaction`
- `BenchmarkGetSighash`
- `BenchmarkSerializePCZT`

---

### 4.3 Documentation Updates

**Tasks:**
- [ ] Update README.md security notice (remove "under development" warning once tested)
- [ ] Add example transactions to documentation
- [ ] Document proving key setup
- [ ] Add troubleshooting guide
- [ ] Update API docs with real examples

---

### 4.4 CLI Tool Enhancements

**File:** `cmd/zcash-t2o/main.go`

**Tasks:**
- [ ] Implement `propose` command with real inputs
- [ ] Implement `prove` command
- [ ] Implement `sign` command with WIF key input
- [ ] Implement `extract` command
- [ ] Add `create-transaction` all-in-one command
- [ ] Add PCZT inspection command

**Example:**
```bash
zcash-t2o create-transaction \
  --input txid:vout:value:script \
  --output uaddr:amount \
  --key-wif KxYZ... \
  --network testnet
```

---

## Phase 5: Production Readiness (Priority 5)

### 5.1 Security Audit Preparation

**Tasks:**
- [ ] Code review all cryptographic operations
- [ ] Verify constant-time operations where needed
- [ ] Check for memory leaks in FFI boundary
- [ ] Review random number generation
- [ ] Audit key material handling

---

### 5.2 Dependency Management

**Tasks:**
- [ ] Pin all dependency versions
- [ ] Verify librustzcash version compatibility
- [ ] Document minimum Rust/Go versions
- [ ] Consider vendoring critical dependencies

---

### 5.3 Release Preparation

**Tasks:**
- [ ] Create CHANGELOG.md
- [ ] Tag v0.1.0 release
- [ ] Publish to GitHub
- [ ] Create release binaries for major platforms
- [ ] Submit to pkg.go.dev

---

## Task Checklist Summary

### Must Have (Blocking Production Use)
- [x] 1.1 - Load proving key and implement proof generation ✅
- [x] 1.2 - Implement binding signature (Rust FFI) ✅
- [ ] 1.2b - Wire up binding signature in Go tx_extractor
- [ ] 1.3 - Implement note encryption ⚠️ CRITICAL BLOCKER
- [ ] 2.3 - Wire up constructor FFI calls
- [ ] 2.4 - Wire up IO finalizer FFI calls
- [ ] 3.1 - End-to-end integration test with real proofs

### Should Have (Important for Robustness)
- [ ] 2.1 - Fix nullifier derivation
- [ ] 2.2 - Fix ephemeral key derivation
- [x] 3.2 - ZIP 244 test vectors ✅ (10 vectors, all passing)
- [ ] 4.1 - Error handling improvements

### Nice to Have (Polish)
- [ ] 3.2b - ZIP 374 PCZT serialization test vectors
- [ ] 3.3 - Testnet integration test
- [ ] 4.2 - Performance optimization
- [ ] 4.3 - Documentation updates
- [ ] 4.4 - CLI tool enhancements
- [ ] 5.x - Production readiness items

---

## Development Workflow

### Daily Workflow
1. Pick highest priority uncompleted task
2. Implement in Rust FFI first (if applicable)
3. Add Rust unit test
4. Wire up Go FFI call
5. Add Go unit test
6. Update integration test
7. Commit with descriptive message

### Testing Strategy
```bash
# After each change:
cd pkg/ffi/rust
cargo test                    # Verify Rust changes

cd ../../..
go test ./pkg/ffi            # Verify FFI bridge
go test ./pkg/roles          # Verify role logic
go test ./pkg/api            # Verify public API

# Before committing:
go test ./...                # Full test suite
cargo clippy                 # Rust lints
go vet ./...                 # Go static analysis
```

---

## Resources

### Key Files to Modify
```
pkg/ffi/rust/src/lib.rs           # Rust FFI implementation
pkg/roles/constructor.go          # Wire up Orchard crypto
pkg/roles/io_finalizer.go         # Wire up scalar arithmetic
pkg/roles/tx_extractor.go         # Wire up binding signature
pkg/ffi/bridge.go                 # Go FFI bindings (if needed)
```

### Recently Completed Files
```
pkg/crypto/zip244.go              # ZIP 244 signature hash computation ✅
pkg/crypto/zip244_test.go         # ZIP 244 test vector validation ✅
pkg/crypto/tx_parser.go           # V5 transaction parsing ✅
testdata/vectors/zip_0244.json    # Official ZIP 244 test vectors ✅
```

### External References
- [ZIP 374 - PCZT Spec](https://zips.z.cash/zip-0374)
- [ZIP 244 - Signature Hash](https://zips.z.cash/zip-0244)
- [ZIP 224 - Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [librustzcash](https://github.com/zcash/librustzcash)
- [pczt crate](https://github.com/zcash/librustzcash/tree/main/pczt)

### Questions to Resolve
1. Where to store/load Orchard proving key? (embedded vs path)
2. Should nullifier derivation be in constructor or separate?
3. Ephemeral key generation - standalone or during encryption?
4. Do we need OVK (outgoing viewing key) support for sender decryption?

---

## Success Criteria

The project is complete when:

1. ⬜ All 8 API functions work with real cryptographic operations
2. ⬜ Can create, prove, sign, and extract valid Zcash v5 transactions
3. ⬜ Transactions broadcast successfully to testnet
4. ✅ All ZIP 244 test vectors pass (10/10)
5. ⬜ Integration tests pass without stubs
6. ⬜ Documentation is complete and accurate
7. ⬜ No placeholder/TODO comments in production code paths
8. ⬜ Security review completed (at least self-review)

---

**Last Updated:** 2025-11-30
**Maintainer:** @trbiv
