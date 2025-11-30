// Package ffi provides CGO bindings to the Rust FFI library.
//
// This package bridges Go code with Rust implementations of Orchard
// cryptographic operations that cannot be efficiently implemented in pure Go.
//
// Build requirements:
//   - Rust toolchain (cargo, rustc)
//   - The Rust library must be built before using this package
//
// Build the Rust library:
//
//	cd pkg/ffi/rust && cargo build --release
//
// The CGO directives below link against the compiled Rust library.
package ffi

/*
#cgo LDFLAGS: -L${SRCDIR}/rust/target/release -lzcash_t2o_ffi
#cgo darwin LDFLAGS: -framework Security -framework Foundation
#cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}/rust/target/release
#cgo linux LDFLAGS: -ldl -lm
#cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}/rust/target/release

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// FFI error codes
typedef enum {
    FFI_OK = 0,
    FFI_ERROR_NULL_POINTER = 1,
    FFI_ERROR_INVALID_PCZT = 2,
    FFI_ERROR_PROVING_FAILED = 3,
    FFI_ERROR_SERIALIZATION_FAILED = 4,
    FFI_ERROR_ORCHARD_CRYPTO_FAILED = 5,
} FFIErrorCode;

// FFI result type
typedef struct {
    FFIErrorCode error_code;
    uint8_t *data;
    size_t data_len;
} FFIResult;

// Function declarations (from bindings.h)
void ffi_free_bytes(uint8_t *ptr, size_t len);
char *ffi_last_error_message(void);
void ffi_free_string(char *s);

FFIResult ffi_prove_pczt(const uint8_t *pczt_bytes, size_t pczt_len);

FFIErrorCode ffi_orchard_note_commitment(
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rseed[32],
    const uint8_t rho[32],
    uint8_t cmx_out[32]
);

FFIErrorCode ffi_orchard_ephemeral_key(
    const uint8_t esk[32],
    uint8_t epk_out[32]
);

FFIErrorCode ffi_orchard_encrypt_note(
    const uint8_t recipient[43],
    uint64_t value,
    const uint8_t rho[32],
    const uint8_t rseed[32],
    const uint8_t memo[512],
    const uint8_t rcv[32],
    uint8_t enc_ciphertext_out[580],
    uint8_t out_ciphertext_out[80],
    uint8_t epk_out[32],
    uint8_t cmx_out[32]
);

FFIErrorCode ffi_orchard_value_commitment(
    uint64_t value,
    const uint8_t rcv[32],
    uint8_t cv_out[32]
);

FFIErrorCode ffi_orchard_derive_nullifier(
    const uint8_t rho[32],
    const uint8_t sk[32],
    uint8_t nf_out[32]
);

FFIErrorCode ffi_orchard_randomized_key(
    const uint8_t sk[32],
    const uint8_t alpha[32],
    uint8_t rk_out[32]
);

FFIErrorCode ffi_pallas_scalar_add(
    const uint8_t a[32],
    const uint8_t b[32],
    uint8_t result_out[32]
);

FFIErrorCode ffi_reddsa_sign_spend_auth(
    const uint8_t sk[32],
    const uint8_t alpha[32],
    const uint8_t sighash[32],
    uint8_t sig_out[64]
);

FFIErrorCode ffi_reddsa_sign_binding(
    const uint8_t bsk[32],
    const uint8_t sighash[32],
    uint8_t sig_out[64]
);

FFIErrorCode ffi_orchard_test_address(
    const uint8_t seed[32],
    uint8_t address_out[43]
);

FFIErrorCode ffi_orchard_generate_dummy_rho(
    uint8_t rho_out[32]
);

FFIErrorCode ffi_orchard_generate_rcv(
    uint8_t rcv_out[32]
);

FFIErrorCode ffi_orchard_generate_dummy_nullifier(
    uint8_t nullifier_out[32]
);

FFIErrorCode ffi_orchard_generate_dummy_sk(
    uint8_t sk_out[32]
);

FFIErrorCode ffi_orchard_derive_fvk(
    const uint8_t sk[32],
    uint8_t fvk_out[96]
);

FFIErrorCode ffi_orchard_generate_dummy_witness(
    uint32_t *position_out,
    uint8_t path_out[1024]
);

FFIErrorCode ffi_orchard_create_dummy_spend(
    uint8_t output_out[1359]
);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// FFIError represents an error returned from the Rust FFI.
type FFIError struct {
	Code    int
	Message string
}

func (e *FFIError) Error() string {
	return fmt.Sprintf("FFI error %d: %s", e.Code, e.Message)
}

// getLastError retrieves the last error message from Rust.
func getLastError(code C.FFIErrorCode) error {
	if code == C.FFI_OK {
		return nil
	}

	// Get error message from Rust
	cMsg := C.ffi_last_error_message()
	if cMsg == nil {
		return &FFIError{
			Code:    int(code),
			Message: "unknown error (no message available)",
		}
	}
	defer C.ffi_free_string(cMsg)

	msg := C.GoString(cMsg)
	return &FFIError{
		Code:    int(code),
		Message: msg,
	}
}

// ============================================================================
// Prover operations
// ============================================================================

// ProvePCZT generates Orchard ZK proofs for a PCZT.
//
// This calls into the Rust implementation to generate zero-knowledge proofs
// for all Orchard actions in the PCZT.
//
// Parameters:
//   - pcztBytes: Serialized PCZT bytes
//
// Returns:
//   - Serialized PCZT with proofs attached
//   - Error if proving fails
func ProvePCZT(pcztBytes []byte) ([]byte, error) {
	if len(pcztBytes) == 0 {
		return nil, fmt.Errorf("empty PCZT bytes")
	}

	result := C.ffi_prove_pczt(
		(*C.uint8_t)(unsafe.Pointer(&pcztBytes[0])),
		C.size_t(len(pcztBytes)),
	)
	if result.error_code != C.FFI_OK {
		return nil, getLastError(result.error_code)
	}

	// Copy result data to Go
	if result.data == nil || result.data_len == 0 {
		return nil, fmt.Errorf("prover returned empty result")
	}

	output := C.GoBytes(unsafe.Pointer(result.data), C.int(result.data_len))

	// Free Rust-allocated memory
	C.ffi_free_bytes(result.data, result.data_len)

	return output, nil
}

// ============================================================================
// Orchard cryptographic operations
// ============================================================================

// OrchardNoteCommitment derives an Orchard note commitment.
//
// Parameters:
//   - recipient: 43-byte Orchard address
//   - value: Note value in zatoshis
//   - rseed: 32-byte random seed
//   - rho: 32-byte nullifier base
//
// Returns:
//   - 32-byte note commitment
//   - Error if derivation fails
func OrchardNoteCommitment(
	recipient [43]byte,
	value uint64,
	rseed [32]byte,
	rho [32]byte,
) ([32]byte, error) {
	var cmx [32]byte

	code := C.ffi_orchard_note_commitment(
		(*C.uint8_t)(unsafe.Pointer(&recipient[0])),
		C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&rseed[0])),
		(*C.uint8_t)(unsafe.Pointer(&rho[0])),
		(*C.uint8_t)(unsafe.Pointer(&cmx[0])),
	)

	if code != C.FFI_OK {
		return cmx, getLastError(code)
	}

	return cmx, nil
}

// OrchardEphemeralKey derives an Orchard ephemeral public key.
//
// Parameters:
//   - esk: 32-byte ephemeral secret key
//
// Returns:
//   - 32-byte ephemeral public key
//   - Error if derivation fails
func OrchardEphemeralKey(esk [32]byte) ([32]byte, error) {
	var epk [32]byte

	code := C.ffi_orchard_ephemeral_key(
		(*C.uint8_t)(unsafe.Pointer(&esk[0])),
		(*C.uint8_t)(unsafe.Pointer(&epk[0])),
	)

	if code != C.FFI_OK {
		return epk, getLastError(code)
	}

	return epk, nil
}

// OrchardEncryptNote encrypts an Orchard note.
//
// This function creates a complete encrypted note including the note commitment
// and ephemeral public key. It replaces the need to call separate functions for
// commitment derivation and ephemeral key generation.
//
// Parameters:
//   - recipient: 43-byte Orchard address
//   - value: Note value in zatoshis
//   - rho: 32-byte nullifier base (from dummy spend)
//   - rseed: 32-byte random seed for note
//   - memo: 512-byte memo field
//   - rcv: 32-byte value commitment randomness
//
// Returns:
//   - 580-byte encrypted ciphertext
//   - 80-byte outgoing ciphertext
//   - 32-byte ephemeral public key
//   - 32-byte note commitment (cmx)
//   - Error if encryption fails
func OrchardEncryptNote(
	recipient [43]byte,
	value uint64,
	rho [32]byte,
	rseed [32]byte,
	memo [512]byte,
	rcv [32]byte,
) (encCiphertext []byte, outCiphertext []byte, epk [32]byte, cmx [32]byte, err error) {
	encCiphertext = make([]byte, 580)
	outCiphertext = make([]byte, 80)

	code := C.ffi_orchard_encrypt_note(
		(*C.uint8_t)(unsafe.Pointer(&recipient[0])),
		C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&rho[0])),
		(*C.uint8_t)(unsafe.Pointer(&rseed[0])),
		(*C.uint8_t)(unsafe.Pointer(&memo[0])),
		(*C.uint8_t)(unsafe.Pointer(&rcv[0])),
		(*C.uint8_t)(unsafe.Pointer(&encCiphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&outCiphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&epk[0])),
		(*C.uint8_t)(unsafe.Pointer(&cmx[0])),
	)

	if code != C.FFI_OK {
		return nil, nil, [32]byte{}, [32]byte{}, getLastError(code)
	}

	return encCiphertext, outCiphertext, epk, cmx, nil
}

// OrchardValueCommitment computes an Orchard value commitment.
//
// Parameters:
//   - value: Note value in zatoshis
//   - rcv: 32-byte randomness
//
// Returns:
//   - 32-byte value commitment
//   - Error if computation fails
func OrchardValueCommitment(value uint64, rcv [32]byte) ([32]byte, error) {
	var cv [32]byte

	code := C.ffi_orchard_value_commitment(
		C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&rcv[0])),
		(*C.uint8_t)(unsafe.Pointer(&cv[0])),
	)

	if code != C.FFI_OK {
		return cv, getLastError(code)
	}

	return cv, nil
}

// OrchardDeriveNullifier derives an Orchard nullifier.
//
// Parameters:
//   - rho: 32-byte nullifier base
//   - sk: 32-byte spending key
//
// Returns:
//   - 32-byte nullifier
//   - Error if derivation fails
func OrchardDeriveNullifier(rho [32]byte, sk [32]byte) ([32]byte, error) {
	var nf [32]byte

	code := C.ffi_orchard_derive_nullifier(
		(*C.uint8_t)(unsafe.Pointer(&rho[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&nf[0])),
	)

	if code != C.FFI_OK {
		return nf, getLastError(code)
	}

	return nf, nil
}

// OrchardRandomizedKey derives an Orchard randomized verification key.
//
// Parameters:
//   - sk: 32-byte spending key
//   - alpha: 32-byte randomizer
//
// Returns:
//   - 32-byte randomized key
//   - Error if derivation fails
func OrchardRandomizedKey(sk [32]byte, alpha [32]byte) ([32]byte, error) {
	var rk [32]byte

	code := C.ffi_orchard_randomized_key(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&alpha[0])),
		(*C.uint8_t)(unsafe.Pointer(&rk[0])),
	)

	if code != C.FFI_OK {
		return rk, getLastError(code)
	}

	return rk, nil
}

// PallasScalarAdd adds two Pallas scalars.
//
// Parameters:
//   - a: 32-byte scalar
//   - b: 32-byte scalar
//
// Returns:
//   - 32-byte result (a + b mod r)
//   - Error if addition fails
func PallasScalarAdd(a [32]byte, b [32]byte) ([32]byte, error) {
	var result [32]byte

	code := C.ffi_pallas_scalar_add(
		(*C.uint8_t)(unsafe.Pointer(&a[0])),
		(*C.uint8_t)(unsafe.Pointer(&b[0])),
		(*C.uint8_t)(unsafe.Pointer(&result[0])),
	)

	if code != C.FFI_OK {
		return result, getLastError(code)
	}

	return result, nil
}

// RedDSASignSpendAuth creates a RedPallas spend authorization signature.
//
// Parameters:
//   - sk: 32-byte spending key
//   - alpha: 32-byte randomizer
//   - sighash: 32-byte transaction hash
//
// Returns:
//   - 64-byte RedPallas signature
//   - Error if signing fails
func RedDSASignSpendAuth(sk [32]byte, alpha [32]byte, sighash [32]byte) ([64]byte, error) {
	var sig [64]byte

	code := C.ffi_reddsa_sign_spend_auth(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&alpha[0])),
		(*C.uint8_t)(unsafe.Pointer(&sighash[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)

	if code != C.FFI_OK {
		return sig, getLastError(code)
	}

	return sig, nil
}

// RedDSASignBinding creates a RedPallas binding signature.
//
// Parameters:
//   - bsk: 32-byte binding signature key
//   - sighash: 32-byte transaction hash
//
// Returns:
//   - 64-byte RedPallas signature
//   - Error if signing fails
func RedDSASignBinding(bsk [32]byte, sighash [32]byte) ([64]byte, error) {
	var sig [64]byte

	code := C.ffi_reddsa_sign_binding(
		(*C.uint8_t)(unsafe.Pointer(&bsk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sighash[0])),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)

	if code != C.FFI_OK {
		return sig, getLastError(code)
	}

	return sig, nil
}

// OrchardTestAddress generates a valid Orchard address from a 32-byte seed.
//
// This is useful for testing - it creates a real Orchard address that can be
// used for encryption and decryption tests.
//
// Parameters:
//   - seed: 32-byte seed (will be used to derive SpendingKey)
//
// Returns:
//   - 43-byte Orchard address
//   - Error if derivation fails
func OrchardTestAddress(seed [32]byte) ([43]byte, error) {
	var address [43]byte

	code := C.ffi_orchard_test_address(
		(*C.uint8_t)(unsafe.Pointer(&seed[0])),
		(*C.uint8_t)(unsafe.Pointer(&address[0])),
	)

	if code != C.FFI_OK {
		return address, getLastError(code)
	}

	return address, nil
}

// OrchardGenerateDummyRho generates a valid rho (nullifier base) for dummy spends.
//
// In Orchard, rho must be a valid Pallas base field element. This function
// generates a cryptographically random valid rho for use in dummy spends
// (transparent-to-Orchard transactions).
//
// Returns:
//   - 32-byte valid rho
//   - Error if generation fails
func OrchardGenerateDummyRho() ([32]byte, error) {
	var rho [32]byte

	code := C.ffi_orchard_generate_dummy_rho(
		(*C.uint8_t)(unsafe.Pointer(&rho[0])),
	)

	if code != C.FFI_OK {
		return rho, getLastError(code)
	}

	return rho, nil
}

// OrchardGenerateRcv generates a valid value commitment randomness (rcv).
//
// The rcv must be a valid Pallas scalar. This function generates a
// cryptographically random valid scalar for use in value commitments.
//
// Returns:
//   - 32-byte valid rcv
//   - Error if generation fails
func OrchardGenerateRcv() ([32]byte, error) {
	var rcv [32]byte

	code := C.ffi_orchard_generate_rcv(
		(*C.uint8_t)(unsafe.Pointer(&rcv[0])),
	)

	if code != C.FFI_OK {
		return rcv, getLastError(code)
	}

	return rcv, nil
}

// OrchardGenerateDummyNullifier generates a valid dummy nullifier.
//
// Nullifiers in Orchard must be valid Pallas base field elements.
// For dummy spends in T2O transactions, we need nullifiers that are valid
// but don't correspond to any real note.
//
// Returns:
//   - 32-byte valid nullifier
//   - Error if generation fails
func OrchardGenerateDummyNullifier() ([32]byte, error) {
	var nf [32]byte

	code := C.ffi_orchard_generate_dummy_nullifier(
		(*C.uint8_t)(unsafe.Pointer(&nf[0])),
	)

	if code != C.FFI_OK {
		return nf, getLastError(code)
	}

	return nf, nil
}

// OrchardGenerateDummySk generates a valid random spending key for dummy spends.
//
// In T2O transactions, we need dummy spends with valid spending keys.
// This generates a random valid SpendingKey by trying random seeds until
// one produces a valid key.
//
// Returns:
//   - 32-byte valid spending key
//   - Error if generation fails
func OrchardGenerateDummySk() ([32]byte, error) {
	var sk [32]byte

	code := C.ffi_orchard_generate_dummy_sk(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)

	if code != C.FFI_OK {
		return sk, getLastError(code)
	}

	return sk, nil
}

// OrchardDeriveFvk derives the Full Viewing Key from a spending key.
//
// The FVK is 96 bytes and is required by the prover to generate proofs.
//
// Returns:
//   - 96-byte Full Viewing Key
//   - Error if derivation fails
func OrchardDeriveFvk(sk [32]byte) ([96]byte, error) {
	var fvk [96]byte

	code := C.ffi_orchard_derive_fvk(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&fvk[0])),
	)

	if code != C.FFI_OK {
		return fvk, getLastError(code)
	}

	return fvk, nil
}

// OrchardGenerateDummyWitness generates a dummy Merkle witness for dummy spends.
//
// Returns:
//   - position: Leaf position in the tree
//   - path: 32 x 32-byte hashes (one per tree level)
//   - Error if generation fails
func OrchardGenerateDummyWitness() (uint32, [32][32]byte, error) {
	var position C.uint32_t
	var pathBytes [1024]byte

	code := C.ffi_orchard_generate_dummy_witness(
		&position,
		(*C.uint8_t)(unsafe.Pointer(&pathBytes[0])),
	)

	if code != C.FFI_OK {
		return 0, [32][32]byte{}, getLastError(code)
	}

	// Convert flat bytes to structured path
	var path [32][32]byte
	for i := 0; i < 32; i++ {
		copy(path[i][:], pathBytes[i*32:(i+1)*32])
	}

	return uint32(position), path, nil
}

// DummySpendData contains all the fields for a cryptographically consistent dummy spend.
type DummySpendData struct {
	Nullifier       [32]byte
	Rk              [32]byte
	Alpha           [32]byte
	Fvk             [96]byte
	Recipient       [43]byte
	Rho             [32]byte
	Rseed           [32]byte
	WitnessPosition uint32
	WitnessPath     [32][32]byte
	DummySk         [32]byte
}

// OrchardCreateDummySpend generates a complete dummy spend with all consistent fields.
//
// This ensures all cryptographic values are properly interrelated:
// - Nullifier is derived from the note (not random)
// - rk matches the fvk and alpha
// - All fields are valid for proof verification
func OrchardCreateDummySpend() (*DummySpendData, error) {
	var output [1359]byte

	code := C.ffi_orchard_create_dummy_spend(
		(*C.uint8_t)(unsafe.Pointer(&output[0])),
	)

	if code != C.FFI_OK {
		return nil, getLastError(code)
	}

	// Parse output fields
	data := &DummySpendData{}
	offset := 0

	copy(data.Nullifier[:], output[offset:offset+32])
	offset += 32

	copy(data.Rk[:], output[offset:offset+32])
	offset += 32

	copy(data.Alpha[:], output[offset:offset+32])
	offset += 32

	copy(data.Fvk[:], output[offset:offset+96])
	offset += 96

	copy(data.Recipient[:], output[offset:offset+43])
	offset += 43

	copy(data.Rho[:], output[offset:offset+32])
	offset += 32

	copy(data.Rseed[:], output[offset:offset+32])
	offset += 32

	// Position is 4 bytes little-endian
	data.WitnessPosition = uint32(output[offset]) |
		uint32(output[offset+1])<<8 |
		uint32(output[offset+2])<<16 |
		uint32(output[offset+3])<<24
	offset += 4

	// Witness path is 32 x 32 bytes
	for i := 0; i < 32; i++ {
		copy(data.WitnessPath[i][:], output[offset+i*32:offset+(i+1)*32])
	}
	offset += 1024

	copy(data.DummySk[:], output[offset:offset+32])

	return data, nil
}
