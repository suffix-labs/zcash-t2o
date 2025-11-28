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
#cgo linux LDFLAGS: -ldl -lm

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
    const uint8_t rseed[32],
    const uint8_t memo[512],
    const uint8_t esk[32],
    const uint8_t epk[32],
    uint8_t enc_ciphertext_out[580],
    uint8_t out_ciphertext_out[80]
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
// Parameters:
//   - recipient: 43-byte Orchard address
//   - value: Note value in zatoshis
//   - rseed: 32-byte random seed
//   - memo: 512-byte memo field
//   - esk: 32-byte ephemeral secret key
//   - epk: 32-byte ephemeral public key
//
// Returns:
//   - 580-byte encrypted ciphertext
//   - 80-byte outgoing ciphertext
//   - Error if encryption fails
func OrchardEncryptNote(
	recipient [43]byte,
	value uint64,
	rseed [32]byte,
	memo [512]byte,
	esk [32]byte,
	epk [32]byte,
) ([]byte, []byte, error) {
	encCiphertext := make([]byte, 580)
	outCiphertext := make([]byte, 80)

	code := C.ffi_orchard_encrypt_note(
		(*C.uint8_t)(unsafe.Pointer(&recipient[0])),
		C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&rseed[0])),
		(*C.uint8_t)(unsafe.Pointer(&memo[0])),
		(*C.uint8_t)(unsafe.Pointer(&esk[0])),
		(*C.uint8_t)(unsafe.Pointer(&epk[0])),
		(*C.uint8_t)(unsafe.Pointer(&encCiphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&outCiphertext[0])),
	)

	if code != C.FFI_OK {
		return nil, nil, getLastError(code)
	}

	return encCiphertext, outCiphertext, nil
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
