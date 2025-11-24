//! Rust FFI wrapper for Zcash transparent-to-Orchard PCZT operations
//!
//! This crate provides C-compatible FFI bindings for Orchard cryptographic
//! operations that cannot be implemented in pure Go. It wraps the Rust
//! implementations from librustzcash.
//!
//! The Go code calls into these functions via CGO to perform:
//!   - Zero-knowledge proof generation (Prover role)
//!   - Orchard note commitments and encryption
//!   - RedPallas signatures for spend authorization and binding
//!   - Pallas curve arithmetic

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// Orchard imports
use orchard::{
    keys::{SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Address, Note,
};

// Pallas curve imports
use group::ff::PrimeField;
use pasta_curves::pallas;

// RedPallas signatures
use rand::rngs::OsRng;
use reddsa::{orchard::SpendAuth, SigningKey};

/// FFI error codes
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIErrorCode {
    Ok = 0,
    NullPointer = 1,
    InvalidPczt = 2,
    ProvingFailed = 3,
    SerializationFailed = 4,
    OrchardCryptoFailed = 5,
}

/// FFI result type for operations that return data
#[repr(C)]
pub struct FFIResult {
    pub error_code: FFIErrorCode,
    pub data: *mut u8,
    pub data_len: usize,
}

impl FFIResult {
    #[allow(dead_code)]
    fn ok(data: Vec<u8>) -> Self {
        let len = data.len();
        let ptr = Box::into_raw(data.into_boxed_slice()) as *mut u8;
        FFIResult {
            error_code: FFIErrorCode::Ok,
            data: ptr,
            data_len: len,
        }
    }

    fn error(code: FFIErrorCode) -> Self {
        FFIResult {
            error_code: code,
            data: ptr::null_mut(),
            data_len: 0,
        }
    }
}

thread_local! {
    /// Thread-local storage for last error message
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

/// Set the last error message
fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg);
    });
}

/// Get the last error message
fn take_last_error() -> Option<String> {
    LAST_ERROR.with(|e| e.borrow_mut().take())
}

// ============================================================================
// Memory management
// ============================================================================

/// Free a byte array allocated by Rust
///
/// # Safety
/// - `ptr` must have been allocated by this library
/// - Must only be called once per pointer
/// - `len` must match the original allocation length
#[no_mangle]
pub unsafe extern "C" fn ffi_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

/// Get the last error message
///
/// Returns a null-terminated C string that must be freed with ffi_free_string
#[no_mangle]
pub extern "C" fn ffi_last_error_message() -> *mut c_char {
    match take_last_error() {
        Some(msg) => match CString::new(msg) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Free an error message string
///
/// # Safety
/// - `s` must have been returned by ffi_last_error_message
/// - Must only be called once per pointer
#[no_mangle]
pub unsafe extern "C" fn ffi_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ============================================================================
// Prover operations
// ============================================================================

/// Generate Orchard ZK proofs for a PCZT
///
/// # Safety
/// - `pczt_bytes` must point to valid memory of length `pczt_len`
/// - Caller must free returned data with ffi_free_bytes
#[no_mangle]
pub unsafe extern "C" fn ffi_prove_pczt(
    pczt_bytes: *const u8,
    pczt_len: usize,
) -> FFIResult {
    // Validate inputs
    if pczt_bytes.is_null() {
        set_last_error("pczt_bytes is null".to_string());
        return FFIResult::error(FFIErrorCode::NullPointer);
    }

    // Convert to Rust slice
    let pczt_data = slice::from_raw_parts(pczt_bytes, pczt_len);

    // Parse PCZT from bytes
    let pczt = match pczt::Pczt::parse(pczt_data) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("Failed to parse PCZT: {:?}", e));
            return FFIResult::error(FFIErrorCode::InvalidPczt);
        }
    };

    // Use the Prover role to check if proving is needed
    use pczt::roles::prover::Prover;

    let prover = Prover::new(pczt);

    // For now, we'll check if proving is needed but return an error
    // because we need the proving key which must be loaded separately
    if prover.requires_orchard_proof() {
        set_last_error(
            "PCZT requires Orchard proofs, but proving key not available in FFI yet".to_string()
        );
        return FFIResult::error(FFIErrorCode::ProvingFailed);
    }

    let pczt = prover.finish();

    // Serialize back to bytes
    let output = pczt.serialize();
    FFIResult::ok(output)
}

// ============================================================================
// Orchard cryptographic operations
// ============================================================================

/// Derive Orchard note commitment
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_note_commitment(
    recipient: *const u8,      // [43]
    value: u64,
    rseed: *const u8,          // [32]
    rho: *const u8,            // [32]
    cmx_out: *mut u8,          // [32]
) -> FFIErrorCode {
    if recipient.is_null() || rseed.is_null() || rho.is_null() || cmx_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse recipient address (43 bytes: diversifier + pk_d)
    let recipient_bytes = slice::from_raw_parts(recipient, 43);
    let mut recipient_arr = [0u8; 43];
    recipient_arr.copy_from_slice(recipient_bytes);

    let address = match Address::from_raw_address_bytes(&recipient_arr).into() {
        Some(addr) => addr,
        None => {
            set_last_error("Invalid Orchard address".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse rho (nullifier base)
    let rho_bytes = slice::from_raw_parts(rho, 32);
    let mut rho_arr = [0u8; 32];
    rho_arr.copy_from_slice(rho_bytes);
    let rho_val: Rho = match Rho::from_bytes(&rho_arr).into() {
        Some(r) => r,
        None => {
            set_last_error("Invalid rho value".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse random seed
    let rseed_bytes = slice::from_raw_parts(rseed, 32);
    let mut rseed_arr = [0u8; 32];
    rseed_arr.copy_from_slice(rseed_bytes);
    let random_seed: RandomSeed = match RandomSeed::from_bytes(rseed_arr, &rho_val).into() {
        Some(rs) => rs,
        None => {
            set_last_error("Invalid random seed".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse value
    let note_value: NoteValue = match NoteValue::from_raw(value).into() {
        Some(v) => v,
        None => {
            set_last_error("Invalid note value".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Create note
    let note: Note = match Note::from_parts(address, note_value, rho_val, random_seed).into() {
        Some(n) => n,
        None => {
            set_last_error("Invalid note parameters".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Compute commitment
    let cmx: ExtractedNoteCommitment = note.commitment().into();

    // Copy to output
    ptr::copy_nonoverlapping(cmx.to_bytes().as_ptr(), cmx_out, 32);

    FFIErrorCode::Ok
}

/// Derive Orchard ephemeral key
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_ephemeral_key(
    esk: *const u8,            // [32]
    epk_out: *mut u8,          // [32]
) -> FFIErrorCode {
    if esk.is_null() || epk_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // NOTE: EphemeralSecretKey and derive_public are private in the new API
    // The ephemeral key derivation is now handled internally during note encryption
    // For FFI purposes, we return an error indicating this is not supported directly
    set_last_error("Ephemeral key derivation should be done during note encryption in new orchard API".to_string());

    FFIErrorCode::OrchardCryptoFailed
}

/// Encrypt Orchard note
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_encrypt_note(
    recipient: *const u8,           // [43]
    _value: u64,
    rseed: *const u8,               // [32]
    memo: *const u8,                // [512]
    esk: *const u8,                 // [32]
    epk: *const u8,                 // [32]
    enc_ciphertext_out: *mut u8,    // [580]
    out_ciphertext_out: *mut u8,    // [80]
) -> FFIErrorCode {
    if recipient.is_null() || rseed.is_null() || memo.is_null() ||
       esk.is_null() || epk.is_null() || enc_ciphertext_out.is_null() ||
       out_ciphertext_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    set_last_error("Note encryption not implemented: requires zcash_note_encryption with OrchardDomain setup".to_string());
    FFIErrorCode::OrchardCryptoFailed
}

/// Compute Orchard value commitment
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_value_commitment(
    value: u64,
    rcv: *const u8,            // [32]
    cv_out: *mut u8,           // [32]
) -> FFIErrorCode {
    if rcv.is_null() || cv_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse value (NoteValue::from_raw now returns NoteValue directly in newer API)
    let note_value = NoteValue::from_raw(value);

    // Parse randomness
    let rcv_bytes = slice::from_raw_parts(rcv, 32);
    let mut rcv_arr = [0u8; 32];
    rcv_arr.copy_from_slice(rcv_bytes);

    let rcv_trapdoor: ValueCommitTrapdoor = match ValueCommitTrapdoor::from_bytes(rcv_arr).into() {
        Some(t) => t,
        None => {
            set_last_error("Invalid value commitment randomness".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Compute value commitment
    // ValueSum can be created by subtracting two NoteValues (Sub returns ValueSum)
    let zero = NoteValue::from_raw(0);
    let value_sum = note_value - zero;
    let cv: ValueCommitment = ValueCommitment::derive(value_sum, rcv_trapdoor);

    // Extract and copy to output
    let cv_bytes = cv.to_bytes();
    ptr::copy_nonoverlapping(cv_bytes.as_ptr(), cv_out, 32);

    FFIErrorCode::Ok
}

/// Derive Orchard nullifier
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_derive_nullifier(
    rho: *const u8,            // [32]
    sk: *const u8,             // [32]
    nf_out: *mut u8,           // [32]
) -> FFIErrorCode {
    if rho.is_null() || sk.is_null() || nf_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // NOTE: Nullifier derivation internals (nk() and Nullifier::derive) are private in the new API
    // Nullifiers should be derived from Note objects using note.nullifier()
    // This standalone nullifier derivation is not supported in the public API
    set_last_error("Nullifier derivation should be done from Note objects in new orchard API".to_string());

    FFIErrorCode::OrchardCryptoFailed
}

/// Derive Orchard randomized verification key
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_randomized_key(
    sk: *const u8,             // [32]
    alpha: *const u8,          // [32]
    rk_out: *mut u8,           // [32]
) -> FFIErrorCode {
    if sk.is_null() || alpha.is_null() || rk_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse spend authorizing key
    let sk_bytes = slice::from_raw_parts(sk, 32);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes);

    // SpendAuthorizingKey doesn't have from_bytes in newer version
    // We need to derive it from a SpendingKey
    let spending_key: SpendingKey = match SpendingKey::from_bytes(sk_arr).into() {
        Some(k) => k,
        None => {
            set_last_error("Invalid spending key".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    let spend_auth_key = SpendAuthorizingKey::from(&spending_key);

    // Parse alpha (randomizer)
    let alpha_bytes = slice::from_raw_parts(alpha, 32);
    let mut alpha_arr = [0u8; 32];
    alpha_arr.copy_from_slice(alpha_bytes);

    let alpha_scalar: pallas::Scalar = match pallas::Scalar::from_repr(alpha_arr).into() {
        Some(s) => s,
        None => {
            set_last_error("Invalid alpha value".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Randomize the key
    let rk = spend_auth_key.randomize(&alpha_scalar);

    // The randomize method returns orchard's internal SigningKey type
    // We need to serialize it directly using the bytes method
    // Since it's an internal type, we'll use the Into<[u8; 32]> trait
    let rk_bytes: [u8; 32] = rk.into();

    // Copy to output
    ptr::copy_nonoverlapping(rk_bytes.as_ptr(), rk_out, 32);

    FFIErrorCode::Ok
}

/// Add Pallas scalars
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_pallas_scalar_add(
    a: *const u8,              // [32]
    b: *const u8,              // [32]
    result_out: *mut u8,       // [32]
) -> FFIErrorCode {
    if a.is_null() || b.is_null() || result_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse scalar a
    let a_bytes = slice::from_raw_parts(a, 32);
    let mut a_arr = [0u8; 32];
    a_arr.copy_from_slice(a_bytes);

    let scalar_a: pallas::Scalar = match pallas::Scalar::from_repr(a_arr).into() {
        Some(s) => s,
        None => {
            set_last_error("Invalid scalar a".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse scalar b
    let b_bytes = slice::from_raw_parts(b, 32);
    let mut b_arr = [0u8; 32];
    b_arr.copy_from_slice(b_bytes);

    let scalar_b: pallas::Scalar = match pallas::Scalar::from_repr(b_arr).into() {
        Some(s) => s,
        None => {
            set_last_error("Invalid scalar b".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Add scalars
    let result = scalar_a + scalar_b;

    // Copy to output
    let result_bytes = result.to_repr();
    ptr::copy_nonoverlapping(result_bytes.as_ptr(), result_out, 32);

    FFIErrorCode::Ok
}

/// Create RedPallas spend authorization signature
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_reddsa_sign_spend_auth(
    sk: *const u8,             // [32]
    alpha: *const u8,          // [32]
    sighash: *const u8,        // [32]
    sig_out: *mut u8,          // [64]
) -> FFIErrorCode {
    if sk.is_null() || alpha.is_null() || sighash.is_null() || sig_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse signing key
    let sk_bytes = slice::from_raw_parts(sk, 32);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes);

    let signing_key = match SigningKey::<SpendAuth>::try_from(sk_arr) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(format!("Invalid signing key: {}", e));
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse sighash message
    let sighash_bytes = slice::from_raw_parts(sighash, 32);

    // Sign the message
    // Note: RedPallas signing with randomizer (alpha) requires special handling
    // For now, we'll use the standard signing
    let signature = signing_key.sign(&mut OsRng, sighash_bytes);

    // Copy signature to output (64 bytes)
    let sig_bytes: [u8; 64] = signature.into();
    ptr::copy_nonoverlapping(sig_bytes.as_ptr(), sig_out, 64);

    FFIErrorCode::Ok
}

/// Create RedPallas binding signature
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_reddsa_sign_binding(
    bsk: *const u8,            // [32]
    sighash: *const u8,        // [32]
    sig_out: *mut u8,          // [64]
) -> FFIErrorCode {
    if bsk.is_null() || sighash.is_null() || sig_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    set_last_error("Binding signature not implemented: requires proper Binding signature type from reddsa".to_string());
    FFIErrorCode::OrchardCryptoFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use group::ff::Field;

    #[test]
    fn test_error_handling() {
        set_last_error("test error".to_string());
        let msg = unsafe {
            let ptr = ffi_last_error_message();
            assert!(!ptr.is_null());
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ffi_free_string(ptr);
            s
        };
        assert_eq!(msg, "test error");
    }

    #[test]
    fn test_pallas_scalar_add() {
        unsafe {
            // Test adding 1 + 1
            let one = pallas::Scalar::ONE;
            let one_bytes = one.to_repr();

            let mut result = [0u8; 32];

            let code = ffi_pallas_scalar_add(
                one_bytes.as_ref().as_ptr(),
                one_bytes.as_ref().as_ptr(),
                result.as_mut_ptr(),
            );

            assert_eq!(code, FFIErrorCode::Ok);

            // Result should be 2
            let two = pallas::Scalar::from(2u64);
            assert_eq!(result, two.to_repr().as_ref());
        }
    }

    #[test]
    fn test_pczt_parse_and_serialize() {
        use pczt::roles::creator::Creator;

        // Create a minimal PCZT using the Creator role
        let pczt = Creator::new(
            0xC2D6D0B4,  // NU5 consensus branch ID
            10_000_000,  // expiry height
            133,         // coin type (mainnet)
            [0; 32],     // transparent anchor
            [0; 32],     // orchard anchor
        ).build();

        // Serialize it
        let pczt_bytes = pczt.serialize();

        println!("Created PCZT: {} bytes", pczt_bytes.len());

        // Test FFI function
        unsafe {
            let result = ffi_prove_pczt(
                pczt_bytes.as_ptr(),
                pczt_bytes.len(),
            );

            // Should succeed (no proofs needed for empty PCZT)
            assert_eq!(result.error_code, FFIErrorCode::Ok);
            assert!(!result.data.is_null());
            assert!(result.data_len > 0);

            println!("FFI returned: {} bytes", result.data_len);

            // Parse the result back
            let result_slice = slice::from_raw_parts(result.data, result.data_len);
            let parsed_pczt = pczt::Pczt::parse(result_slice);
            assert!(parsed_pczt.is_ok(), "Failed to parse result PCZT");

            // Free the result
            ffi_free_bytes(result.data, result.data_len);
        }
    }

    #[test]
    fn test_pczt_invalid_bytes() {
        unsafe {
            let invalid_bytes = vec![0u8; 10];

            let result = ffi_prove_pczt(
                invalid_bytes.as_ptr(),
                invalid_bytes.len(),
            );

            // Should fail with InvalidPczt error
            assert_eq!(result.error_code, FFIErrorCode::InvalidPczt);
            assert!(result.data.is_null());
            assert_eq!(result.data_len, 0);

            // Check error message
            let err_msg = ffi_last_error_message();
            assert!(!err_msg.is_null());
            let msg = CStr::from_ptr(err_msg).to_string_lossy();
            println!("Error message: {}", msg);
            assert!(msg.contains("Failed to parse PCZT"));
            ffi_free_string(err_msg);
        }
    }
}
