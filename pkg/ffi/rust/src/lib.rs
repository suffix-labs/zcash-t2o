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

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;

// Re-exports from librustzcash for easy access
// Note: These paths are placeholders - actual librustzcash structure may vary
// TODO: Update these imports based on actual librustzcash crate structure

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

/// Thread-local storage for last error message
thread_local! {
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

    // TODO: Actual implementation
    // This is a placeholder that shows the structure
    //
    // Real implementation should:
    // 1. Deserialize PCZT using postcard
    // 2. Use zcash_proofs to generate Orchard proofs
    // 3. Attach proofs to the PCZT
    // 4. Serialize back to bytes
    //
    // Example pseudocode:
    //   let pczt: Pczt = postcard::from_bytes(pczt_data)?;
    //   let prover = LocalProver::new(...);
    //   let proof = prover.create_orchard_proof(&pczt)?;
    //   pczt.orchard.zk_proof = Some(proof);
    //   let output = postcard::to_allocvec(&pczt)?;
    //   FFIResult::ok(output)

    set_last_error("ffi_prove_pczt not yet implemented - requires librustzcash integration".to_string());
    FFIResult::error(FFIErrorCode::ProvingFailed)
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

    // TODO: Implement using orchard crate
    // Example:
    //   use orchard::note::Note;
    //   let note = Note::new(...);
    //   let cmx = note.commitment().to_bytes();
    //   ptr::copy_nonoverlapping(cmx.as_ptr(), cmx_out, 32);

    set_last_error("ffi_orchard_note_commitment not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
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

    // TODO: Implement using orchard crate
    // Example:
    //   use orchard::keys::EphemeralSecretKey;
    //   let epk = EphemeralSecretKey::from_bytes(esk).derive_public();
    //   ptr::copy_nonoverlapping(epk.to_bytes().as_ptr(), epk_out, 32);

    set_last_error("ffi_orchard_ephemeral_key not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
}

/// Encrypt Orchard note
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_encrypt_note(
    recipient: *const u8,           // [43]
    value: u64,
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

    // TODO: Implement using orchard note_encryption
    // Example:
    //   use orchard::note_encryption;
    //   let (enc_ct, out_ct) = note_encryption::encrypt(...);
    //   ptr::copy_nonoverlapping(enc_ct.as_ptr(), enc_ciphertext_out, 580);
    //   ptr::copy_nonoverlapping(out_ct.as_ptr(), out_ciphertext_out, 80);

    set_last_error("ffi_orchard_encrypt_note not yet implemented".to_string());
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

    // TODO: Implement using orchard value commitment
    // Example:
    //   use orchard::value::ValueCommitment;
    //   let cv = ValueCommitment::new(value, rcv);
    //   ptr::copy_nonoverlapping(cv.to_bytes().as_ptr(), cv_out, 32);

    set_last_error("ffi_orchard_value_commitment not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
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

    // TODO: Implement using orchard nullifier derivation
    // Example:
    //   use orchard::note::Nullifier;
    //   let nf = Nullifier::derive(rho, sk);
    //   ptr::copy_nonoverlapping(nf.to_bytes().as_ptr(), nf_out, 32);

    set_last_error("ffi_orchard_derive_nullifier not yet implemented".to_string());
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

    // TODO: Implement using orchard key randomization
    // Example:
    //   use orchard::keys::SpendAuthorizingKey;
    //   let rk = SpendAuthorizingKey::from_bytes(sk).randomize(alpha);
    //   ptr::copy_nonoverlapping(rk.to_bytes().as_ptr(), rk_out, 32);

    set_last_error("ffi_orchard_randomized_key not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
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

    // TODO: Implement using pallas scalar arithmetic
    // Example:
    //   use pasta_curves::pallas::Scalar;
    //   let scalar_a = Scalar::from_bytes(a);
    //   let scalar_b = Scalar::from_bytes(b);
    //   let result = scalar_a + scalar_b;
    //   ptr::copy_nonoverlapping(result.to_bytes().as_ptr(), result_out, 32);

    set_last_error("ffi_pallas_scalar_add not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
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

    // TODO: Implement using reddsa RedPallas signing
    // Example:
    //   use reddsa::orchard::SpendAuth;
    //   let sig = SpendAuth::sign(sk, alpha, sighash);
    //   ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), sig_out, 64);

    set_last_error("ffi_reddsa_sign_spend_auth not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
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

    // TODO: Implement using reddsa RedPallas signing
    // Example:
    //   use reddsa::orchard::Binding;
    //   let sig = Binding::sign(bsk, sighash);
    //   ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), sig_out, 64);

    set_last_error("ffi_reddsa_sign_binding not yet implemented".to_string());
    FFIErrorCode::OrchardCryptoFailed
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
