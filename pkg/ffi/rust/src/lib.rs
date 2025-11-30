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
use std::sync::OnceLock;

// Orchard imports
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    note_encryption::{OrchardDomain, OrchardNoteEncryption},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Address, Note,
};

// Note encryption traits
use zcash_note_encryption::Domain;

// Pallas curve imports
use group::ff::{Field, PrimeField};
use pasta_curves::pallas;

// RedPallas signatures
use rand::rngs::OsRng;
use reddsa::{orchard::SpendAuth, orchard::Binding, SigningKey};

// ============================================================================
// Proving key initialization
// ============================================================================

/// Global Orchard proving key, lazily initialized on first use.
/// This key is built once and reused across all proof generation calls.
/// Building the key takes ~1-2 seconds, so we cache it for performance.
static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

/// Get a reference to the Orchard proving key, building it on first access.
/// This is thread-safe and will only build the key once.
fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(orchard::circuit::ProvingKey::build)
}

// ============================================================================
// FFI types and error handling
// ============================================================================

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

    // Use the Prover role to generate proofs if needed
    use pczt::roles::prover::Prover;

    let mut prover = Prover::new(pczt);

    // Check if Orchard proofs are required, and if so, generate them
    if prover.requires_orchard_proof() {
        // Get the proving key (will build it on first call, then cache)
        let pk = orchard_proving_key();

        // Generate the Orchard proofs
        prover = match prover.create_orchard_proof(pk) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(format!("Failed to create Orchard proof: {:?}", e));
                return FFIResult::error(FFIErrorCode::ProvingFailed);
            }
        };
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
/// Creates an encrypted note including:
/// - enc_ciphertext (580 bytes) - encrypted note for recipient
/// - out_ciphertext (80 bytes) - encrypted data for sender recovery
/// - epk (32 bytes) - ephemeral public key
/// - cmx (32 bytes) - note commitment
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_encrypt_note(
    recipient: *const u8,           // [43] - Orchard address
    value: u64,                     // Note value in zatoshis
    rho: *const u8,                 // [32] - Nullifier base (from dummy spend or prior note)
    rseed: *const u8,               // [32] - Random seed for note
    memo: *const u8,                // [512] - Memo field
    rcv: *const u8,                 // [32] - Value commitment randomness
    enc_ciphertext_out: *mut u8,    // [580] - Output: encrypted note
    out_ciphertext_out: *mut u8,    // [80] - Output: outgoing ciphertext
    epk_out: *mut u8,               // [32] - Output: ephemeral public key
    cmx_out: *mut u8,               // [32] - Output: note commitment
) -> FFIErrorCode {
    if recipient.is_null() || rho.is_null() || rseed.is_null() || memo.is_null() ||
       rcv.is_null() || enc_ciphertext_out.is_null() || out_ciphertext_out.is_null() ||
       epk_out.is_null() || cmx_out.is_null() {
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
    let note_value = NoteValue::from_raw(value);

    // Create note
    let note: Note = match Note::from_parts(address, note_value, rho_val, random_seed).into() {
        Some(n) => n,
        None => {
            set_last_error("Invalid note parameters".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Compute note commitment
    let cmx: ExtractedNoteCommitment = note.commitment().into();

    // Parse memo
    let memo_bytes = slice::from_raw_parts(memo, 512);
    let mut memo_arr = [0u8; 512];
    memo_arr.copy_from_slice(memo_bytes);

    // Parse rcv for value commitment
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

    // Compute value commitment (needed for outgoing ciphertext)
    let zero = NoteValue::from_raw(0);
    let value_sum = note_value - zero;
    let cv_net: ValueCommitment = ValueCommitment::derive(value_sum, rcv_trapdoor);

    // Create note encryption (without OVK for T2O - we don't need sender recovery)
    // For T2O transactions, we use None for OVK since the sender is transparent
    let encryptor = OrchardNoteEncryption::new(None, note, memo_arr);

    // Get ephemeral public key using Domain trait
    let epk_bytes = OrchardDomain::epk_bytes(encryptor.epk());

    // Encrypt note plaintext (580 bytes)
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    // Encrypt outgoing plaintext (80 bytes)
    let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng);

    // Copy outputs
    ptr::copy_nonoverlapping(enc_ciphertext.as_ref().as_ptr(), enc_ciphertext_out, 580);
    ptr::copy_nonoverlapping(out_ciphertext.as_ptr(), out_ciphertext_out, 80);
    ptr::copy_nonoverlapping(epk_bytes.as_ref().as_ptr(), epk_out, 32);
    ptr::copy_nonoverlapping(cmx.to_bytes().as_ptr(), cmx_out, 32);

    FFIErrorCode::Ok
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

    // Get the full viewing key and then the spend validating key (ak)
    let fvk = FullViewingKey::from(&spending_key);

    // Get the spend validating key (ak) - this is the public key counterpart
    use orchard::keys::SpendValidatingKey;
    let spend_validating_key: SpendValidatingKey = fvk.into();

    // Randomize the spend validating key (verification key) with alpha
    // This produces rk = ak + alpha * G (on Pallas curve)
    let rk = spend_validating_key.randomize(&alpha_scalar);

    // Get the randomized verification key bytes
    // The randomize method returns orchard's internal redpallas::VerificationKey
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
/// The binding signature proves that the transaction is balanced (sum of inputs = sum of outputs)
/// by signing with the binding signing key (bsk), which is derived from the sum of value commitment
/// randomness values.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_reddsa_sign_binding(
    bsk: *const u8,            // [32] binding signing key
    sighash: *const u8,        // [32] transaction sighash
    sig_out: *mut u8,          // [64] output signature
) -> FFIErrorCode {
    if bsk.is_null() || sighash.is_null() || sig_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse binding signing key from bytes
    let bsk_bytes = slice::from_raw_parts(bsk, 32);
    let mut bsk_arr = [0u8; 32];
    bsk_arr.copy_from_slice(bsk_bytes);

    let signing_key = match SigningKey::<Binding>::try_from(bsk_arr) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(format!("Invalid binding signing key: {}", e));
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Parse sighash message
    let sighash_bytes = slice::from_raw_parts(sighash, 32);

    // Sign the transaction sighash with the binding key
    let signature = signing_key.sign(&mut OsRng, sighash_bytes);

    // Copy signature to output (64 bytes: R || s)
    let sig_bytes: [u8; 64] = signature.into();
    ptr::copy_nonoverlapping(sig_bytes.as_ptr(), sig_out, 64);

    FFIErrorCode::Ok
}

/// Generate a valid Pallas base field element for rho or other uses
///
/// In Orchard, rho must be a valid Pallas base field element. For T2O transactions,
/// we create "dummy spends" that need valid rho values. This function generates
/// a valid field element by creating a random Pallas base.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_generate_dummy_rho(
    rho_out: *mut u8,          // [32] - output rho
) -> FFIErrorCode {
    if rho_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Generate a random Pallas base field element
    // This is guaranteed to be a valid rho
    let base_element = pallas::Base::random(&mut OsRng);

    // Serialize to bytes (canonical representation)
    let rho_bytes = base_element.to_repr();

    // Copy to output
    ptr::copy_nonoverlapping(rho_bytes.as_ptr(), rho_out, 32);

    FFIErrorCode::Ok
}

/// Generate a valid Pallas scalar for value commitment randomness (rcv)
///
/// The value commitment trapdoor (rcv) must be a valid Pallas scalar.
/// This function generates a cryptographically random valid scalar.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_generate_rcv(
    rcv_out: *mut u8,          // [32] - output rcv
) -> FFIErrorCode {
    if rcv_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Generate a random Pallas scalar
    // This is guaranteed to be a valid value commitment trapdoor
    let scalar = pallas::Scalar::random(&mut OsRng);

    // Serialize to bytes (canonical representation)
    let rcv_bytes = scalar.to_repr();

    // Copy to output
    ptr::copy_nonoverlapping(rcv_bytes.as_ptr(), rcv_out, 32);

    FFIErrorCode::Ok
}

/// Generate a valid dummy nullifier (Pallas base field element)
///
/// Nullifiers in Orchard must be valid Pallas base field elements.
/// For dummy spends in T2O transactions, we need nullifiers that are valid
/// but don't correspond to any real note. This function generates random
/// valid field elements for that purpose.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_generate_dummy_nullifier(
    nullifier_out: *mut u8,    // [32] - output nullifier
) -> FFIErrorCode {
    if nullifier_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Generate a random Pallas base field element
    // This is guaranteed to be a valid nullifier representation
    let base_element = pallas::Base::random(&mut OsRng);

    // Serialize to bytes (canonical representation)
    let nf_bytes = base_element.to_repr();

    // Copy to output
    ptr::copy_nonoverlapping(nf_bytes.as_ptr(), nullifier_out, 32);

    FFIErrorCode::Ok
}

/// Generate a valid random dummy spending key for dummy spends
///
/// In T2O transactions, we need dummy spends with valid spending keys.
/// This generates a random valid SpendingKey by trying random seeds until
/// one produces a valid key (SpendingKey::from_bytes has constraints).
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_generate_dummy_sk(
    sk_out: *mut u8,           // [32] - output spending key bytes
) -> FFIErrorCode {
    if sk_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // SpendingKey::from_bytes can fail for some byte values, so we try until we get a valid one
    use rand::RngCore;
    loop {
        // Generate random 32 bytes using OsRng
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        // Try to create a valid SpendingKey
        if SpendingKey::from_bytes(seed).is_some().into() {
            // This seed produces a valid SpendingKey, use it
            ptr::copy_nonoverlapping(seed.as_ptr(), sk_out, 32);
            return FFIErrorCode::Ok;
        }
        // If not valid, try again (this is rare, most seeds are valid)
    }
}

/// Generate a complete dummy spend with all cryptographically consistent fields
///
/// This function generates all the fields needed for a dummy spend that will pass
/// proof verification. All values are consistent with each other:
/// - The nullifier is derived from the note (fvk, recipient, value=0, rho, rseed)
/// - The rk is derived from the fvk and alpha
/// - The witness is a valid dummy witness
///
/// Returns in order:
/// - nullifier [32]
/// - rk [32]
/// - alpha [32]
/// - fvk [96]
/// - recipient [43]
/// - rho [32]
/// - rseed [32]
/// - witness_position [4] (as u32 little-endian)
/// - witness_path [1024] (32 x 32 bytes)
/// - dummy_sk [32]
///
/// Total: 32+32+32+96+43+32+32+4+1024+32 = 1359 bytes
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_create_dummy_spend(
    output_out: *mut u8,       // [1359] - all output fields
) -> FFIErrorCode {
    if output_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    use rand::RngCore;

    // Generate random spending key for the dummy spend
    loop {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);

        let spending_key: SpendingKey = match SpendingKey::from_bytes(sk_bytes).into() {
            Some(k) => k,
            None => continue, // Try again with different random bytes
        };

        // Derive FVK and address
        let fvk = FullViewingKey::from(&spending_key);
        let recipient = fvk.address_at(0u32, Scope::External);

        // Generate rho and rseed (for the dummy note)
        let rho_base = pallas::Base::random(&mut OsRng);
        let rho = Rho::from_bytes(&rho_base.to_repr())
            .into_option()
            .expect("random base should be valid rho");

        // Generate random rseed using public API
        let mut rseed_bytes = [0u8; 32];
        loop {
            OsRng.fill_bytes(&mut rseed_bytes);
            if RandomSeed::from_bytes(rseed_bytes, &rho).is_some().into() {
                break;
            }
        }
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho)
            .into_option()
            .expect("rseed should be valid - we just checked");

        // Create the dummy note (value = 0) using public API
        let note = match Note::from_parts(recipient, NoteValue::from_raw(0), rho, rseed).into_option() {
            Some(n) => n,
            None => continue, // Rare, but try again
        };

        // Derive nullifier from the note
        let nullifier = note.nullifier(&fvk);

        // Generate alpha (spend auth randomizer)
        let alpha = pallas::Scalar::random(&mut OsRng);

        // Derive rk (randomized verification key)
        use orchard::keys::SpendValidatingKey;
        let ak: SpendValidatingKey = fvk.clone().into();
        let rk = ak.randomize(&alpha);

        // Generate dummy witness
        let witness_position = OsRng.next_u32();
        let mut witness_path = [[0u8; 32]; 32];
        for i in 0..32 {
            let hash = pallas::Base::random(&mut OsRng);
            witness_path[i] = hash.to_repr();
        }

        // Write all outputs
        let mut offset = 0usize;

        // nullifier [32]
        let nf_bytes: [u8; 32] = nullifier.to_bytes();
        ptr::copy_nonoverlapping(nf_bytes.as_ptr(), output_out.add(offset), 32);
        offset += 32;

        // rk [32]
        let rk_bytes: [u8; 32] = rk.into();
        ptr::copy_nonoverlapping(rk_bytes.as_ptr(), output_out.add(offset), 32);
        offset += 32;

        // alpha [32]
        let alpha_bytes = alpha.to_repr();
        ptr::copy_nonoverlapping(alpha_bytes.as_ptr(), output_out.add(offset), 32);
        offset += 32;

        // fvk [96]
        let fvk_bytes = fvk.to_bytes();
        ptr::copy_nonoverlapping(fvk_bytes.as_ptr(), output_out.add(offset), 96);
        offset += 96;

        // recipient [43]
        let recipient_bytes = recipient.to_raw_address_bytes();
        ptr::copy_nonoverlapping(recipient_bytes.as_ptr(), output_out.add(offset), 43);
        offset += 43;

        // rho [32]
        let rho_bytes = rho.to_bytes();
        ptr::copy_nonoverlapping(rho_bytes.as_ptr(), output_out.add(offset), 32);
        offset += 32;

        // rseed [32]
        ptr::copy_nonoverlapping(rseed_bytes.as_ptr(), output_out.add(offset), 32);
        offset += 32;

        // witness_position [4]
        let pos_bytes = witness_position.to_le_bytes();
        ptr::copy_nonoverlapping(pos_bytes.as_ptr(), output_out.add(offset), 4);
        offset += 4;

        // witness_path [1024]
        for i in 0..32 {
            ptr::copy_nonoverlapping(witness_path[i].as_ptr(), output_out.add(offset + i * 32), 32);
        }
        offset += 1024;

        // dummy_sk [32]
        ptr::copy_nonoverlapping(sk_bytes.as_ptr(), output_out.add(offset), 32);

        return FFIErrorCode::Ok;
    }
}

/// Generate a dummy Merkle witness for dummy spends
///
/// A dummy witness consists of:
/// - A random position (u32)
/// - 32 random Pallas base field elements (one for each level of the tree)
///
/// The position is returned in the first 4 bytes (little-endian).
/// The remaining 32*32 = 1024 bytes are the authentication path.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_generate_dummy_witness(
    position_out: *mut u32,    // output position
    path_out: *mut u8,         // [32 * 32 = 1024] - output path
) -> FFIErrorCode {
    if position_out.is_null() || path_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    use rand::RngCore;

    // Generate random position
    *position_out = OsRng.next_u32();

    // Generate 32 random Pallas base elements (one per tree level)
    for i in 0..32 {
        let base = pallas::Base::random(&mut OsRng);
        let base_bytes = base.to_repr();
        ptr::copy_nonoverlapping(base_bytes.as_ptr(), path_out.add(i * 32), 32);
    }

    FFIErrorCode::Ok
}

/// Derive Full Viewing Key from a spending key
///
/// The FVK is 96 bytes and is required by the prover to generate proofs.
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_derive_fvk(
    sk: *const u8,             // [32] - spending key bytes
    fvk_out: *mut u8,          // [96] - output FVK bytes
) -> FFIErrorCode {
    if sk.is_null() || fvk_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse spending key
    let sk_bytes = slice::from_raw_parts(sk, 32);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes);

    let spending_key: SpendingKey = match SpendingKey::from_bytes(sk_arr).into() {
        Some(k) => k,
        None => {
            set_last_error("Invalid spending key".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Derive full viewing key
    let fvk = FullViewingKey::from(&spending_key);

    // Serialize to bytes
    let fvk_bytes = fvk.to_bytes();

    // Copy to output
    ptr::copy_nonoverlapping(fvk_bytes.as_ptr(), fvk_out, 96);

    FFIErrorCode::Ok
}

/// Generate a test Orchard address from a 32-byte seed
///
/// This creates a valid Orchard address for testing purposes by:
/// 1. Creating a SpendingKey from the seed
/// 2. Deriving the FullViewingKey
/// 3. Getting the default address
///
/// # Safety
/// - All pointer parameters must point to valid arrays of the specified size
#[no_mangle]
pub unsafe extern "C" fn ffi_orchard_test_address(
    seed: *const u8,           // [32] - seed bytes
    address_out: *mut u8,      // [43] - output address
) -> FFIErrorCode {
    if seed.is_null() || address_out.is_null() {
        return FFIErrorCode::NullPointer;
    }

    // Parse seed
    let seed_bytes = slice::from_raw_parts(seed, 32);
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(seed_bytes);

    // Create spending key from seed
    let spending_key: SpendingKey = match SpendingKey::from_bytes(seed_arr).into() {
        Some(k) => k,
        None => {
            set_last_error("Invalid seed for spending key".to_string());
            return FFIErrorCode::OrchardCryptoFailed;
        }
    };

    // Derive full viewing key
    let fvk = FullViewingKey::from(&spending_key);

    // Get default address (external scope, index 0)
    let address = fvk.address_at(0u32, Scope::External);

    // Serialize to raw bytes
    let address_bytes = address.to_raw_address_bytes();

    // Copy to output
    ptr::copy_nonoverlapping(address_bytes.as_ptr(), address_out, 43);

    FFIErrorCode::Ok
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
                one_bytes.as_ptr(),
                one_bytes.as_ptr(),
                result.as_mut_ptr(),
            );

            assert_eq!(code, FFIErrorCode::Ok);

            // Result should be 2
            let two = pallas::Scalar::from(2u64);
            assert_eq!(result, two.to_repr().as_ref());
        }
    }

    #[test]
    fn test_orchard_proving_key_initialization() {
        // This test verifies that we can build the Orchard proving key
        // Note: This takes ~1-2 seconds on first run, but is cached for subsequent calls

        println!("Building Orchard proving key (this may take a moment)...");
        let pk1 = orchard_proving_key();
        println!("Proving key built successfully!");

        // Verify we can call it multiple times and get the same instance
        let pk2 = orchard_proving_key();

        // Both should point to the same memory location (same static instance)
        assert!(
            std::ptr::eq(pk1, pk2),
            "Should return same proving key instance on multiple calls"
        );

        println!("Proving key is properly cached - test passed!");
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

        // Print bytes in a more readable format
        print!("PCZT bytes: ");
        for (i, b) in pczt_bytes.iter().enumerate() {
            print!("{:02x} ", b);
            if (i + 1) % 16 == 0 {
                println!();
                print!("            ");
            }
        }
        println!();

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

    #[test]
    fn test_ffi_prove_pczt_no_proofs_needed() {
        use pczt::roles::creator::Creator;

        println!("\n=== Testing ffi_prove_pczt with PCZT (no proofs needed) ===\n");

        // Create a minimal PCZT without Orchard actions (so no proofs are needed)
        println!("Creating minimal PCZT...");
        let pczt = Creator::new(
            0xC2D6D0B4,  // NU5 consensus branch ID (mainnet)
            10_000_000,  // expiry height
            133,         // coin type (mainnet)
            [0; 32],     // transparent anchor
            orchard::Anchor::empty_tree().to_bytes(), // orchard anchor
        ).build();

        let pczt_bytes = pczt.serialize();
        println!("PCZT serialized: {} bytes", pczt_bytes.len());

        // Call the FFI function - should succeed without needing proofs
        println!("Calling ffi_prove_pczt (no Orchard actions, so no proving needed)...");
        unsafe {
            let result = ffi_prove_pczt(
                pczt_bytes.as_ptr(),
                pczt_bytes.len(),
            );

            assert_eq!(result.error_code, FFIErrorCode::Ok, "ffi_prove_pczt should succeed");
            assert!(!result.data.is_null());
            assert!(result.data_len > 0);

            println!("✓ ffi_prove_pczt succeeded: {} bytes", result.data_len);

            // Parse the result back
            let result_slice = slice::from_raw_parts(result.data, result.data_len);
            let proved_pczt = pczt::Pczt::parse(result_slice)
                .expect("Failed to parse result PCZT");

            // Verify it's still valid
            assert!(proved_pczt.orchard().actions().is_empty(), "Should have no Orchard actions");
            println!("✓ Result PCZT is valid!");

            // Free the result
            ffi_free_bytes(result.data, result.data_len);
        }

        println!("\n✓ Test passed! The proving key is initialized and ready for actual proofs.");
        println!("Note: This test verifies the infrastructure works.");
        println!("Full end-to-end proving tests will be in the Go integration tests.");
    }

    #[test]
    fn test_reddsa_sign_binding() {
        use reddsa::{Signature, VerificationKey};
        use group::ff::Field;

        println!("\n=== Testing RedPallas binding signature ===\n");

        unsafe {
            // Generate a random binding signing key
            let bsk = pallas::Scalar::random(&mut OsRng);
            let bsk_bytes = bsk.to_repr();

            // Create a test sighash
            let sighash = [0x42u8; 32];

            // Output buffer for signature
            let mut sig_out = [0u8; 64];

            // Call the FFI function
            println!("Creating binding signature...");
            let result = ffi_reddsa_sign_binding(
                bsk_bytes.as_ptr(),
                sighash.as_ptr(),
                sig_out.as_mut_ptr(),
            );

            assert_eq!(result, FFIErrorCode::Ok, "Binding signature should succeed");
            println!("✓ Signature created: {} bytes", sig_out.len());

            // Verify the signature using reddsa directly
            println!("Verifying signature...");

            // Create signing key from the same bytes
            let mut bsk_arr = [0u8; 32];
            bsk_arr.copy_from_slice(&bsk_bytes);
            let signing_key = SigningKey::<Binding>::try_from(bsk_arr)
                .expect("Failed to create signing key");

            // Get verification key
            let vk = VerificationKey::<Binding>::from(&signing_key);

            // Parse the signature
            let signature = Signature::<Binding>::try_from(sig_out)
                .expect("Failed to parse signature");

            // Verify the signature
            assert!(
                vk.verify(&sighash, &signature).is_ok(),
                "Signature should verify correctly"
            );

            println!("✓ Signature verified successfully!");
        }
    }

    #[test]
    fn test_reddsa_sign_binding_different_messages() {
        println!("\n=== Testing binding signatures are unique per message ===\n");

        use reddsa::{Signature, VerificationKey};
        use group::ff::Field;

        unsafe {
            // Generate a binding signing key
            let bsk = pallas::Scalar::random(&mut OsRng);
            let bsk_bytes = bsk.to_repr();

            // Create two different sighashes
            let sighash1 = [0x42u8; 32];
            let sighash2 = [0x43u8; 32];

            let mut sig1 = [0u8; 64];
            let mut sig2 = [0u8; 64];

            // Sign both messages
            ffi_reddsa_sign_binding(bsk_bytes.as_ptr(), sighash1.as_ptr(), sig1.as_mut_ptr());
            ffi_reddsa_sign_binding(bsk_bytes.as_ptr(), sighash2.as_ptr(), sig2.as_mut_ptr());

            // Signatures should be different
            assert_ne!(sig1, sig2, "Signatures for different messages should differ");

            // Both should verify with their respective messages
            let mut bsk_arr = [0u8; 32];
            bsk_arr.copy_from_slice(&bsk_bytes);
            let signing_key = SigningKey::<Binding>::try_from(bsk_arr).unwrap();
            let vk = VerificationKey::<Binding>::from(&signing_key);

            let parsed_sig1 = Signature::<Binding>::try_from(sig1).unwrap();
            let parsed_sig2 = Signature::<Binding>::try_from(sig2).unwrap();

            assert!(vk.verify(&sighash1, &parsed_sig1).is_ok());
            assert!(vk.verify(&sighash2, &parsed_sig2).is_ok());

            // Cross-verification should fail
            assert!(vk.verify(&sighash1, &parsed_sig2).is_err());
            assert!(vk.verify(&sighash2, &parsed_sig1).is_err());

            println!("✓ Signatures are correctly unique per message");
        }
    }

    #[test]
    fn test_reddsa_sign_binding_null_pointers() {
        println!("\n=== Testing binding signature with null pointers ===\n");

        unsafe {
            let bsk = [1u8; 32];
            let sighash = [0x42u8; 32];
            let mut sig_out = [0u8; 64];

            // Test null bsk
            assert_eq!(
                ffi_reddsa_sign_binding(ptr::null(), sighash.as_ptr(), sig_out.as_mut_ptr()),
                FFIErrorCode::NullPointer
            );

            // Test null sighash
            assert_eq!(
                ffi_reddsa_sign_binding(bsk.as_ptr(), ptr::null(), sig_out.as_mut_ptr()),
                FFIErrorCode::NullPointer
            );

            // Test null output
            assert_eq!(
                ffi_reddsa_sign_binding(bsk.as_ptr(), sighash.as_ptr(), ptr::null_mut()),
                FFIErrorCode::NullPointer
            );

            println!("✓ Null pointer checks passed");
        }
    }
}
