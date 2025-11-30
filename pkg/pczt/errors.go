// Package pczt error types.
//
// These error types correspond to the errors returned by the public API
// functions defined in the PCZT specification. They provide structured
// error information for different failure modes during PCZT operations.
//
// Rust equivalent errors can be found in:
//   - librustzcash/pczt/src/roles/ (various role implementations)
package pczt

import "fmt"

// API error types matching the PCZT specification.

// ProposalError is returned when propose_transaction fails.
//
// This can occur during Creator, Constructor, or IO Finalizer role execution.
// Common causes: invalid inputs, insufficient funds, invalid addresses.
type ProposalError struct {
	Code    string // Error code (e.g., ErrInvalidInput, ErrInsufficientFunds)
	Message string // Human-readable error message
	Cause   error  // Underlying error (if any)
}

func (e *ProposalError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("proposal error [%s]: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("proposal error [%s]: %s", e.Code, e.Message)
}

// ProverError is returned when prove_transaction fails.
//
// The Prover role generates zero-knowledge proofs for Orchard actions.
// This operation is computationally expensive and requires the Rust FFI.
type ProverError struct {
	Code    string // Error code (e.g., ErrProofCreationFailed)
	Message string // Human-readable error message
	Cause   error  // Underlying error from Rust prover
}

func (e *ProverError) Error() string {
	return fmt.Sprintf("prover error [%s]: %s", e.Code, e.Message)
}

// VerificationFailure is returned when verify_before_signing detects issues.
//
// This error indicates the PCZT doesn't match expectations (e.g., outputs
// don't match the transaction request, fees are incorrect, etc.).
type VerificationFailure struct {
	Code    string                 // Error code (e.g., ErrInvalidPCZT)
	Message string                 // Human-readable error message
	Details map[string]interface{} // Additional context about the failure
}

func (e *VerificationFailure) Error() string {
	return fmt.Sprintf("verification failed [%s]: %s", e.Code, e.Message)
}

// SighashError is returned when get_sighash fails.
//
// This occurs when computing the ZIP 244 signature hash for a transparent input.
type SighashError struct {
	InputIndex uint32 // Index of the input that caused the error
	Message    string // Human-readable error message
	Cause      error  // Underlying error (if any)
}

func (e *SighashError) Error() string {
	return fmt.Sprintf("sighash error at input %d: %s", e.InputIndex, e.Message)
}

// SignatureError is returned when append_signature fails.
//
// This occurs when a signature is invalid or doesn't match the input.
type SignatureError struct {
	InputIndex uint32 // Index of the input that caused the error
	Message    string // Human-readable error message
	Cause      error  // Underlying error (if any)
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("signature error at input %d: %s", e.InputIndex, e.Message)
}

// CombineError is returned when combine fails to merge PCZTs.
//
// The Combiner role merges parallel PCZTs (e.g., from different signers).
// Fails if PCZTs are incompatible or have conflicting data.
type CombineError struct {
	Message string // Human-readable error message
	Cause   error  // Underlying error (if any)
}

func (e *CombineError) Error() string {
	return fmt.Sprintf("combine error: %s", e.Message)
}

// FinalizationError is returned when finalize_and_extract fails.
//
// This occurs during Spend Finalizer or Transaction Extractor execution.
// Common causes: incomplete signatures, invalid proofs, malformed PCZT.
type FinalizationError struct {
	Code    string // Error code (e.g., ErrIncompletePCZT)
	Message string // Human-readable error message
	Cause   error  // Underlying error (if any)
}

func (e *FinalizationError) Error() string {
	return fmt.Sprintf("finalization error [%s]: %s", e.Code, e.Message)
}

// ParseError is returned when parse_pczt fails to decode PCZT bytes.
//
// This occurs when the input data is not a valid PCZT (wrong magic bytes,
// unsupported version, or malformed Postcard encoding).
type ParseError struct {
	Message string // Human-readable error message
	Cause   error  // Underlying decode error
}

func (e *ParseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("parse error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("parse error: %s", e.Message)
}

// Error codes used throughout the PCZT API.
//
// These codes provide structured error identification for programmatic handling.
const (
	ErrInvalidInput        = "INVALID_INPUT"         // Input data is invalid or malformed
	ErrInsufficientFunds   = "INSUFFICIENT_FUNDS"    // Not enough funds to cover outputs + fees
	ErrInvalidAddress      = "INVALID_ADDRESS"       // Address format is invalid or unsupported
	ErrInvalidSighash      = "INVALID_SIGHASH"       // Signature hash computation failed
	ErrInvalidSignature    = "INVALID_SIGNATURE"     // Signature is invalid or doesn't verify
	ErrProofCreationFailed = "PROOF_CREATION_FAILED" // ZK proof generation failed
	ErrIncompletePCZT      = "INCOMPLETE_PCZT"       // PCZT is missing required data (e.g., signatures)
	ErrInvalidPCZT         = "INVALID_PCZT"          // PCZT structure is invalid or inconsistent
	ErrConflictingData     = "CONFLICTING_DATA"      // Conflicting data when combining PCZTs
)
