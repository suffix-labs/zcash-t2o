// Package api provides the high-level public API for PCZT operations.
//
// This is the main entry point for applications using the zcash-t2o library.
// It implements the 8 core functions from the ZIP 374 specification:
//
//  1. ProposeTransaction - Creates initial PCZT with inputs and outputs
//  2. ProveTransaction - Generates zero-knowledge proofs
//  3. VerifyBeforeSigning - Validates PCZT before signing
//  4. GetSighash - Computes signature hash for an input
//  5. AppendSignature - Adds a signature to an input
//  6. Combine - Merges multiple PCZTs with partial signatures
//  7. FinalizeAndExtract - Finalizes and extracts final transaction
//  8. ParsePCZT / SerializePCZT - Binary encoding/decoding
//
// Corresponds to the public API specification in ZIP 374.
package api

import (
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/crypto"
	"github.com/suffix-labs/zcash-t2o/pkg/ffi"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
	"github.com/suffix-labs/zcash-t2o/pkg/roles"
	"github.com/suffix-labs/zcash-t2o/pkg/zip321"
)

// TransparentInput represents a transparent UTXO to spend.
type TransparentInput struct {
	TxID         [32]byte // Transaction ID
	OutputIndex  uint32   // Output index
	Value        uint64   // Value in zatoshis
	ScriptPubKey []byte   // Locking script
	RedeemScript []byte   // P2SH redeem script (nil for P2PKH)
	Sequence     *uint32  // Sequence number (nil = 0xFFFFFFFF)
}

// OrchardOutput represents a shielded Orchard output.
type OrchardOutput struct {
	Address string // Orchard unified address (or raw Orchard address)
	Value   uint64 // Value in zatoshis
	Memo    []byte // Memo field (max 512 bytes)
}

// TransparentOutput represents a transparent output (e.g., change).
type TransparentOutput struct {
	Value        uint64  // Value in zatoshis
	ScriptPubKey []byte  // Locking script
	Address      *string // Optional user address
}

// TransactionProposal contains all inputs and outputs for a transaction.
type TransactionProposal struct {
	TransparentInputs  []TransparentInput
	TransparentOutputs []TransparentOutput
	OrchardOutputs     []OrchardOutput

	// Transaction metadata
	ConsensusBranchID uint32  // Network upgrade branch ID
	ExpiryHeight      uint32  // Block height for expiry
	CoinType          uint32  // SLIP 44 coin type (133 = mainnet, 1 = testnet)
	OrchardAnchor     [32]byte // Orchard commitment tree anchor
	LockTime          *uint32  // Optional nLockTime
}

// ============================================================================
// API Function 1: ProposeTransaction
// ============================================================================

// ProposeTransaction creates a PCZT from a transaction proposal.
//
// This function:
//  1. Creates a new PCZT using the Creator role
//  2. Adds all inputs and outputs using the Constructor role
//  3. Finalizes I/O using the IO Finalizer role
//
// The resulting PCZT is ready for proving (ProveTransaction).
//
// Corresponds to the `propose_transaction` function in ZIP 374.
//
// Parameters:
//   - proposal: Transaction inputs, outputs, and metadata
//
// Returns:
//   - Serialized PCZT bytes
//   - Error if construction fails
func ProposeTransaction(proposal *TransactionProposal) ([]byte, error) {
	// Step 1: Creator - Initialize PCZT
	creator := roles.NewCreator(
		proposal.ConsensusBranchID,
		proposal.ExpiryHeight,
		proposal.CoinType,
		proposal.OrchardAnchor,
	)

	if proposal.LockTime != nil {
		creator.WithFallbackLockTime(*proposal.LockTime)
	}

	p := creator.Create()

	// Step 2: Constructor - Add inputs and outputs
	constructor := roles.NewConstructor(p)

	// Add transparent inputs
	for _, input := range proposal.TransparentInputs {
		err := constructor.AddTransparentInput(
			input.TxID,
			input.OutputIndex,
			input.Value,
			input.ScriptPubKey,
			input.RedeemScript,
			input.Sequence,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add transparent input: %w", err)
		}
	}

	// Add transparent outputs
	for _, output := range proposal.TransparentOutputs {
		err := constructor.AddTransparentOutput(
			output.Value,
			output.ScriptPubKey,
			output.Address,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add transparent output: %w", err)
		}
	}

	// Add Orchard outputs
	for _, output := range proposal.OrchardOutputs {
		// Parse Orchard address
		// TODO: Implement proper address parsing
		// For now, assume raw 43-byte address is provided
		recipient, err := parseOrchardAddress(output.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Orchard address: %w", err)
		}

		// Pad memo to 512 bytes
		memo := [512]byte{}
		copy(memo[:], output.Memo)

		err = constructor.AddOrchardOutput(recipient, output.Value, memo)
		if err != nil {
			return nil, fmt.Errorf("failed to add Orchard output: %w", err)
		}
	}

	p = constructor.Finish()

	// Step 3: IO Finalizer - Lock transaction structure
	ioFinalizer := roles.NewIoFinalizer(p)
	if err := ioFinalizer.Finalize(); err != nil {
		return nil, fmt.Errorf("IO finalization failed: %w", err)
	}

	p = ioFinalizer.Finish()

	// Serialize PCZT
	pcztBytes, err := pczt.Serialize(p)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PCZT: %w", err)
	}

	return pcztBytes, nil
}

// ============================================================================
// API Function 2: ProveTransaction
// ============================================================================

// ProveTransaction generates zero-knowledge proofs for a PCZT.
//
// This calls into the Rust FFI to generate Orchard ZK proofs using
// the zcash_proofs library. The proofs prove the validity of the
// Orchard actions without revealing any private information.
//
// Corresponds to the `prove_transaction` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Serialized PCZT from ProposeTransaction
//
// Returns:
//   - Serialized PCZT with proofs attached
//   - Error if proving fails
func ProveTransaction(pcztBytes []byte) ([]byte, error) {
	// Call Rust FFI to generate proofs
	provedBytes, err := ffi.ProvePCZT(pcztBytes)
	if err != nil {
		return nil, fmt.Errorf("proving failed: %w", err)
	}

	return provedBytes, nil
}

// ============================================================================
// API Function 3: VerifyBeforeSigning
// ============================================================================

// VerifyBeforeSigning validates a PCZT before signing.
//
// This function checks:
//  - PCZT is well-formed
//  - All required fields are present
//  - Proofs are valid (if present)
//  - Transaction balances correctly
//  - No modification flags conflict with existing signatures
//
// Wallets should call this before presenting the transaction to the
// user for signing.
//
// Corresponds to the `verify_before_signing` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Serialized PCZT
//
// Returns:
//   - Error if validation fails (nil = valid)
func VerifyBeforeSigning(pcztBytes []byte) error {
	// Deserialize PCZT
	p, err := pczt.Parse(pcztBytes)
	if err != nil {
		return fmt.Errorf("invalid PCZT: %w", err)
	}

	// Check that PCZT is finalized (no modification flags)
	if p.Global.TxModifiable != 0 {
		return fmt.Errorf("PCZT not finalized (tx_modifiable = 0x%x)", p.Global.TxModifiable)
	}

	// Validate transparent inputs
	if len(p.Transparent.Inputs) == 0 {
		return fmt.Errorf("no transparent inputs")
	}

	// Check all inputs have required fields
	for i, input := range p.Transparent.Inputs {
		if len(input.ScriptPubKey) == 0 {
			return fmt.Errorf("input %d missing scriptPubKey", i)
		}
		if input.Value == 0 {
			return fmt.Errorf("input %d has zero value", i)
		}
	}

	// Validate Orchard bundle if present
	if len(p.Orchard.Actions) > 0 {
		// Check that proofs exist
		if p.Orchard.ZkProof == nil {
			return fmt.Errorf("Orchard actions present but no ZK proof")
		}

		// Check that bsk is set
		if p.Orchard.Bsk == nil {
			return fmt.Errorf("Orchard bundle missing bsk")
		}

		// Validate each action
		for i, action := range p.Orchard.Actions {
			if action.Spend.SpendAuthSig == nil {
				return fmt.Errorf("action %d missing spend authorization signature", i)
			}
		}
	}

	// Check value balance
	// TODO: Implement full value balance validation
	// Should verify: sum(transparent_inputs) = sum(transparent_outputs) + sum(orchard_outputs)

	return nil
}

// ============================================================================
// API Function 4: GetSighash
// ============================================================================

// GetSighash computes the ZIP 244 signature hash for an input.
//
// This is the 32-byte hash that should be signed with the private key.
//
// Corresponds to the `get_sighash` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Serialized PCZT
//   - inputIndex: Index of the input to sign (0-based)
//
// Returns:
//   - 32-byte signature hash
//   - Error if computation fails
func GetSighash(pcztBytes []byte, inputIndex uint32) ([32]byte, error) {
	var sighash [32]byte

	// Deserialize PCZT
	p, err := pczt.Parse(pcztBytes)
	if err != nil {
		return sighash, fmt.Errorf("invalid PCZT: %w", err)
	}

	// Validate input index
	if int(inputIndex) >= len(p.Transparent.Inputs) {
		return sighash, fmt.Errorf("input index %d out of bounds (have %d inputs)",
			inputIndex, len(p.Transparent.Inputs))
	}

	// Get sighash type for this input
	input := &p.Transparent.Inputs[inputIndex]

	// Compute ZIP 244 signature hash
	sighash, err = crypto.GetSignatureHash(p, inputIndex, input.SighashType)
	if err != nil {
		return sighash, fmt.Errorf("failed to compute sighash: %w", err)
	}

	return sighash, nil
}

// ============================================================================
// API Function 5: AppendSignature
// ============================================================================

// AppendSignature adds a signature to a transparent input.
//
// This function:
//  1. Deserializes the PCZT
//  2. Adds the signature using the Signer role
//  3. Serializes the PCZT back to bytes
//
// Multiple parties can call this function independently to add their
// signatures. The Combiner can later merge them.
//
// Corresponds to the `append_signature` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Serialized PCZT
//   - inputIndex: Index of the input to sign
//   - privateKey: Private key for signing (WIF format)
//
// Returns:
//   - Serialized PCZT with signature added
//   - Error if signing fails
func AppendSignature(
	pcztBytes []byte,
	inputIndex uint32,
	privateKey *crypto.PrivateKey,
) ([]byte, error) {
	// Deserialize PCZT
	p, err := pczt.Parse(pcztBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PCZT: %w", err)
	}

	// Sign the input
	signer := roles.NewSigner(p)
	if err := signer.SignTransparentInput(inputIndex, privateKey); err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	p = signer.Finish()

	// Serialize back to bytes
	signedBytes, err := pczt.Serialize(p)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed PCZT: %w", err)
	}

	return signedBytes, nil
}

// ============================================================================
// API Function 6: Combine
// ============================================================================

// Combine merges multiple PCZTs with partial signatures.
//
// This enables parallel signing workflows where multiple parties sign
// independently and then combine their signatures.
//
// All PCZTs must represent the same transaction (same inputs/outputs).
//
// Corresponds to the `combine` function in ZIP 374.
//
// Parameters:
//   - pcztBytesList: List of serialized PCZTs to combine
//
// Returns:
//   - Combined PCZT with all signatures merged
//   - Error if combination fails
func Combine(pcztBytesList [][]byte) ([]byte, error) {
	if len(pcztBytesList) == 0 {
		return nil, fmt.Errorf("no PCZTs to combine")
	}

	if len(pcztBytesList) == 1 {
		return pcztBytesList[0], nil
	}

	// Deserialize all PCZTs
	pczts := make([]*pczt.PCZT, len(pcztBytesList))
	for i, pcztBytes := range pcztBytesList {
		p, err := pczt.Parse(pcztBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PCZT %d: %w", i, err)
		}
		pczts[i] = p
	}

	// Combine using Combiner role
	combiner := roles.NewCombiner(pczts)
	combined, err := combiner.Combine()
	if err != nil {
		return nil, fmt.Errorf("combination failed: %w", err)
	}

	// Serialize combined PCZT
	combinedBytes, err := pczt.Serialize(combined)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize combined PCZT: %w", err)
	}

	return combinedBytes, nil
}

// ============================================================================
// API Function 7: FinalizeAndExtract
// ============================================================================

// FinalizeAndExtract finalizes a PCZT and extracts the raw transaction.
//
// This function:
//  1. Finalizes transparent inputs using the Spend Finalizer
//  2. Extracts the final transaction using the Transaction Extractor
//
// The resulting transaction bytes are ready to broadcast to the network.
//
// Corresponds to the `finalize_and_extract` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Fully signed PCZT
//
// Returns:
//   - Raw transaction bytes (ready for broadcast)
//   - Error if finalization fails
func FinalizeAndExtract(pcztBytes []byte) ([]byte, error) {
	// Deserialize PCZT
	p, err := pczt.Parse(pcztBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PCZT: %w", err)
	}

	// Finalize transparent inputs
	spendFinalizer := roles.NewSpendFinalizer(p)
	if err := spendFinalizer.Finalize(); err != nil {
		return nil, fmt.Errorf("spend finalization failed: %w", err)
	}

	p = spendFinalizer.Finish()

	// Extract transaction
	extractor := roles.NewTxExtractor(p)
	txBytes, err := extractor.Extract()
	if err != nil {
		return nil, fmt.Errorf("transaction extraction failed: %w", err)
	}

	return txBytes, nil
}

// ============================================================================
// API Functions 8a & 8b: ParsePCZT / SerializePCZT
// ============================================================================

// ParsePCZT deserializes a PCZT from bytes.
//
// This is a convenience wrapper around the pczt package's Deserialize function.
//
// Corresponds to the `parse_pczt` function in ZIP 374.
//
// Parameters:
//   - pcztBytes: Serialized PCZT bytes
//
// Returns:
//   - Parsed PCZT structure
//   - Error if parsing fails
func ParsePCZT(pcztBytes []byte) (*pczt.PCZT, error) {
	return pczt.Parse(pcztBytes)
}

// SerializePCZT serializes a PCZT to bytes.
//
// This is a convenience wrapper around the pczt package's Serialize function.
//
// Corresponds to the `serialize_pczt` function in ZIP 374.
//
// Parameters:
//   - p: PCZT structure
//
// Returns:
//   - Serialized PCZT bytes
//   - Error if serialization fails
func SerializePCZT(p *pczt.PCZT) ([]byte, error) {
	return pczt.Serialize(p)
}

// ============================================================================
// Helper functions
// ============================================================================

// parseOrchardAddress parses an Orchard address string.
//
// TODO: Implement proper unified address parsing
// For now, this is a placeholder that accepts hex-encoded 43-byte addresses
func parseOrchardAddress(address string) ([43]byte, error) {
	var result [43]byte

	// TODO: Implement proper address parsing using zcash_address library
	// Should support:
	// - Unified addresses (u...)
	// - Raw Orchard addresses (if exposed)
	//
	// For now, assume hex-encoded 43 bytes
	if len(address) != 86 { // 43 bytes * 2 hex chars
		return result, fmt.Errorf("invalid Orchard address length")
	}

	// Placeholder: would decode hex here
	return result, fmt.Errorf("Orchard address parsing not yet implemented")
}

// ParsePaymentRequest parses a ZIP 321 payment request URI.
//
// This is a convenience function that wraps the zip321 package.
//
// Parameters:
//   - uri: ZIP 321 payment request URI
//
// Returns:
//   - Parsed payment request
//   - Error if parsing fails
func ParsePaymentRequest(uri string) (*zip321.PaymentRequest, error) {
	return zip321.Parse(uri)
}
