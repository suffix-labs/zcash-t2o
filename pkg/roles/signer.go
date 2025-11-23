package roles

import (
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/crypto"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// Signer adds signatures to transparent inputs.
//
// Corresponds to: pczt::roles::signer::Signer
//   (librustzcash/pczt/src/roles/signer/)
//
// The Signer role:
//   - Computes ZIP 244 signature hashes for each transparent input
//   - Signs the sighashes with private keys
//   - Stores signatures as "partial signatures" in the PCZT
//   - Updates modification flags based on SIGHASH types
//
// Multiple signers can operate in parallel, each signing their inputs.
// The Combiner role can then merge the signatures together.
type Signer struct {
	pczt *pczt.PCZT
}

// NewSigner creates a new Signer.
func NewSigner(p *pczt.PCZT) *Signer {
	return &Signer{pczt: p}
}

// SignTransparentInput signs a specific transparent input.
//
// This computes the ZIP 244 signature hash for the input, signs it with
// the provided private key, and adds the signature to the PCZT's partial
// signatures map.
//
// Parameters:
//   - inputIndex: Index of the input to sign (0-based)
//   - privateKey: secp256k1 private key for signing
//
// The signature format is: DER-encoded ECDSA signature || SIGHASH type byte
//
// Returns an error if:
//   - Input index is out of bounds
//   - Sighash computation fails
//   - Signing fails
func (s *Signer) SignTransparentInput(
	inputIndex uint32,
	privateKey *crypto.PrivateKey,
) error {
	if int(inputIndex) >= len(s.pczt.Transparent.Inputs) {
		return fmt.Errorf("input index %d out of bounds (have %d inputs)",
			inputIndex, len(s.pczt.Transparent.Inputs))
	}

	input := &s.pczt.Transparent.Inputs[inputIndex]

	// Compute ZIP 244 signature hash for this input
	// This is the 32-byte value that we'll sign with the private key
	sighash, err := crypto.GetSignatureHash(s.pczt, inputIndex, input.SighashType)
	if err != nil {
		return fmt.Errorf("failed to compute sighash: %w", err)
	}

	// Sign the sighash with the private key (ECDSA on secp256k1)
	derSignature, err := privateKey.Sign(sighash)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	// Append the sighash type byte to the signature
	// Bitcoin/Zcash transparent signatures have format: DER_signature || sighash_type
	signature := append(derSignature, input.SighashType)

	// Add to partial signatures map (pubkey -> signature)
	// The Spend Finalizer will later use this to construct the scriptSig
	pubkey := privateKey.PublicKey().SerializeCompressed()
	input.PartialSignatures[pubkey] = signature

	// Update the transaction's modifiable flags based on what this signature commits to
	// For example, SIGHASH_ALL commits to all inputs and outputs (nothing modifiable)
	s.updateModifiableFlags(input.SighashType)

	return nil
}

// updateModifiableFlags updates tx_modifiable based on SIGHASH type.
//
// Different SIGHASH types commit to different parts of the transaction:
//   - SIGHASH_ALL: Signs all inputs and outputs (nothing modifiable)
//   - SIGHASH_NONE: Signs all inputs but no outputs (outputs modifiable)
//   - SIGHASH_SINGLE: Signs all inputs and one output (other outputs modifiable)
//   - SIGHASH_ANYONECANPAY: Signs only this input (other inputs modifiable)
//
// This function clears the appropriate modification flags to reflect what
// the signature commits to.
func (s *Signer) updateModifiableFlags(sighashType uint8) {
	// Extract base sighash type (remove ANYONECANPAY flag if present)
	base := sighashType & 0x1F
	anyoneCanPay := (sighashType & pczt.SighashAnyoneCanPay) != 0

	// If not ANYONECANPAY, the signature commits to all inputs
	// Clear the inputs modifiable flags
	if !anyoneCanPay {
		s.pczt.Global.TxModifiable &^= pczt.FlagTransparentInputsModifiable
		s.pczt.Global.TxModifiable &^= pczt.FlagShieldedModifiable
	}

	// If SIGHASH_ALL, the signature commits to all outputs
	// Clear the outputs modifiable flags
	if base == pczt.SighashAll {
		s.pczt.Global.TxModifiable &^= pczt.FlagTransparentOutputsModifiable
		s.pczt.Global.TxModifiable &^= pczt.FlagShieldedModifiable
	}

	// If SIGHASH_SINGLE, set the flag to indicate at least one input uses it
	// This is important for validation
	if base == pczt.SighashSingle {
		s.pczt.Global.TxModifiable |= pczt.FlagHasSighashSingle
	}
}

// Finish returns the signed PCZT.
//
// The PCZT now contains partial signatures and can be:
//   - Passed to the Combiner if multiple parties are signing
//   - Passed to the Spend Finalizer to create final scriptSigs
func (s *Signer) Finish() *pczt.PCZT {
	return s.pczt
}
