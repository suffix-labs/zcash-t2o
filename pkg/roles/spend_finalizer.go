package roles

import (
	"bytes"
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// SpendFinalizer finalizes transparent inputs by constructing scriptSigs.
//
// Corresponds to: pczt::roles::spend_finalizer::SpendFinalizer
//   (librustzcash/pczt/src/roles/spend_finalizer/)
//
// The Spend Finalizer role:
//   - Takes partial signatures from the Signer role
//   - Constructs final scriptSig scripts for each transparent input
//   - Handles both P2PKH and P2SH input types
//   - Clears metadata (signatures, derivation info) after finalization
//
// After this role executes, the transparent inputs are ready for extraction
// into the final transaction.
type SpendFinalizer struct {
	pczt *pczt.PCZT
}

// NewSpendFinalizer creates a new Spend Finalizer.
func NewSpendFinalizer(p *pczt.PCZT) *SpendFinalizer {
	return &SpendFinalizer{pczt: p}
}

// Finalize finalizes all transparent inputs.
//
// This constructs the scriptSig for each input based on its type:
//   - P2PKH: <signature> <pubkey>
//   - P2SH: <sig1> <sig2> ... <redeemScript>
//
// Returns an error if any input cannot be finalized (missing signatures, etc.)
func (f *SpendFinalizer) Finalize() error {
	for i := range f.pczt.Transparent.Inputs {
		input := &f.pczt.Transparent.Inputs[i]

		// Determine input type and finalize accordingly
		if input.RedeemScript != nil {
			// P2SH input
			if err := f.finalizeP2SH(input); err != nil {
				return fmt.Errorf("failed to finalize P2SH input %d: %w", i, err)
			}
		} else {
			// P2PKH input
			if err := f.finalizeP2PKH(input); err != nil {
				return fmt.Errorf("failed to finalize P2PKH input %d: %w", i, err)
			}
		}

		// Clear metadata after finalization
		// This removes sensitive information and reduces PCZT size
		f.clearInputMetadata(input)
	}

	return nil
}

// finalizeP2PKH constructs a P2PKH scriptSig.
//
// P2PKH scriptSig format: <signature> <pubkey>
//
// Corresponds to: Bitcoin P2PKH (Pay-to-Public-Key-Hash)
//   See: bitcoin/script/script.h
func (f *SpendFinalizer) finalizeP2PKH(input *pczt.TransparentInput) error {
	// P2PKH requires exactly one signature
	if len(input.PartialSignatures) != 1 {
		return fmt.Errorf("P2PKH requires exactly 1 signature, got %d",
			len(input.PartialSignatures))
	}

	// Get the single signature and pubkey
	var signature []byte
	var pubkey [33]byte
	for pk, sig := range input.PartialSignatures {
		pubkey = pk
		signature = sig
		break
	}

	// Build scriptSig: <signature> <pubkey>
	scriptSig := buildScriptSig(signature, pubkey[:])
	input.ScriptSig = &scriptSig

	return nil
}

// finalizeP2SH constructs a P2SH scriptSig.
//
// P2SH scriptSig format: <sig1> <sig2> ... <sigN> <redeemScript>
//
// The exact signature order and count depend on the redeemScript.
// For multisig, signatures must be in the same order as pubkeys in the redeemScript.
//
// Corresponds to: Bitcoin P2SH (Pay-to-Script-Hash)
//   See: bitcoin/script/script.h
func (f *SpendFinalizer) finalizeP2SH(input *pczt.TransparentInput) error {
	if input.RedeemScript == nil {
		return fmt.Errorf("P2SH input missing redeem script")
	}

	// For simplicity, we assume a standard multisig redeem script
	// More complex P2SH types would require parsing the redeemScript
	// TODO: Add support for parsing complex redeem scripts

	// Collect all signatures
	signatures := make([][]byte, 0, len(input.PartialSignatures))
	for _, sig := range input.PartialSignatures {
		signatures = append(signatures, sig)
	}

	if len(signatures) == 0 {
		return fmt.Errorf("P2SH input has no signatures")
	}

	// Build scriptSig: <sig1> <sig2> ... <redeemScript>
	scriptSig := buildP2SHScriptSig(signatures, input.RedeemScript)
	input.ScriptSig = &scriptSig

	return nil
}

// clearInputMetadata clears sensitive and unnecessary metadata.
//
// After finalization, we no longer need:
//   - Partial signatures (now in scriptSig)
//   - Derivation information (only needed for signing)
//   - Hash preimages (only needed for script construction)
//
// This reduces PCZT size and removes potentially sensitive information.
func (f *SpendFinalizer) clearInputMetadata(input *pczt.TransparentInput) {
	input.PartialSignatures = nil
	input.Bip32Derivation = nil
	input.Ripemd160Preimages = nil
	input.Sha256Preimages = nil
	input.Hash160Preimages = nil
	input.Hash256Preimages = nil
}

// Finish returns the finalized PCZT.
//
// The PCZT is now ready for the Transaction Extractor to produce the
// final transaction bytes.
func (f *SpendFinalizer) Finish() *pczt.PCZT {
	return f.pczt
}

// ============================================================================
// Bitcoin Script Construction Helpers
//
// These functions build Bitcoin-style script bytecode for transparent inputs.
//
// See: bitcoin/script/script.h and bitcoin/script/interpreter.cpp
// ============================================================================

// buildScriptSig constructs a P2PKH scriptSig.
//
// Format: <signature> <pubkey>
//
// Each element is pushed to the stack with a length prefix:
//   - OP_PUSHBYTES_N (where N is the length of the following data)
//   - Data bytes
func buildScriptSig(signature []byte, pubkey []byte) []byte {
	var buf bytes.Buffer

	// Push signature
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)

	// Push pubkey
	buf.WriteByte(byte(len(pubkey)))
	buf.Write(pubkey)

	return buf.Bytes()
}

// buildP2SHScriptSig constructs a P2SH scriptSig.
//
// Format: <sig1> <sig2> ... <sigN> <redeemScript>
//
// For multisig redeem scripts, there's a dummy OP_0 at the start due to
// a Bitcoin off-by-one bug (CHECKMULTISIG pops an extra value).
//
// See: https://bitcoin.stackexchange.com/questions/38037/
func buildP2SHScriptSig(signatures [][]byte, redeemScript []byte) []byte {
	var buf bytes.Buffer

	// OP_0 (dummy value for CHECKMULTISIG bug)
	// This is required for standard multisig P2SH
	buf.WriteByte(0x00)

	// Push each signature
	for _, sig := range signatures {
		buf.WriteByte(byte(len(sig)))
		buf.Write(sig)
	}

	// Push redeem script
	// Use appropriate push opcode based on length
	if len(redeemScript) <= 75 {
		buf.WriteByte(byte(len(redeemScript)))
	} else if len(redeemScript) <= 0xFF {
		buf.WriteByte(0x4C) // OP_PUSHDATA1
		buf.WriteByte(byte(len(redeemScript)))
	} else {
		buf.WriteByte(0x4D) // OP_PUSHDATA2
		buf.WriteByte(byte(len(redeemScript)))
		buf.WriteByte(byte(len(redeemScript) >> 8))
	}
	buf.Write(redeemScript)

	return buf.Bytes()
}
