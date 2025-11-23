package roles

import (
	"bytes"
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// Combiner merges multiple PCZTs into a single PCZT.
//
// Corresponds to: pczt::roles::combiner::Combiner
//   (librustzcash/pczt/src/roles/combiner/)
//
// The Combiner role enables parallel signing workflows:
//   - Multiple parties can sign different inputs in parallel
//   - Each party creates their own PCZT with partial signatures
//   - The Combiner merges all partial signatures into one PCZT
//
// Use cases:
//   - Multi-signature wallets (multiple parties must sign)
//   - Parallel hardware wallet signing
//   - Distributed transaction construction
//
// The Combiner merges:
//   - Partial signatures from transparent inputs
//   - Metadata (derivation paths, preimages, etc.)
//   - Proprietary fields
type Combiner struct {
	pczts []*pczt.PCZT
}

// NewCombiner creates a new Combiner.
//
// Parameters:
//   - pczts: List of PCZTs to combine (must all represent the same transaction)
func NewCombiner(pczts []*pczt.PCZT) *Combiner {
	return &Combiner{pczts: pczts}
}

// Combine merges all PCZTs into a single PCZT.
//
// The PCZTs must be compatible (same transaction structure). This function
// merges all partial signatures and metadata.
//
// Returns an error if:
//   - PCZTs are incompatible (different transaction IDs)
//   - Conflicting data is found
func (c *Combiner) Combine() (*pczt.PCZT, error) {
	if len(c.pczts) == 0 {
		return nil, fmt.Errorf("no PCZTs to combine")
	}

	if len(c.pczts) == 1 {
		return c.pczts[0], nil
	}

	// Use first PCZT as base
	result := c.pczts[0]

	// Merge each subsequent PCZT
	for i := 1; i < len(c.pczts); i++ {
		if err := c.mergeInto(result, c.pczts[i]); err != nil {
			return nil, fmt.Errorf("failed to merge PCZT %d: %w", i, err)
		}
	}

	return result, nil
}

// mergeInto merges source PCZT into destination PCZT.
//
// This combines:
//   - Transparent input partial signatures and metadata
//   - Transparent output metadata
//   - Global proprietary fields
//
// Orchard actions are not merged (they should be identical across PCZTs).
func (c *Combiner) mergeInto(dst, src *pczt.PCZT) error {
	// Validate PCZTs are compatible
	if err := c.validateCompatible(dst, src); err != nil {
		return err
	}

	// Merge global metadata
	c.mergeGlobal(&dst.Global, &src.Global)

	// Merge transparent inputs
	if err := c.mergeTransparentInputs(dst, src); err != nil {
		return err
	}

	// Merge transparent outputs
	c.mergeTransparentOutputs(dst, src)

	return nil
}

// validateCompatible checks if two PCZTs represent the same transaction.
//
// PCZTs are compatible if they have:
//   - Same transaction version
//   - Same consensus branch ID
//   - Same expiry height
//   - Same number of inputs/outputs
//   - Same input prevouts (txid + index)
func (c *Combiner) validateCompatible(a, b *pczt.PCZT) error {
	// Check global fields
	if a.Global.TxVersion != b.Global.TxVersion {
		return fmt.Errorf("incompatible tx versions: %d != %d",
			a.Global.TxVersion, b.Global.TxVersion)
	}

	if a.Global.ConsensusBranchID != b.Global.ConsensusBranchID {
		return fmt.Errorf("incompatible consensus branch IDs: 0x%x != 0x%x",
			a.Global.ConsensusBranchID, b.Global.ConsensusBranchID)
	}

	if a.Global.ExpiryHeight != b.Global.ExpiryHeight {
		return fmt.Errorf("incompatible expiry heights: %d != %d",
			a.Global.ExpiryHeight, b.Global.ExpiryHeight)
	}

	// Check transparent bundle compatibility
	if len(a.Transparent.Inputs) != len(b.Transparent.Inputs) {
		return fmt.Errorf("incompatible input counts: %d != %d",
			len(a.Transparent.Inputs), len(b.Transparent.Inputs))
	}

	if len(a.Transparent.Outputs) != len(b.Transparent.Outputs) {
		return fmt.Errorf("incompatible output counts: %d != %d",
			len(a.Transparent.Outputs), len(b.Transparent.Outputs))
	}

	// Check each input prevout matches
	for i := range a.Transparent.Inputs {
		aInput := &a.Transparent.Inputs[i]
		bInput := &b.Transparent.Inputs[i]

		if !bytes.Equal(aInput.PrevoutTxID[:], bInput.PrevoutTxID[:]) {
			return fmt.Errorf("input %d has different prevout txid", i)
		}

		if aInput.PrevoutIndex != bInput.PrevoutIndex {
			return fmt.Errorf("input %d has different prevout index: %d != %d",
				i, aInput.PrevoutIndex, bInput.PrevoutIndex)
		}
	}

	return nil
}

// mergeGlobal merges global metadata.
//
// This combines proprietary fields from both PCZTs.
func (c *Combiner) mergeGlobal(dst, src *pczt.Global) {
	// Merge proprietary fields
	for key, value := range src.Proprietary {
		if _, exists := dst.Proprietary[key]; !exists {
			dst.Proprietary[key] = value
		}
	}
}

// mergeTransparentInputs merges transparent input data.
//
// For each input, this merges:
//   - Partial signatures (by pubkey)
//   - BIP32 derivation paths
//   - Hash preimages
//   - Proprietary fields
func (c *Combiner) mergeTransparentInputs(dst, src *pczt.PCZT) error {
	for i := range dst.Transparent.Inputs {
		dstInput := &dst.Transparent.Inputs[i]
		srcInput := &src.Transparent.Inputs[i]

		// Merge partial signatures
		// Key is the compressed public key (33 bytes)
		for pubkey, signature := range srcInput.PartialSignatures {
			if existing, exists := dstInput.PartialSignatures[pubkey]; exists {
				// Check for conflicting signatures for same pubkey
				if !bytes.Equal(existing, signature) {
					return fmt.Errorf("input %d: conflicting signatures for pubkey %x", i, pubkey)
				}
			} else {
				dstInput.PartialSignatures[pubkey] = signature
			}
		}

		// Merge BIP32 derivation paths
		for pubkey, derivation := range srcInput.Bip32Derivation {
			if _, exists := dstInput.Bip32Derivation[pubkey]; !exists {
				dstInput.Bip32Derivation[pubkey] = derivation
			}
		}

		// Merge hash preimages
		c.mergeHashPreimages(dstInput, srcInput)

		// Merge proprietary fields
		for key, value := range srcInput.Proprietary {
			if _, exists := dstInput.Proprietary[key]; !exists {
				dstInput.Proprietary[key] = value
			}
		}

		// Merge redeem script if present
		if dstInput.RedeemScript == nil && srcInput.RedeemScript != nil {
			dstInput.RedeemScript = srcInput.RedeemScript
		}

		// Merge scriptSig if present (from finalized PCZT)
		if dstInput.ScriptSig == nil && srcInput.ScriptSig != nil {
			dstInput.ScriptSig = srcInput.ScriptSig
		}
	}

	return nil
}

// mergeHashPreimages merges hash preimage maps.
//
// These are used for hash-locked scripts (RIPEMD160, SHA256, HASH160, HASH256).
func (c *Combiner) mergeHashPreimages(dst, src *pczt.TransparentInput) {
	// RIPEMD160 preimages
	for hash, preimage := range src.Ripemd160Preimages {
		if _, exists := dst.Ripemd160Preimages[hash]; !exists {
			dst.Ripemd160Preimages[hash] = preimage
		}
	}

	// SHA256 preimages
	for hash, preimage := range src.Sha256Preimages {
		if _, exists := dst.Sha256Preimages[hash]; !exists {
			dst.Sha256Preimages[hash] = preimage
		}
	}

	// HASH160 preimages (RIPEMD160(SHA256(x)))
	for hash, preimage := range src.Hash160Preimages {
		if _, exists := dst.Hash160Preimages[hash]; !exists {
			dst.Hash160Preimages[hash] = preimage
		}
	}

	// HASH256 preimages (SHA256(SHA256(x)))
	for hash, preimage := range src.Hash256Preimages {
		if _, exists := dst.Hash256Preimages[hash]; !exists {
			dst.Hash256Preimages[hash] = preimage
		}
	}
}

// mergeTransparentOutputs merges transparent output metadata.
//
// For each output, this merges:
//   - BIP32 derivation paths
//   - User addresses
//   - Proprietary fields
func (c *Combiner) mergeTransparentOutputs(dst, src *pczt.PCZT) {
	for i := range dst.Transparent.Outputs {
		dstOutput := &dst.Transparent.Outputs[i]
		srcOutput := &src.Transparent.Outputs[i]

		// Merge BIP32 derivation paths
		for pubkey, derivation := range srcOutput.Bip32Derivation {
			if _, exists := dstOutput.Bip32Derivation[pubkey]; !exists {
				dstOutput.Bip32Derivation[pubkey] = derivation
			}
		}

		// Merge user address
		if dstOutput.UserAddress == nil && srcOutput.UserAddress != nil {
			dstOutput.UserAddress = srcOutput.UserAddress
		}

		// Merge proprietary fields
		for key, value := range srcOutput.Proprietary {
			if _, exists := dstOutput.Proprietary[key]; !exists {
				dstOutput.Proprietary[key] = value
			}
		}
	}
}
