package roles

import (
	"crypto/rand"
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/ffi"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// Constructor adds inputs and outputs to a PCZT.
//
// Corresponds to: pczt::roles::updater::Updater (librustzcash/pczt/src/roles/)
//
// Note: The Rust implementation calls this "Updater" but the spec uses "Constructor".
// The Constructor role:
//   - Adds transparent inputs (UTXOs to spend)
//   - Adds Orchard outputs (shielded recipients)
//   - Creates dummy spends for output-only actions
//   - Computes value commitments and note commitments
//   - Updates the Orchard value balance
//
// For transparent-to-Orchard transactions, this role bridges the transparent
// and shielded pools by creating Orchard actions with dummy spends.
type Constructor struct {
	pczt *pczt.PCZT
}

// NewConstructor creates a new Constructor from an existing PCZT.
//
// The PCZT should have been created by the Creator role.
func NewConstructor(p *pczt.PCZT) *Constructor {
	return &Constructor{pczt: p}
}

// AddTransparentInput adds a transparent UTXO to spend.
//
// Parameters:
//   - prevoutTxID: Transaction ID of the UTXO
//   - prevoutIndex: Output index in the transaction
//   - value: Value in zatoshis
//   - scriptPubKey: Locking script from the UTXO
//   - redeemScript: P2SH redeem script (nil for P2PKH)
//   - sequence: Sequence number (nil uses default 0xFFFFFFFF)
//
// The input is added with default SIGHASH_ALL. Signatures will be added
// by the Signer role later.
func (c *Constructor) AddTransparentInput(
	prevoutTxID [32]byte,
	prevoutIndex uint32,
	value uint64,
	scriptPubKey []byte,
	redeemScript []byte,
	sequence *uint32,
) error {
	// Check if inputs are modifiable
	if c.pczt.Global.TxModifiable&pczt.FlagTransparentInputsModifiable == 0 {
		return fmt.Errorf("transparent inputs not modifiable")
	}

	input := pczt.TransparentInput{
		PrevoutTxID:        prevoutTxID,
		PrevoutIndex:       prevoutIndex,
		Value:              value,
		ScriptPubKey:       scriptPubKey,
		SighashType:        pczt.SighashAll,
		Sequence:           sequence,
		RedeemScript:       redeemScript,
		PartialSignatures:  make(map[[33]byte][]byte),
		Bip32Derivation:    make(map[[33]byte]pczt.Zip32Derivation),
		Ripemd160Preimages: make(map[[20]byte][]byte),
		Sha256Preimages:    make(map[[32]byte][]byte),
		Hash160Preimages:   make(map[[20]byte][]byte),
		Hash256Preimages:   make(map[[32]byte][]byte),
		Proprietary:        make(map[string][]byte),
	}

	c.pczt.Transparent.Inputs = append(c.pczt.Transparent.Inputs, input)
	return nil
}

// AddTransparentOutput adds a transparent output (e.g., for change).
//
// This is used for sending transparent change back to the sender or
// for mixing transparent and shielded outputs.
func (c *Constructor) AddTransparentOutput(
	value uint64,
	scriptPubKey []byte,
	userAddress *string,
) error {
	// Check if outputs are modifiable
	if c.pczt.Global.TxModifiable&pczt.FlagTransparentOutputsModifiable == 0 {
		return fmt.Errorf("transparent outputs not modifiable")
	}

	output := pczt.TransparentOutput{
		Value:           value,
		ScriptPubKey:    scriptPubKey,
		Bip32Derivation: make(map[[33]byte]pczt.Zip32Derivation),
		UserAddress:     userAddress,
		Proprietary:     make(map[string][]byte),
	}

	c.pczt.Transparent.Outputs = append(c.pczt.Transparent.Outputs, output)
	return nil
}

// AddOrchardOutput adds an Orchard shielded output.
//
// Parameters:
//   - recipient: Raw Orchard address (43 bytes: diversifier + pk_d)
//   - value: Amount in zatoshis
//   - memo: 512-byte memo field (can be empty)
//
// This function creates:
//   - A dummy spend (since Orchard actions pair spend+output)
//   - The actual output with encrypted note
//   - Value commitment and note commitment
//
// All cryptographic operations are performed via Rust FFI to the Orchard crate.
func (c *Constructor) AddOrchardOutput(
	recipient [43]byte,
	value uint64,
	memo [512]byte,
) error {
	// Check if shielded outputs are modifiable
	if c.pczt.Global.TxModifiable&pczt.FlagShieldedModifiable == 0 {
		return fmt.Errorf("shielded outputs not modifiable")
	}

	// Create dummy spend with all cryptographically consistent values via FFI.
	// This generates: nullifier, rk, alpha, fvk, recipient, rho, rseed, witness, dummy_sk
	// All values are internally consistent (nullifier derived from note, etc.)
	dummySpendData, err := ffi.OrchardCreateDummySpend()
	if err != nil {
		return fmt.Errorf("failed to create dummy spend: %w", err)
	}

	// The output note's rho must be Rho::from_nf_old(spend.nullifier)
	// In Orchard, rho = nullifier bytes (they're both Pallas base elements)
	outputRho := dummySpendData.Nullifier

	// Generate random rseed for the output note (different from spend's rseed)
	outputRseed := generateRandomness32()

	// Generate a valid rcv (Pallas scalar) via FFI for the value commitment
	rcv, err := ffi.OrchardGenerateRcv()
	if err != nil {
		return fmt.Errorf("failed to generate rcv: %w", err)
	}

	// Encrypt note and get cmx + epk via FFI
	// This single call handles: note creation, commitment, encryption, and ephemeral key
	encCiphertext, outCiphertext, ephemeralKey, cmx, err := ffi.OrchardEncryptNote(
		recipient,
		value,
		outputRho,
		outputRseed,
		memo,
		rcv,
	)
	if err != nil {
		return fmt.Errorf("note encryption failed: %w", err)
	}

	// Build dummy spend from FFI data
	zeroValue := uint64(0)
	dummySpend := pczt.OrchardSpend{
		Nullifier: dummySpendData.Nullifier,
		Rk:        dummySpendData.Rk,
		Value:     &zeroValue,
		Rho:       &dummySpendData.Rho,
		Rseed:     &dummySpendData.Rseed,
		Recipient: &dummySpendData.Recipient,
		Alpha:     &dummySpendData.Alpha,
		Fvk:       &dummySpendData.Fvk,
		Witness: &pczt.MerkleWitness{
			Position: dummySpendData.WitnessPosition,
			Path:     dummySpendData.WitnessPath,
		},
		DummySk:     &dummySpendData.DummySk,
		Proprietary: make(map[string][]byte),
	}

	// Create output
	output := pczt.OrchardOutput{
		Cmx:           cmx,
		EphemeralKey:  ephemeralKey,
		EncCiphertext: encCiphertext,
		OutCiphertext: outCiphertext,
		Recipient:     &recipient,
		Value:         &value,
		Rseed:         &outputRseed,
		Proprietary:   make(map[string][]byte),
	}

	// Compute value commitment via FFI
	cvNet := computeValueCommitment(value, rcv)

	action := pczt.OrchardAction{
		CvNet:  cvNet,
		Spend:  dummySpend,
		Output: output,
		Rcv:    &rcv,
	}

	c.pczt.Orchard.Actions = append(c.pczt.Orchard.Actions, action)

	// Update value balance (value entering the shielded pool)
	// For transparent -> Orchard, this is positive (value entering)
	c.pczt.Orchard.ValueSum.Magnitude += value
	c.pczt.Orchard.ValueSum.IsNegative = false // Positive balance

	return nil
}

// Finish returns the constructed PCZT.
//
// After all inputs and outputs have been added, call this to get the
// updated PCZT ready for the next role (IO Finalizer).
func (c *Constructor) Finish() *pczt.PCZT {
	return c.pczt
}

// ============================================================================
// Cryptographic helper functions
//
// TODO: These are placeholder implementations. In production, these MUST
// call into the Orchard Rust crate via FFI to perform the actual cryptographic
// operations. Implementing these incorrectly would create invalid transactions.
//
// See: librustzcash/orchard/src/ for the Rust implementations
// ============================================================================

// generateRandomness32 generates 32 bytes of cryptographic randomness.
func generateRandomness32() [32]byte {
	var r [32]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(fmt.Sprintf("failed to generate randomness: %v", err))
	}
	return r
}

// NOTE: The following functions are kept for potential future use but are no longer
// used in the main flow. The new OrchardEncryptNote FFI function handles note
// commitment, ephemeral key derivation, and encryption in a single call.

// deriveNoteCommitment computes the Orchard note commitment.
// This is now handled by OrchardEncryptNote but kept for standalone use cases.
func deriveNoteCommitment(recipient [43]byte, value uint64, rseed [32]byte, rho [32]byte) [32]byte {
	cmx, err := ffi.OrchardNoteCommitment(recipient, value, rseed, rho)
	if err != nil {
		return [32]byte{}
	}
	return cmx
}

// computeValueCommitment computes a Pedersen commitment to the value.
//
// Calls into Rust FFI for actual Pallas curve operations.
// Corresponds to: orchard::value::ValueCommitment in librustzcash
//
// Formula: cv = value * V + rcv * R (on Pallas curve)
// where V and R are fixed generators
func computeValueCommitment(value uint64, rcv [32]byte) [32]byte {
	cv, err := ffi.OrchardValueCommitment(value, rcv)
	if err != nil {
		// Log error but return zero - caller should validate
		return [32]byte{}
	}
	return cv
}

// deriveNullifier computes a nullifier from rho and spending key.
//
// NOTE: The Orchard crate API changed - nullifier derivation now requires
// a full Note object. This function attempts the FFI call but the Rust
// side currently returns an error. For dummy spends, we generate a random
// nullifier which is acceptable since the spend is synthetic.
// Corresponds to: orchard::note::Nullifier::derive in librustzcash
func deriveNullifier(rho [32]byte, sk [32]byte) [32]byte {
	nf, err := ffi.OrchardDeriveNullifier(rho, sk)
	if err != nil {
		// Current Orchard API doesn't expose standalone nullifier derivation
		// For dummy spends, generate a valid dummy nullifier (must be valid Pallas base element)
		dummyNf, err := ffi.OrchardGenerateDummyNullifier()
		if err != nil {
			// Should never happen, but fallback to generating from rho derivation function
			dummyNf, _ = ffi.OrchardGenerateDummyRho()
		}
		return dummyNf
	}
	return nf
}

// deriveRandomizedKey computes a randomized verification key.
//
// Calls into Rust FFI for actual Pallas curve operations.
// Corresponds to: orchard::keys::SpendAuthorizingKey::randomize in librustzcash
//
// Formula: rk = ak + alpha * G (on Pallas curve)
func deriveRandomizedKey(sk [32]byte, alpha [32]byte) [32]byte {
	rk, err := ffi.OrchardRandomizedKey(sk, alpha)
	if err != nil {
		// Log error but return zero - caller should validate
		return [32]byte{}
	}
	return rk
}
