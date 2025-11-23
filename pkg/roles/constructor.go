package roles

import (
	"crypto/rand"
	"fmt"

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
// The cryptographic operations (note encryption, commitments) are currently
// TODO and will be implemented via Rust FFI to the Orchard crate.
func (c *Constructor) AddOrchardOutput(
	recipient [43]byte,
	value uint64,
	memo [512]byte,
) error {
	// Check if shielded outputs are modifiable
	if c.pczt.Global.TxModifiable&pczt.FlagShieldedModifiable == 0 {
		return fmt.Errorf("shielded outputs not modifiable")
	}

	// Generate random values for the output
	rseed := generateRandomness32()
	rho := generateRandomness32()
	rcv := generateRandomness32()

	// TODO: Implement Orchard cryptographic operations
	// These will be implemented via Rust FFI to the orchard crate
	// For now, these are placeholder implementations

	// Create note commitment (cmx)
	cmx := deriveNoteCommitment(recipient, value, rseed, rho)

	// Generate ephemeral key pair
	esk := generateRandomness32()
	ephemeralKey := deriveEphemeralKey(esk)

	// Encrypt note plaintext
	encCiphertext, outCiphertext := encryptNote(
		recipient,
		value,
		rseed,
		memo,
		esk,
		ephemeralKey,
	)

	// Create dummy spend for the action
	dummySpend := c.createDummySpend(rho)

	// Create output
	output := pczt.OrchardOutput{
		Cmx:           cmx,
		EphemeralKey:  ephemeralKey,
		EncCiphertext: encCiphertext,
		OutCiphertext: outCiphertext,
		Recipient:     &recipient,
		Value:         &value,
		Rseed:         &rseed,
		Proprietary:   make(map[string][]byte),
	}

	// Create action (spend + output)
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

// createDummySpend creates a dummy spend for an output-only action.
//
// In Orchard, every action must have both a spend and an output. When we're
// only creating outputs (transparent -> Orchard), we create "dummy spends"
// that don't actually consume any notes. The dummy spend has:
//   - A synthetic nullifier (derived from randomness)
//   - Zero value
//   - A temporary spending key (will be cleared by IO Finalizer)
func (c *Constructor) createDummySpend(rho [32]byte) pczt.OrchardSpend {
	// Generate dummy spending key (will be used to sign, then cleared)
	dummySk := generateRandomness32()

	// Derive dummy nullifier from rho
	nullifier := deriveNullifier(rho, dummySk)

	// Generate alpha (spend auth randomizer)
	alpha := generateRandomness32()

	// Derive rk (randomized verification key)
	rk := deriveRandomizedKey(dummySk, alpha)

	zeroValue := uint64(0)

	return pczt.OrchardSpend{
		Nullifier:   nullifier,
		Rk:          rk,
		Value:       &zeroValue,
		Rho:         &rho,
		Alpha:       &alpha,
		DummySk:     &dummySk,
		Proprietary: make(map[string][]byte),
	}
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

// deriveNoteCommitment computes the Orchard note commitment.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::note::Note::commitment() in librustzcash
func deriveNoteCommitment(recipient [43]byte, value uint64, rseed [32]byte, rho [32]byte) [32]byte {
	// PLACEHOLDER: Real implementation requires Pallas curve operations
	var cmx [32]byte
	// cmx = OrchardNoteCommitment(recipient, value, rseed, rho)
	return cmx
}

// deriveEphemeralKey derives an ephemeral public key from a secret.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard key agreement on Pallas curve
func deriveEphemeralKey(esk [32]byte) [32]byte {
	// PLACEHOLDER: Real implementation requires Pallas scalar multiplication
	var epk [32]byte
	// epk = esk * G (on Pallas curve)
	return epk
}

// encryptNote encrypts the note plaintext and outgoing ciphertext.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::note_encryption in librustzcash
//
// Returns:
//   - encCiphertext: 580 bytes (encrypted for recipient)
//   - outCiphertext: 80 bytes (encrypted for sender to recover)
func encryptNote(
	recipient [43]byte,
	value uint64,
	rseed [32]byte,
	memo [512]byte,
	esk [32]byte,
	epk [32]byte,
) ([]byte, []byte) {
	// PLACEHOLDER: Real implementation uses ChaCha20Poly1305
	encCiphertext := make([]byte, 580) // 580 bytes for Orchard v5
	outCiphertext := make([]byte, 80)  // 80 bytes for outgoing
	return encCiphertext, outCiphertext
}

// computeValueCommitment computes a Pedersen commitment to the value.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::value::ValueCommitment in librustzcash
//
// Formula: cv = value * V + rcv * R (on Pallas curve)
// where V and R are fixed generators
func computeValueCommitment(value uint64, rcv [32]byte) [32]byte {
	// PLACEHOLDER: Real implementation requires Pallas curve operations
	var cv [32]byte
	return cv
}

// deriveNullifier computes a nullifier from rho and spending key.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::note::Nullifier::derive in librustzcash
func deriveNullifier(rho [32]byte, sk [32]byte) [32]byte {
	// PLACEHOLDER: Real implementation uses Poseidon hash
	var nf [32]byte
	return nf
}

// deriveRandomizedKey computes a randomized verification key.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::keys::SpendAuthorizingKey::randomize in librustzcash
//
// Formula: rk = ak + alpha * G (on Pallas curve)
func deriveRandomizedKey(sk [32]byte, alpha [32]byte) [32]byte {
	// PLACEHOLDER: Real implementation requires Pallas curve operations
	var rk [32]byte
	return rk
}
