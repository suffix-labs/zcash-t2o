package roles

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// TxExtractor extracts a final Zcash transaction from a finalized PCZT.
//
// Corresponds to: pczt::roles::tx_extractor::TxExtractor
//   (librustzcash/pczt/src/roles/tx_extractor/)
//
// The Transaction Extractor role:
//   - Verifies the PCZT is fully finalized and ready for extraction
//   - Serializes the transaction in Zcash v5 format
//   - Creates the Orchard binding signature
//   - Produces the final raw transaction bytes
//
// This is the final role in the PCZT workflow. After extraction, you have
// a complete, signed Zcash transaction ready for broadcast.
type TxExtractor struct {
	pczt *pczt.PCZT
}

// NewTxExtractor creates a new Transaction Extractor.
func NewTxExtractor(p *pczt.PCZT) *TxExtractor {
	return &TxExtractor{pczt: p}
}

// Extract extracts the final transaction bytes.
//
// This performs the following steps:
//   1. Validates that the PCZT is fully finalized
//   2. Creates the Orchard binding signature (if Orchard bundle exists)
//   3. Serializes the transaction in Zcash v5 format
//
// Returns the raw transaction bytes ready for broadcast to the network.
//
// Corresponds to: librustzcash/zcash_primitives/src/transaction/builder.rs
//   and librustzcash/pczt/src/roles/tx_extractor/
func (e *TxExtractor) Extract() ([]byte, error) {
	// Validate PCZT is ready for extraction
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("PCZT validation failed: %w", err)
	}

	// Create Orchard binding signature
	if len(e.pczt.Orchard.Actions) > 0 {
		if err := e.createBindingSignature(); err != nil {
			return nil, fmt.Errorf("failed to create binding signature: %w", err)
		}
	}

	// Serialize transaction
	txBytes, err := e.serializeTransaction()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	return txBytes, nil
}

// validate checks that the PCZT is fully finalized and ready for extraction.
//
// Validation rules:
//   - All transparent inputs must have scriptSig set
//   - Orchard bundle must have ZK proof (if actions exist)
//   - Orchard bundle must have bsk for binding signature
//   - No modification flags should be set (tx is locked)
func (e *TxExtractor) validate() error {
	// Check modification flags are cleared
	if e.pczt.Global.TxModifiable != 0 {
		return fmt.Errorf("transaction still modifiable (flags: 0x%x)", e.pczt.Global.TxModifiable)
	}

	// Validate transparent inputs have scriptSig
	for i, input := range e.pczt.Transparent.Inputs {
		if input.ScriptSig == nil {
			return fmt.Errorf("input %d missing scriptSig (not finalized)", i)
		}
	}

	// Validate Orchard bundle if present
	if len(e.pczt.Orchard.Actions) > 0 {
		if e.pczt.Orchard.ZkProof == nil {
			return fmt.Errorf("Orchard bundle missing ZK proof")
		}
		if e.pczt.Orchard.Bsk == nil {
			return fmt.Errorf("Orchard bundle missing bsk (binding signature key)")
		}
	}

	return nil
}

// createBindingSignature creates the Orchard binding signature.
//
// The binding signature proves that the sum of value commitments equals
// the declared value balance. It's computed as:
//
//   binding_sig = RedPallasSign(bsk, sighash)
//
// where bsk = sum(rcv_i) was computed by the IO Finalizer.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: orchard::bundle::Authorization::binding_signature
//   (librustzcash/orchard/src/bundle.rs)
func (e *TxExtractor) createBindingSignature() error {
	if e.pczt.Orchard.Bsk == nil {
		return fmt.Errorf("cannot create binding signature: bsk not set")
	}

	// Compute sighash for binding signature
	// This is the ZIP 244 transaction hash
	sighash := e.computeBindingSighash()

	// Sign with the binding signature key
	// TODO: Must use Orchard FFI for RedPallas signing
	bindingSig := signBinding(*e.pczt.Orchard.Bsk, sighash)

	e.pczt.Orchard.BindingSig = &bindingSig

	return nil
}

// computeBindingSighash computes the sighash for the binding signature.
//
// This is the same as the ZIP 244 transaction hash used for transparent
// signatures, but without the input-specific context.
//
// TODO: This should reuse the ZIP 244 implementation
func (e *TxExtractor) computeBindingSighash() [32]byte {
	// PLACEHOLDER: Real implementation should use crypto.ComputeZIP244Hash
	var sighash [32]byte
	return sighash
}

// serializeTransaction serializes the transaction in Zcash v5 format.
//
// Zcash v5 transaction format (ZIP 244):
//   - Header (version, version_group_id, consensus_branch_id, lock_time, expiry_height)
//   - Transparent bundle (inputs and outputs)
//   - Sapling bundle (not used in transparent-to-Orchard)
//   - Orchard bundle (actions, flags, value_balance, anchor, proof, binding_sig)
//
// See: https://zips.z.cash/zip-0244
// Corresponds to: librustzcash/zcash_primitives/src/transaction/txid.rs
func (e *TxExtractor) serializeTransaction() ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	e.writeHeader(&buf)

	// Write transparent bundle
	e.writeTransparentBundle(&buf)

	// Write Sapling bundle (empty for Orchard-only)
	e.writeSaplingBundle(&buf)

	// Write Orchard bundle
	if err := e.writeOrchardBundle(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// writeHeader writes the transaction header.
//
// Header format (ZIP 244):
//   - tx_version (4 bytes, little-endian)
//   - version_group_id (4 bytes, little-endian)
//   - consensus_branch_id (4 bytes, little-endian)
//   - lock_time (4 bytes, little-endian)
//   - expiry_height (4 bytes, little-endian)
func (e *TxExtractor) writeHeader(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, e.pczt.Global.TxVersion)
	binary.Write(buf, binary.LittleEndian, e.pczt.Global.VersionGroupID)
	binary.Write(buf, binary.LittleEndian, e.pczt.Global.ConsensusBranchID)

	// Lock time (use fallback if set, otherwise 0)
	lockTime := uint32(0)
	if e.pczt.Global.FallbackLockTime != nil {
		lockTime = *e.pczt.Global.FallbackLockTime
	}
	binary.Write(buf, binary.LittleEndian, lockTime)

	binary.Write(buf, binary.LittleEndian, e.pczt.Global.ExpiryHeight)
}

// writeTransparentBundle writes the transparent inputs and outputs.
//
// Transparent bundle format:
//   - num_inputs (varint)
//   - for each input:
//       - prevout_txid (32 bytes)
//       - prevout_index (4 bytes, little-endian)
//       - scriptSig (varint length + bytes)
//       - sequence (4 bytes, little-endian)
//   - num_outputs (varint)
//   - for each output:
//       - value (8 bytes, little-endian)
//       - scriptPubKey (varint length + bytes)
func (e *TxExtractor) writeTransparentBundle(buf *bytes.Buffer) {
	// Write inputs
	writeCompactSize(buf, uint64(len(e.pczt.Transparent.Inputs)))
	for _, input := range e.pczt.Transparent.Inputs {
		// Prevout
		buf.Write(input.PrevoutTxID[:])
		binary.Write(buf, binary.LittleEndian, input.PrevoutIndex)

		// ScriptSig
		scriptSig := []byte{}
		if input.ScriptSig != nil {
			scriptSig = *input.ScriptSig
		}
		writeCompactSize(buf, uint64(len(scriptSig)))
		buf.Write(scriptSig)

		// Sequence
		sequence := uint32(0xFFFFFFFF)
		if input.Sequence != nil {
			sequence = *input.Sequence
		}
		binary.Write(buf, binary.LittleEndian, sequence)
	}

	// Write outputs
	writeCompactSize(buf, uint64(len(e.pczt.Transparent.Outputs)))
	for _, output := range e.pczt.Transparent.Outputs {
		binary.Write(buf, binary.LittleEndian, output.Value)
		writeCompactSize(buf, uint64(len(output.ScriptPubKey)))
		buf.Write(output.ScriptPubKey)
	}
}

// writeSaplingBundle writes an empty Sapling bundle.
//
// For transparent-to-Orchard transactions, we don't use Sapling.
// Empty bundle format: 0x00 (no spends, no outputs)
func (e *TxExtractor) writeSaplingBundle(buf *bytes.Buffer) {
	// No spends
	writeCompactSize(buf, 0)
	// No outputs
	writeCompactSize(buf, 0)
}

// writeOrchardBundle writes the Orchard shielded bundle.
//
// Orchard bundle format (ZIP 224):
//   - num_actions (varint)
//   - for each action:
//       - cv (32 bytes) - value commitment
//       - nullifier (32 bytes)
//       - rk (32 bytes) - randomized verification key
//       - cmx (32 bytes) - note commitment
//       - ephemeral_key (32 bytes)
//       - enc_ciphertext (580 bytes)
//       - out_ciphertext (80 bytes)
//   - flags (1 byte)
//   - value_balance (8 bytes, signed little-endian)
//   - anchor (32 bytes)
//   - for each action:
//       - spend_auth_sig (64 bytes) - RedPallas signature
//   - zkproof (variable length)
//   - binding_sig (64 bytes) - RedPallas signature
func (e *TxExtractor) writeOrchardBundle(buf *bytes.Buffer) error {
	numActions := len(e.pczt.Orchard.Actions)

	// If no actions, write empty bundle marker
	if numActions == 0 {
		writeCompactSize(buf, 0)
		return nil
	}

	// Write number of actions
	writeCompactSize(buf, uint64(numActions))

	// Write action data (spend + output for each)
	for _, action := range e.pczt.Orchard.Actions {
		// cv (value commitment net)
		buf.Write(action.CvNet[:])

		// nullifier
		buf.Write(action.Spend.Nullifier[:])

		// rk (randomized verification key)
		buf.Write(action.Spend.Rk[:])

		// cmx (note commitment)
		buf.Write(action.Output.Cmx[:])

		// ephemeral_key
		buf.Write(action.Output.EphemeralKey[:])

		// enc_ciphertext (580 bytes)
		if len(action.Output.EncCiphertext) != 580 {
			return fmt.Errorf("invalid enc_ciphertext length: %d (expected 580)",
				len(action.Output.EncCiphertext))
		}
		buf.Write(action.Output.EncCiphertext)

		// out_ciphertext (80 bytes)
		if len(action.Output.OutCiphertext) != 80 {
			return fmt.Errorf("invalid out_ciphertext length: %d (expected 80)",
				len(action.Output.OutCiphertext))
		}
		buf.Write(action.Output.OutCiphertext)
	}

	// Flags
	buf.WriteByte(e.pczt.Orchard.Flags)

	// Value balance (signed 64-bit little-endian)
	valueBalance := int64(e.pczt.Orchard.ValueSum.Magnitude)
	if e.pczt.Orchard.ValueSum.IsNegative {
		valueBalance = -valueBalance
	}
	binary.Write(buf, binary.LittleEndian, valueBalance)

	// Anchor
	buf.Write(e.pczt.Orchard.Anchor[:])

	// Spend authorization signatures
	for _, action := range e.pczt.Orchard.Actions {
		if action.Spend.SpendAuthSig == nil {
			return fmt.Errorf("action missing spend_auth_sig")
		}
		buf.Write((*action.Spend.SpendAuthSig)[:])
	}

	// ZK proof
	if e.pczt.Orchard.ZkProof == nil {
		return fmt.Errorf("Orchard bundle missing ZK proof")
	}
	writeCompactSize(buf, uint64(len(*e.pczt.Orchard.ZkProof)))
	buf.Write(*e.pczt.Orchard.ZkProof)

	// Binding signature
	if e.pczt.Orchard.BindingSig == nil {
		return fmt.Errorf("Orchard bundle missing binding signature")
	}
	buf.Write((*e.pczt.Orchard.BindingSig)[:])

	return nil
}

// ============================================================================
// Cryptographic helper functions
//
// TODO: These are placeholder implementations. In production, these MUST
// call into the Orchard Rust crate via FFI.
// ============================================================================

// signBinding creates a RedPallas binding signature.
//
// TODO: Must be implemented via Orchard FFI
// Corresponds to: reddsa::orchard::Binding::sign in librustzcash
//
// The binding signature proves the value balance is correct:
//   sum(value_commitments) = value_balance * V + bsk * R
//
// Parameters:
//   - bsk: Binding signature key (sum of all rcv values)
//   - sighash: Transaction hash to sign
//
// Returns: 64-byte RedPallas signature
func signBinding(bsk [32]byte, sighash [32]byte) [64]byte {
	// PLACEHOLDER: Real implementation uses RedPallas signing
	var sig [64]byte
	// sig = RedPallasSign(bsk, sighash)
	return sig
}

// ============================================================================
// Bitcoin-style CompactSize encoding
//
// CompactSize is a variable-length encoding for unsigned integers used in
// Bitcoin and Zcash for length prefixes.
//
// See: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
// ============================================================================

// writeCompactSize writes a CompactSize-encoded integer.
//
// Encoding:
//   - < 0xFD: 1 byte (the value itself)
//   - >= 0xFD and <= 0xFFFF: 0xFD + 2 bytes little-endian
//   - >= 0x10000 and <= 0xFFFFFFFF: 0xFE + 4 bytes little-endian
//   - >= 0x100000000: 0xFF + 8 bytes little-endian
func writeCompactSize(buf *bytes.Buffer, n uint64) {
	if n < 0xFD {
		buf.WriteByte(byte(n))
	} else if n <= 0xFFFF {
		buf.WriteByte(0xFD)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	} else if n <= 0xFFFFFFFF {
		buf.WriteByte(0xFE)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	} else {
		buf.WriteByte(0xFF)
		binary.Write(buf, binary.LittleEndian, n)
	}
}
