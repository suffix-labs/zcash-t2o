// Package crypto implements ZIP-244 signature hash computation.
//
// This file provides V5 transaction parsing for test vector validation.
// It parses raw transaction bytes into a structured format that can be
// converted to PCZT for signature hash computation.
//
// Reference: ZIP-225 (Version 5 Transaction Format)
// https://zips.z.cash/zip-0225
package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// ParsedV5Tx represents a parsed V5 transaction.
// This is an intermediate format used to bridge raw transaction bytes
// to the PCZT format needed for signature hash computation.
type ParsedV5Tx struct {
	// Header fields
	Version           int32
	VersionGroupID    uint32
	ConsensusBranchID uint32
	LockTime          uint32
	ExpiryHeight      uint32

	// Transparent bundle
	TransparentInputs  []ParsedTxIn
	TransparentOutputs []ParsedTxOut

	// Sapling bundle (parsed for digest computation)
	SaplingSpends  []SaplingSpend
	SaplingOutputs []SaplingOutput
	SaplingValue   int64
	SaplingAnchor  [32]byte

	// Orchard bundle
	OrchardActions     []OrchardAction
	OrchardFlags       uint8
	OrchardValueBalance int64
	OrchardAnchor      [32]byte
	OrchardProof       []byte
	OrchardBindingSig  [64]byte
}

// ParsedTxIn represents a transparent input from raw transaction bytes.
type ParsedTxIn struct {
	PrevoutTxID  [32]byte
	PrevoutIndex uint32
	ScriptSig    []byte
	Sequence     uint32
}

// ParsedTxOut represents a transparent output from raw transaction bytes.
type ParsedTxOut struct {
	Value        uint64
	ScriptPubKey []byte
}

// SaplingSpend represents a Sapling spend for digest computation.
// Note: In V5 format, the anchor is stored once at the bundle level, not per-spend.
type SaplingSpend struct {
	CV           [32]byte   // cv (value commitment)
	Nullifier    [32]byte   // nullifier
	Rk           [32]byte   // rk (randomized verification key)
	Proof        [192]byte  // zkproof (read separately after outputs)
	SpendAuthSig [64]byte   // spend_auth_sig (read separately)
}

// SaplingOutput represents a Sapling output for digest computation.
type SaplingOutput struct {
	CV            [32]byte    // cv (value commitment)
	Cmu           [32]byte    // cmu (note commitment)
	EphemeralKey  [32]byte    // ephemeral_key
	EncCiphertext [580]byte   // enc_ciphertext
	OutCiphertext [80]byte    // out_ciphertext
	Proof         [192]byte   // zkproof (read separately)
}

// OrchardAction represents an Orchard action from raw transaction bytes.
type OrchardAction struct {
	CV           [32]byte
	Nullifier    [32]byte
	Rk           [32]byte
	Cmx          [32]byte
	EphemeralKey [32]byte
	EncCiphertext [580]byte
	OutCiphertext [80]byte
	SpendAuthSig [64]byte
}

// ParseV5Transaction parses raw V5 transaction bytes into a structured format.
// Returns an error if the transaction is not a valid v5 format.
func ParseV5Transaction(data []byte) (*ParsedV5Tx, error) {
	r := bytes.NewReader(data)
	tx := &ParsedV5Tx{}

	// Read header
	if err := binary.Read(r, binary.LittleEndian, &tx.Version); err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}

	// Check version (v5 has version with overwintered flag)
	// The version field is int32, with bit 31 = overwintered flag
	if tx.Version>>31 == 0 {
		return nil, fmt.Errorf("not an overwintered transaction (version=%d)", tx.Version)
	}
	versionNum := tx.Version & 0x7FFFFFFF
	if versionNum != 5 {
		return nil, fmt.Errorf("not a v5 transaction (version=%d)", versionNum)
	}

	if err := binary.Read(r, binary.LittleEndian, &tx.VersionGroupID); err != nil {
		return nil, fmt.Errorf("reading version_group_id: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &tx.ConsensusBranchID); err != nil {
		return nil, fmt.Errorf("reading consensus_branch_id: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &tx.LockTime); err != nil {
		return nil, fmt.Errorf("reading lock_time: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &tx.ExpiryHeight); err != nil {
		return nil, fmt.Errorf("reading expiry_height: %w", err)
	}

	// Read transparent bundle
	if err := parseTransparentBundle(r, tx); err != nil {
		return nil, fmt.Errorf("parsing transparent bundle: %w", err)
	}

	// Read Sapling bundle
	if err := parseSaplingBundle(r, tx); err != nil {
		return nil, fmt.Errorf("parsing sapling bundle: %w", err)
	}

	// Read Orchard bundle
	if err := parseOrchardBundle(r, tx); err != nil {
		return nil, fmt.Errorf("parsing orchard bundle: %w", err)
	}

	return tx, nil
}

// parseTransparentBundle reads the transparent inputs and outputs.
func parseTransparentBundle(r io.Reader, tx *ParsedV5Tx) error {
	// Read number of inputs
	numInputs, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading input count: %w", err)
	}

	// Read inputs
	tx.TransparentInputs = make([]ParsedTxIn, numInputs)
	for i := uint64(0); i < numInputs; i++ {
		if err := parseTxIn(r, &tx.TransparentInputs[i]); err != nil {
			return fmt.Errorf("parsing input %d: %w", i, err)
		}
	}

	// Read number of outputs
	numOutputs, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading output count: %w", err)
	}

	// Read outputs
	tx.TransparentOutputs = make([]ParsedTxOut, numOutputs)
	for i := uint64(0); i < numOutputs; i++ {
		if err := parseTxOut(r, &tx.TransparentOutputs[i]); err != nil {
			return fmt.Errorf("parsing output %d: %w", i, err)
		}
	}

	return nil
}

// parseTxIn reads a single transparent input.
func parseTxIn(r io.Reader, txin *ParsedTxIn) error {
	// Previous outpoint (txid + index)
	if _, err := io.ReadFull(r, txin.PrevoutTxID[:]); err != nil {
		return fmt.Errorf("reading prevout txid: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &txin.PrevoutIndex); err != nil {
		return fmt.Errorf("reading prevout index: %w", err)
	}

	// ScriptSig (variable length)
	scriptLen, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading scriptSig length: %w", err)
	}
	txin.ScriptSig = make([]byte, scriptLen)
	if _, err := io.ReadFull(r, txin.ScriptSig); err != nil {
		return fmt.Errorf("reading scriptSig: %w", err)
	}

	// Sequence
	if err := binary.Read(r, binary.LittleEndian, &txin.Sequence); err != nil {
		return fmt.Errorf("reading sequence: %w", err)
	}

	return nil
}

// parseTxOut reads a single transparent output.
func parseTxOut(r io.Reader, txout *ParsedTxOut) error {
	// Value (8 bytes)
	if err := binary.Read(r, binary.LittleEndian, &txout.Value); err != nil {
		return fmt.Errorf("reading value: %w", err)
	}

	// ScriptPubKey (variable length)
	scriptLen, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading scriptPubKey length: %w", err)
	}
	txout.ScriptPubKey = make([]byte, scriptLen)
	if _, err := io.ReadFull(r, txout.ScriptPubKey); err != nil {
		return fmt.Errorf("reading scriptPubKey: %w", err)
	}

	return nil
}

// parseSaplingBundle reads the Sapling spends and outputs in V5 format.
// V5 format differs from V4:
// - Spends are compact: cv (32) | nullifier (32) | rk (32)
// - No per-spend anchor; anchor is shared once if any spends exist
// - Proofs and signatures are read after all descriptors
func parseSaplingBundle(r io.Reader, tx *ParsedV5Tx) error {
	// Read number of Sapling spends
	numSpends, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading spend count: %w", err)
	}

	// Read Sapling spend descriptors (without proofs/sigs)
	// V5 format: cv (32) | nullifier (32) | rk (32)
	if numSpends > 0 {
		tx.SaplingSpends = make([]SaplingSpend, numSpends)
		for i := uint64(0); i < numSpends; i++ {
			spend := &tx.SaplingSpends[i]
			if _, err := io.ReadFull(r, spend.CV[:]); err != nil {
				return fmt.Errorf("reading spend cv: %w", err)
			}
			if _, err := io.ReadFull(r, spend.Nullifier[:]); err != nil {
				return fmt.Errorf("reading spend nullifier: %w", err)
			}
			if _, err := io.ReadFull(r, spend.Rk[:]); err != nil {
				return fmt.Errorf("reading spend rk: %w", err)
			}
		}
	}

	// Read number of Sapling outputs
	numOutputs, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading output count: %w", err)
	}

	// Read Sapling output descriptors (without proofs)
	// V5 format: cv (32) | cmu (32) | ephemeral_key (32) | enc_ciphertext (580) | out_ciphertext (80)
	if numOutputs > 0 {
		tx.SaplingOutputs = make([]SaplingOutput, numOutputs)
		for i := uint64(0); i < numOutputs; i++ {
			out := &tx.SaplingOutputs[i]
			if _, err := io.ReadFull(r, out.CV[:]); err != nil {
				return fmt.Errorf("reading output cv: %w", err)
			}
			if _, err := io.ReadFull(r, out.Cmu[:]); err != nil {
				return fmt.Errorf("reading output cmu: %w", err)
			}
			if _, err := io.ReadFull(r, out.EphemeralKey[:]); err != nil {
				return fmt.Errorf("reading output ephemeral key: %w", err)
			}
			if _, err := io.ReadFull(r, out.EncCiphertext[:]); err != nil {
				return fmt.Errorf("reading output enc ciphertext: %w", err)
			}
			if _, err := io.ReadFull(r, out.OutCiphertext[:]); err != nil {
				return fmt.Errorf("reading output out ciphertext: %w", err)
			}
		}
	}

	// If we have any Sapling components, read the remaining bundle data
	if numSpends > 0 || numOutputs > 0 {
		// Value balance (int64)
		if err := binary.Read(r, binary.LittleEndian, &tx.SaplingValue); err != nil {
			return fmt.Errorf("reading sapling value balance: %w", err)
		}

		// Read anchor only if we have spends (shared anchor for all spends in V5)
		if numSpends > 0 {
			if _, err := io.ReadFull(r, tx.SaplingAnchor[:]); err != nil {
				return fmt.Errorf("reading sapling anchor: %w", err)
			}
		}

		// Read spend proofs (192 bytes each)
		for i := uint64(0); i < numSpends; i++ {
			if _, err := io.ReadFull(r, tx.SaplingSpends[i].Proof[:]); err != nil {
				return fmt.Errorf("reading spend proof: %w", err)
			}
		}

		// Read spend auth sigs (64 bytes each)
		for i := uint64(0); i < numSpends; i++ {
			if _, err := io.ReadFull(r, tx.SaplingSpends[i].SpendAuthSig[:]); err != nil {
				return fmt.Errorf("reading spend auth sig: %w", err)
			}
		}

		// Read output proofs (192 bytes each)
		for i := uint64(0); i < numOutputs; i++ {
			if _, err := io.ReadFull(r, tx.SaplingOutputs[i].Proof[:]); err != nil {
				return fmt.Errorf("reading output proof: %w", err)
			}
		}

		// Read binding signature (64 bytes)
		var bindingSig [64]byte
		if _, err := io.ReadFull(r, bindingSig[:]); err != nil {
			return fmt.Errorf("reading sapling binding sig: %w", err)
		}
	}

	return nil
}

// parseOrchardBundle reads the Orchard actions.
func parseOrchardBundle(r io.Reader, tx *ParsedV5Tx) error {
	// Read number of Orchard actions
	numActions, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading action count: %w", err)
	}

	if numActions == 0 {
		return nil
	}

	// Read actions
	tx.OrchardActions = make([]OrchardAction, numActions)
	for i := uint64(0); i < numActions; i++ {
		action := &tx.OrchardActions[i]

		// cv_net (32)
		if _, err := io.ReadFull(r, action.CV[:]); err != nil {
			return fmt.Errorf("reading action cv: %w", err)
		}
		// nullifier (32)
		if _, err := io.ReadFull(r, action.Nullifier[:]); err != nil {
			return fmt.Errorf("reading action nullifier: %w", err)
		}
		// rk (32)
		if _, err := io.ReadFull(r, action.Rk[:]); err != nil {
			return fmt.Errorf("reading action rk: %w", err)
		}
		// cmx (32)
		if _, err := io.ReadFull(r, action.Cmx[:]); err != nil {
			return fmt.Errorf("reading action cmx: %w", err)
		}
		// ephemeral_key (32)
		if _, err := io.ReadFull(r, action.EphemeralKey[:]); err != nil {
			return fmt.Errorf("reading action ephemeral key: %w", err)
		}
		// enc_ciphertext (580)
		if _, err := io.ReadFull(r, action.EncCiphertext[:]); err != nil {
			return fmt.Errorf("reading action enc ciphertext: %w", err)
		}
		// out_ciphertext (80)
		if _, err := io.ReadFull(r, action.OutCiphertext[:]); err != nil {
			return fmt.Errorf("reading action out ciphertext: %w", err)
		}
	}

	// Flags (1 byte)
	var flags [1]byte
	if _, err := io.ReadFull(r, flags[:]); err != nil {
		return fmt.Errorf("reading orchard flags: %w", err)
	}
	tx.OrchardFlags = flags[0]

	// Value balance (8 bytes, signed)
	if err := binary.Read(r, binary.LittleEndian, &tx.OrchardValueBalance); err != nil {
		return fmt.Errorf("reading orchard value balance: %w", err)
	}

	// Anchor (32 bytes)
	if _, err := io.ReadFull(r, tx.OrchardAnchor[:]); err != nil {
		return fmt.Errorf("reading orchard anchor: %w", err)
	}

	// Proof (variable length)
	proofLen, err := readCompactSize(r)
	if err != nil {
		return fmt.Errorf("reading proof length: %w", err)
	}
	tx.OrchardProof = make([]byte, proofLen)
	if _, err := io.ReadFull(r, tx.OrchardProof); err != nil {
		return fmt.Errorf("reading proof: %w", err)
	}

	// Spend auth sigs for each action
	for i := uint64(0); i < numActions; i++ {
		if _, err := io.ReadFull(r, tx.OrchardActions[i].SpendAuthSig[:]); err != nil {
			return fmt.Errorf("reading action spend auth sig: %w", err)
		}
	}

	// Binding signature (64 bytes)
	if _, err := io.ReadFull(r, tx.OrchardBindingSig[:]); err != nil {
		return fmt.Errorf("reading orchard binding sig: %w", err)
	}

	return nil
}

// readCompactSize reads a Bitcoin-style variable-length integer.
func readCompactSize(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}

	switch first[0] {
	case 253:
		var v uint16
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		return uint64(v), nil
	case 254:
		var v uint32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		return uint64(v), nil
	case 255:
		var v uint64
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		return v, nil
	default:
		return uint64(first[0]), nil
	}
}

// TxToPCZT converts a parsed V5 transaction to PCZT format.
// The amounts and scriptPubkeys parameters provide the input UTXO data
// that is not included in the transaction itself but is needed for signing.
func TxToPCZT(tx *ParsedV5Tx, amounts []int64, scriptPubkeys [][]byte) *pczt.PCZT {
	p := &pczt.PCZT{
		Global: pczt.Global{
			TxVersion:         uint32(tx.Version & 0x7FFFFFFF),
			VersionGroupID:    tx.VersionGroupID,
			ConsensusBranchID: tx.ConsensusBranchID,
			ExpiryHeight:      tx.ExpiryHeight,
		},
	}

	// Set lock time
	if tx.LockTime != 0 {
		p.Global.FallbackLockTime = &tx.LockTime
	}

	// Convert transparent inputs
	p.Transparent.Inputs = make([]pczt.TransparentInput, len(tx.TransparentInputs))
	for i, txin := range tx.TransparentInputs {
		p.Transparent.Inputs[i] = pczt.TransparentInput{
			PrevoutTxID:  txin.PrevoutTxID,
			PrevoutIndex: txin.PrevoutIndex,
			ScriptSig:    txin.ScriptSig,
		}
		// Set sequence if not default
		seq := txin.Sequence
		p.Transparent.Inputs[i].Sequence = &seq

		// Set value and scriptPubKey from external data
		if i < len(amounts) {
			p.Transparent.Inputs[i].Value = uint64(amounts[i])
		}
		if i < len(scriptPubkeys) {
			p.Transparent.Inputs[i].ScriptPubKey = scriptPubkeys[i]
		}
	}

	// Convert transparent outputs
	p.Transparent.Outputs = make([]pczt.TransparentOutput, len(tx.TransparentOutputs))
	for i, txout := range tx.TransparentOutputs {
		p.Transparent.Outputs[i] = pczt.TransparentOutput{
			Value:        txout.Value,
			ScriptPubKey: txout.ScriptPubKey,
		}
	}

	// Convert Orchard bundle
	if len(tx.OrchardActions) > 0 {
		p.Orchard.Flags = tx.OrchardFlags
		p.Orchard.Anchor = tx.OrchardAnchor
		p.Orchard.ZkProof = tx.OrchardProof

		// Value balance
		if tx.OrchardValueBalance >= 0 {
			p.Orchard.ValueSum.Magnitude = uint64(tx.OrchardValueBalance)
			p.Orchard.ValueSum.IsNegative = false
		} else {
			p.Orchard.ValueSum.Magnitude = uint64(-tx.OrchardValueBalance)
			p.Orchard.ValueSum.IsNegative = true
		}

		// Binding signature
		bindingSig := tx.OrchardBindingSig
		p.Orchard.BindingSig = &bindingSig

		// Convert actions
		p.Orchard.Actions = make([]pczt.OrchardAction, len(tx.OrchardActions))
		for i, action := range tx.OrchardActions {
			spendAuthSig := action.SpendAuthSig
			p.Orchard.Actions[i] = pczt.OrchardAction{
				CvNet: action.CV,
				Spend: pczt.OrchardSpend{
					Nullifier:    action.Nullifier,
					Rk:           action.Rk,
					SpendAuthSig: &spendAuthSig,
				},
				Output: pczt.OrchardOutput{
					Cmx:           action.Cmx,
					EphemeralKey:  action.EphemeralKey,
					EncCiphertext: action.EncCiphertext[:],
					OutCiphertext: action.OutCiphertext[:],
				},
			}
		}
	}

	return p
}

// ComputeTxID computes the transaction ID according to ZIP-244.
// Returns the 32-byte transaction ID.
// Note: This uses PCZT which doesn't fully support Sapling.
// For full Sapling support, use ComputeTxIDFromParsed.
func ComputeTxID(p *pczt.PCZT) ([32]byte, error) {
	digests, err := ComputeTxDigests(p)
	if err != nil {
		return [32]byte{}, err
	}

	// TXID = BLAKE2b-256("ZcashTxHash_" || branch_id, header || transparent || sapling || orchard)
	personalization := make([]byte, 16)
	copy(personalization, []byte(Zip244HashPersonalization))
	binary.LittleEndian.PutUint32(personalization[12:], p.Global.ConsensusBranchID)

	h, _ := blake2bNew256(personalization)
	h.Write(digests.HeaderDigest[:])
	h.Write(digests.TransparentDigest[:])
	h.Write(digests.SaplingDigest[:])
	h.Write(digests.OrchardDigest[:])

	var txid [32]byte
	copy(txid[:], h.Sum(nil))
	return txid, nil
}

// ComputeTxIDFromParsed computes the transaction ID from a parsed V5 transaction.
// This properly handles Sapling data that isn't available through PCZT.
func ComputeTxIDFromParsed(tx *ParsedV5Tx) ([32]byte, error) {
	// Convert to PCZT for the parts it supports
	pcztTx := TxToPCZT(tx, nil, nil)

	// Compute header digest
	headerDigest, err := computeHeaderDigest(pcztTx)
	if err != nil {
		return [32]byte{}, err
	}

	// Compute transparent digest
	transparentDigest, err := computeTransparentDigest(pcztTx)
	if err != nil {
		return [32]byte{}, err
	}

	// Compute Sapling digest from parsed data
	saplingData := parsedTxToSaplingDigestData(tx)
	saplingDigest := ComputeSaplingDigestWithData(saplingData)

	// Compute Orchard digest
	orchardDigest, err := computeOrchardDigest(pcztTx)
	if err != nil {
		return [32]byte{}, err
	}

	// TXID = BLAKE2b-256("ZcashTxHash_" || branch_id, header || transparent || sapling || orchard)
	personalization := make([]byte, 16)
	copy(personalization, []byte(Zip244HashPersonalization))
	binary.LittleEndian.PutUint32(personalization[12:], tx.ConsensusBranchID)

	h, _ := blake2bNew256(personalization)
	h.Write(headerDigest[:])
	h.Write(transparentDigest[:])
	h.Write(saplingDigest[:])
	h.Write(orchardDigest[:])

	var txid [32]byte
	copy(txid[:], h.Sum(nil))
	return txid, nil
}

// parsedTxToSaplingDigestData converts parsed Sapling data to digest format
func parsedTxToSaplingDigestData(tx *ParsedV5Tx) *SaplingDigestData {
	if len(tx.SaplingSpends) == 0 && len(tx.SaplingOutputs) == 0 {
		return nil
	}

	data := &SaplingDigestData{
		ValueBalance: tx.SaplingValue,
	}

	// Convert spends
	for _, spend := range tx.SaplingSpends {
		data.Spends = append(data.Spends, SaplingSpendData{
			CV:        spend.CV,
			Anchor:    tx.SaplingAnchor, // V5 uses shared anchor
			Nullifier: spend.Nullifier,
			Rk:        spend.Rk,
		})
	}

	// Convert outputs
	for _, out := range tx.SaplingOutputs {
		data.Outputs = append(data.Outputs, SaplingOutputData{
			CV:            out.CV,
			Cmu:           out.Cmu,
			EphemeralKey:  out.EphemeralKey,
			EncCiphertext: out.EncCiphertext,
			OutCiphertext: out.OutCiphertext,
		})
	}

	return data
}

// GetShieldedSignatureHash computes the signature hash for shielded inputs.
// This is used for Sapling and Orchard spend authorization signatures.
// For shielded inputs, we compute transparent_sig_digest with txin=nil,
// meaning txin_sig_digest returns the empty hash (just personalization).
func GetShieldedSignatureHash(p *pczt.PCZT) ([32]byte, error) {
	digests, err := ComputeTxDigests(p)
	if err != nil {
		return [32]byte{}, err
	}

	// For shielded, compute transparent_sig_digest with no specific input
	// If no transparent inputs, this returns transparent_digest (T.2)
	// Otherwise, it computes the full sig digest but with empty txin_sig_digest
	transparentSigDigest := computeShieldedTransparentSigDigest(p)

	// Personalization includes branch ID
	personalization := make([]byte, 16)
	copy(personalization, []byte(Zip244HashPersonalization))
	binary.LittleEndian.PutUint32(personalization[12:], p.Global.ConsensusBranchID)

	h, _ := blake2bNew256(personalization)
	h.Write(digests.HeaderDigest[:])
	h.Write(transparentSigDigest[:])
	h.Write(digests.SaplingDigest[:])
	h.Write(digests.OrchardDigest[:])

	var sighash [32]byte
	copy(sighash[:], h.Sum(nil))
	return sighash, nil
}

// computeShieldedTransparentSigDigest computes the transparent sig digest for shielded inputs.
// If coinbase or no transparent inputs, returns transparent_digest (T.2).
// Otherwise computes the full sig digest with empty txin_sig_digest.
func computeShieldedTransparentSigDigest(p *pczt.PCZT) [32]byte {
	// If coinbase or no transparent inputs, return the transparent_digest (T.2)
	// A coinbase transaction has one input with prevout_txid = 32 zero bytes and prevout_index = 0xffffffff
	if len(p.Transparent.Inputs) == 0 || isCoinbase(p) {
		digest, _ := computeTransparentDigest(p)
		return digest
	}

	// Otherwise compute the full sig digest with SIGHASH_ALL but no specific input
	h, _ := blake2bNew256([]byte(TransparentDigestPersonalization))

	// hash_type = SIGHASH_ALL
	h.Write([]byte{pczt.SighashAll})

	// prevouts_sig_digest (all inputs)
	prevoutsDigest := computePrevoutsSigDigest(p.Transparent.Inputs, false)
	h.Write(prevoutsDigest[:])

	// amounts_sig_digest (all inputs)
	amountsDigest := computeAmountsSigDigest(p.Transparent.Inputs, false)
	h.Write(amountsDigest[:])

	// scriptpubkeys_sig_digest (all inputs)
	scriptsDigest := computeScriptsSigDigest(p.Transparent.Inputs, false)
	h.Write(scriptsDigest[:])

	// sequence_sig_digest (all inputs)
	sequenceDigest := computeSequenceSigDigest(p.Transparent.Inputs, false)
	h.Write(sequenceDigest[:])

	// outputs_sig_digest (all outputs for SIGHASH_ALL)
	outputsDigest := computeOutputsSigDigest(p.Transparent.Outputs, pczt.SighashAll, 0)
	h.Write(outputsDigest[:])

	// txin_sig_digest is EMPTY for shielded (just personalization hash)
	emptyTxinDigest := computeEmptyTxInSigDigest()
	h.Write(emptyTxinDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// computeEmptyTxInSigDigest returns the empty txin digest (just personalization)
func computeEmptyTxInSigDigest() [32]byte {
	h, _ := blake2bNew256([]byte(TxInDigestPersonalization))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// isCoinbase returns true if the transaction is a coinbase transaction.
// A coinbase transaction has exactly one transparent input with:
// - prevout_txid = 32 zero bytes
// - prevout_index = 0xffffffff
func isCoinbase(p *pczt.PCZT) bool {
	if len(p.Transparent.Inputs) != 1 {
		return false
	}
	input := p.Transparent.Inputs[0]
	// Check if prevout is all zeros
	for _, b := range input.PrevoutTxID {
		if b != 0 {
			return false
		}
	}
	// Check if prevout_index is 0xffffffff
	return input.PrevoutIndex == 0xffffffff
}

// blake2bNew256 is defined in zip244.go and uses github.com/minio/blake2b-simd
// for proper personalization support.
