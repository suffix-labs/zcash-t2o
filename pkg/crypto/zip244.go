// Package crypto implements ZIP 244 signature hash computation.
//
// ZIP 244 defines the v5 transaction digest algorithm used for signing Zcash
// transactions. It replaces the previous ZIP 143 algorithm used in v4.
//
// This implementation corresponds to:
//   - librustzcash/zcash_primitives/src/transaction/sighash_v5.rs
//   - librustzcash/zcash_primitives/src/transaction/txid.rs
//   - zcash-test-vectors/zcash_test_vectors/zip_0244.py
//
// References:
//   - ZIP 244: https://zips.z.cash/zip-0244
//   - The signature hash is computed by hashing together 4 digests:
//     1. Header digest (version, lock time, expiry)
//     2. Transparent digest (prevouts, sequences, outputs)
//     3. Sapling digest (spends, outputs, value balance)
//     4. Orchard digest (actions, value balance, anchor)
package crypto

import (
	"bytes"
	"encoding/binary"
	"hash"
	"io"

	blake2b "github.com/minio/blake2b-simd"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// blake2bNew256 creates a new BLAKE2b-256 hash with the given personalization.
// This is the correct way to use BLAKE2b for ZIP 244 - the personalization is
// NOT a key, but a distinct parameter that modifies the hash function.
func blake2bNew256(personalization []byte) (hash.Hash, error) {
	config := &blake2b.Config{
		Size:   32,
		Person: personalization,
	}
	return blake2b.New(config)
}

// ZIP 244 constants - personalization strings for BLAKE2b hashing
const (
	// Transaction ID personalization (12 bytes prefix + 4 bytes branch ID)
	Zip244HashPersonalization = "ZcashTxHash_"

	// Component digest personalizations (all 16 bytes)
	HeaderDigestPersonalization      = "ZTxIdHeadersHash"
	TransparentDigestPersonalization = "ZTxIdTranspaHash"
	SaplingDigestPersonalization     = "ZTxIdSaplingHash"
	OrchardDigestPersonalization     = "ZTxIdOrchardHash"

	// Transparent sub-digests
	PrevoutDigestPersonalization  = "ZTxIdPrevoutHash"
	SequenceDigestPersonalization = "ZTxIdSequencHash"
	OutputsDigestPersonalization  = "ZTxIdOutputsHash"

	// Transparent signature digests (for amounts and scripts)
	AmountsDigestPersonalization = "ZTxTrAmountsHash"
	ScriptsDigestPersonalization = "ZTxTrScriptsHash"
	TxInDigestPersonalization    = "Zcash___TxInHash"

	// Sapling sub-digests
	SaplingSpendsDigestPersonalization          = "ZTxIdSSpendsHash"
	SaplingSpendsCompactPersonalization         = "ZTxIdSSpendCHash"
	SaplingSpendsNoncompactPersonalization      = "ZTxIdSSpendNHash"
	SaplingOutputsDigestPersonalization         = "ZTxIdSOutputHash"
	SaplingOutputsCompactPersonalization        = "ZTxIdSOutC__Hash"
	SaplingOutputsMemosPersonalization          = "ZTxIdSOutM__Hash"
	SaplingOutputsNoncompactPersonalization     = "ZTxIdSOutN__Hash"

	// Orchard sub-digests
	OrchardActionsCompactPersonalization    = "ZTxIdOrcActCHash"
	OrchardActionsMemosPersonalization      = "ZTxIdOrcActMHash"
	OrchardActionsNoncompactPersonalization = "ZTxIdOrcActNHash"
)

// TxDigests contains all transaction digests for ZIP 244
type TxDigests struct {
	HeaderDigest      [32]byte
	TransparentDigest [32]byte
	SaplingDigest     [32]byte
	OrchardDigest     [32]byte
}

// ComputeTxDigests computes all digests for a transaction
func ComputeTxDigests(p *pczt.PCZT) (*TxDigests, error) {
	digests := &TxDigests{}

	// Compute header digest
	var err error
	digests.HeaderDigest, err = computeHeaderDigest(p)
	if err != nil {
		return nil, err
	}

	// Compute transparent digest
	digests.TransparentDigest, err = computeTransparentDigest(p)
	if err != nil {
		return nil, err
	}

	// Sapling digest
	digests.SaplingDigest, err = computeSaplingDigest(p)
	if err != nil {
		return nil, err
	}

	// Orchard digest
	digests.OrchardDigest, err = computeOrchardDigest(p)
	if err != nil {
		return nil, err
	}

	return digests, nil
}

// computeHeaderDigest computes the header digest (T.1)
// T.1: header_digest = BLAKE2b-256("ZTxIdHeadersHash", header)
func computeHeaderDigest(p *pczt.PCZT) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(HeaderDigestPersonalization))

	buf := new(bytes.Buffer)

	// Serialize header fields:
	// version (4) || version_group_id (4) || consensus_branch_id (4) ||
	// lock_time (4) || expiry_height (4)

	// Version with overwintered flag (bit 31 set)
	version := p.Global.TxVersion | (1 << 31)
	binary.Write(buf, binary.LittleEndian, version)
	binary.Write(buf, binary.LittleEndian, p.Global.VersionGroupID)
	binary.Write(buf, binary.LittleEndian, p.Global.ConsensusBranchID)

	lockTime := uint32(0)
	if p.Global.FallbackLockTime != nil {
		lockTime = *p.Global.FallbackLockTime
	}
	binary.Write(buf, binary.LittleEndian, lockTime)
	binary.Write(buf, binary.LittleEndian, p.Global.ExpiryHeight)

	h.Write(buf.Bytes())

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// computeTransparentDigest computes the transparent digest (T.2)
// T.2a: prevouts_digest = BLAKE2b-256("ZTxIdPrevoutHash", prevouts)
// T.2b: sequence_digest = BLAKE2b-256("ZTxIdSequencHash", sequences)
// T.2c: outputs_digest = BLAKE2b-256("ZTxIdOutputsHash", outputs)
// T.2: transparent_digest = BLAKE2b-256("ZTxIdTranspaHash", T.2a || T.2b || T.2c)
func computeTransparentDigest(p *pczt.PCZT) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(TransparentDigestPersonalization))

	// If no transparent inputs/outputs, return empty hash with personalization
	if len(p.Transparent.Inputs) == 0 && len(p.Transparent.Outputs) == 0 {
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest, nil
	}

	// T.2a: prevouts_digest
	prevoutsDigest, _ := computePrevoutsDigest(p.Transparent.Inputs)

	// T.2b: sequence_digest
	sequenceDigest, _ := computeSequenceDigest(p.Transparent.Inputs)

	// T.2c: outputs_digest
	outputsDigest, _ := computeOutputsDigest(p.Transparent.Outputs)

	// Combine into transparent digest
	h.Write(prevoutsDigest[:])
	h.Write(sequenceDigest[:])
	h.Write(outputsDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computePrevoutsDigest(inputs []pczt.TransparentInput) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(PrevoutDigestPersonalization))

	for _, input := range inputs {
		h.Write(input.PrevoutTxID[:])
		binary.Write(h, binary.LittleEndian, input.PrevoutIndex)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computeSequenceDigest(inputs []pczt.TransparentInput) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(SequenceDigestPersonalization))

	for _, input := range inputs {
		seq := uint32(0xFFFFFFFF)
		if input.Sequence != nil {
			seq = *input.Sequence
		}
		binary.Write(h, binary.LittleEndian, seq)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computeOutputsDigest(outputs []pczt.TransparentOutput) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(OutputsDigestPersonalization))

	for _, output := range outputs {
		binary.Write(h, binary.LittleEndian, output.Value)
		writeCompactSize(h, uint64(len(output.ScriptPubKey)))
		h.Write(output.ScriptPubKey)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// SaplingDigestData contains Sapling data needed for digest computation.
// This is separate from PCZT because PCZT doesn't fully support Sapling.
type SaplingDigestData struct {
	Spends     []SaplingSpendData
	Outputs    []SaplingOutputData
	ValueBalance int64
}

// SaplingSpendData contains the Sapling spend fields needed for digest.
type SaplingSpendData struct {
	CV        [32]byte
	Anchor    [32]byte // Shared anchor in V5, but stored per-spend for digest
	Nullifier [32]byte
	Rk        [32]byte
}

// SaplingOutputData contains the Sapling output fields needed for digest.
type SaplingOutputData struct {
	CV            [32]byte
	Cmu           [32]byte
	EphemeralKey  [32]byte
	EncCiphertext [580]byte
	OutCiphertext [80]byte
}

// computeSaplingDigest computes the Sapling digest (T.3)
// Returns empty hash with personalization if no Sapling components
func computeSaplingDigest(p *pczt.PCZT) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(SaplingDigestPersonalization))

	// PCZT's SaplingBundle doesn't contain actual data, so we return empty digest
	// For proper Sapling support, use ComputeSaplingDigestWithData
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// ComputeSaplingDigestWithData computes the Sapling digest from explicit data.
// This is used when parsing raw transactions that contain Sapling data.
func ComputeSaplingDigestWithData(data *SaplingDigestData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingDigestPersonalization))

	if data == nil || (len(data.Spends) == 0 && len(data.Outputs) == 0) {
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest
	}

	// Sapling spends digest
	spendsDigest := computeSaplingSpendsDigest(data.Spends)
	h.Write(spendsDigest[:])

	// Sapling outputs digest
	outputsDigest := computeSaplingOutputsDigest(data.Outputs)
	h.Write(outputsDigest[:])

	// Value balance
	binary.Write(h, binary.LittleEndian, data.ValueBalance)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingSpendsDigest(spends []SaplingSpendData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingSpendsDigestPersonalization))

	if len(spends) == 0 {
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest
	}

	// Compact digest: nullifiers
	compactDigest := computeSaplingSpendsCompactDigest(spends)
	h.Write(compactDigest[:])

	// Noncompact digest: cv, anchor, rk
	noncompactDigest := computeSaplingSpendsNoncompactDigest(spends)
	h.Write(noncompactDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingSpendsCompactDigest(spends []SaplingSpendData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingSpendsCompactPersonalization))
	for _, spend := range spends {
		h.Write(spend.Nullifier[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingSpendsNoncompactDigest(spends []SaplingSpendData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingSpendsNoncompactPersonalization))
	for _, spend := range spends {
		h.Write(spend.CV[:])
		h.Write(spend.Anchor[:])
		h.Write(spend.Rk[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingOutputsDigest(outputs []SaplingOutputData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingOutputsDigestPersonalization))

	if len(outputs) == 0 {
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest
	}

	// Compact digest: cmu, ephemeralKey, encCiphertext[:52]
	compactDigest := computeSaplingOutputsCompactDigest(outputs)
	h.Write(compactDigest[:])

	// Memos digest: encCiphertext[52:564]
	memosDigest := computeSaplingOutputsMemosDigest(outputs)
	h.Write(memosDigest[:])

	// Noncompact digest: cv, encCiphertext[564:], outCiphertext
	noncompactDigest := computeSaplingOutputsNoncompactDigest(outputs)
	h.Write(noncompactDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingOutputsCompactDigest(outputs []SaplingOutputData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingOutputsCompactPersonalization))
	for _, out := range outputs {
		h.Write(out.Cmu[:])
		h.Write(out.EphemeralKey[:])
		h.Write(out.EncCiphertext[:52])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingOutputsMemosDigest(outputs []SaplingOutputData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingOutputsMemosPersonalization))
	for _, out := range outputs {
		h.Write(out.EncCiphertext[52:564])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSaplingOutputsNoncompactDigest(outputs []SaplingOutputData) [32]byte {
	h, _ := blake2bNew256([]byte(SaplingOutputsNoncompactPersonalization))
	for _, out := range outputs {
		h.Write(out.CV[:])
		h.Write(out.EncCiphertext[564:])
		h.Write(out.OutCiphertext[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// computeOrchardDigest computes the Orchard digest (T.4)
// Structure: BLAKE2b-256("ZTxIdOrchardHash", compact || memos || noncompact || flags || valueBalance || anchor)
func computeOrchardDigest(p *pczt.PCZT) ([32]byte, error) {
	h, _ := blake2bNew256([]byte(OrchardDigestPersonalization))

	if len(p.Orchard.Actions) == 0 {
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest, nil
	}

	// Compact digest: nullifier || cmx || ephemeralKey || encCiphertext[:52]
	compactDigest := computeOrchardActionsCompactDigest(p.Orchard.Actions)
	h.Write(compactDigest[:])

	// Memos digest: encCiphertext[52:564]
	memosDigest := computeOrchardActionsMemosDigest(p.Orchard.Actions)
	h.Write(memosDigest[:])

	// Noncompact digest: cv || rk || encCiphertext[564:] || outCiphertext
	noncompactDigest := computeOrchardActionsNoncompactDigest(p.Orchard.Actions)
	h.Write(noncompactDigest[:])

	// flags || value_balance || anchor
	h.Write([]byte{p.Orchard.Flags})

	// Value balance as signed int64
	var valueBalance int64
	if p.Orchard.ValueSum.IsNegative {
		valueBalance = -int64(p.Orchard.ValueSum.Magnitude)
	} else {
		valueBalance = int64(p.Orchard.ValueSum.Magnitude)
	}
	binary.Write(h, binary.LittleEndian, valueBalance)

	h.Write(p.Orchard.Anchor[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computeOrchardActionsCompactDigest(actions []pczt.OrchardAction) [32]byte {
	h, _ := blake2bNew256([]byte(OrchardActionsCompactPersonalization))

	for _, action := range actions {
		h.Write(action.Spend.Nullifier[:])
		h.Write(action.Output.Cmx[:])
		h.Write(action.Output.EphemeralKey[:])
		// First 52 bytes of enc_ciphertext
		if len(action.Output.EncCiphertext) >= 52 {
			h.Write(action.Output.EncCiphertext[:52])
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeOrchardActionsMemosDigest(actions []pczt.OrchardAction) [32]byte {
	h, _ := blake2bNew256([]byte(OrchardActionsMemosPersonalization))

	for _, action := range actions {
		// Bytes 52..564 of enc_ciphertext (memo)
		if len(action.Output.EncCiphertext) >= 564 {
			h.Write(action.Output.EncCiphertext[52:564])
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeOrchardActionsNoncompactDigest(actions []pczt.OrchardAction) [32]byte {
	h, _ := blake2bNew256([]byte(OrchardActionsNoncompactPersonalization))

	for _, action := range actions {
		h.Write(action.CvNet[:])
		h.Write(action.Spend.Rk[:])
		// Bytes 564.. of enc_ciphertext
		if len(action.Output.EncCiphertext) > 564 {
			h.Write(action.Output.EncCiphertext[564:])
		}
		h.Write(action.Output.OutCiphertext)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// GetSignatureHash computes the signature hash for a specific transparent input
// This is the main function called by the public API
func GetSignatureHash(
	p *pczt.PCZT,
	inputIndex uint32,
	sighashType uint8,
) ([32]byte, error) {
	if int(inputIndex) >= len(p.Transparent.Inputs) {
		return [32]byte{}, &pczt.SighashError{
			InputIndex: inputIndex,
			Message:    "input index out of bounds",
		}
	}

	// Compute all digests
	digests, err := ComputeTxDigests(p)
	if err != nil {
		return [32]byte{}, err
	}

	// Compute per-input sighash according to ZIP 244
	return computeTransparentSighash(p, digests, inputIndex, sighashType)
}

// computeTransparentSighash implements the transparent signature hash algorithm
// See ZIP 244 Section 4.3
func computeTransparentSighash(
	p *pczt.PCZT,
	digests *TxDigests,
	inputIndex uint32,
	sighashType uint8,
) ([32]byte, error) {
	// Personalization includes branch ID
	personalization := make([]byte, 16)
	copy(personalization, []byte(Zip244HashPersonalization))
	binary.LittleEndian.PutUint32(personalization[12:], p.Global.ConsensusBranchID)

	h, _ := blake2bNew256(personalization)

	// S.1: header_digest
	h.Write(digests.HeaderDigest[:])

	// S.2: transparent signature digest
	transparentSigDigest := computeTransparentSigDigest(p, inputIndex, sighashType)
	h.Write(transparentSigDigest[:])

	// S.3: sapling_digest
	h.Write(digests.SaplingDigest[:])

	// S.4: orchard_digest
	h.Write(digests.OrchardDigest[:])

	var sighash [32]byte
	copy(sighash[:], h.Sum(nil))
	return sighash, nil
}

// computeTransparentSigDigest computes S.2 based on sighash type
// Structure:
//   hash_type ||
//   prevouts_sig_digest ||
//   amounts_sig_digest ||
//   scriptpubkeys_sig_digest ||
//   sequence_sig_digest ||
//   outputs_sig_digest ||
//   txin_sig_digest
func computeTransparentSigDigest(
	p *pczt.PCZT,
	inputIndex uint32,
	sighashType uint8,
) [32]byte {
	h, _ := blake2bNew256([]byte(TransparentDigestPersonalization))

	input := &p.Transparent.Inputs[inputIndex]
	anyoneCanPay := (sighashType & pczt.SighashAnyoneCanPay) != 0
	sigHashMask := sighashType & 0x1f

	// S.2a: hash_type (1 byte)
	h.Write([]byte{sighashType})

	// S.2b: prevouts_sig_digest
	prevoutsDigest := computePrevoutsSigDigest(p.Transparent.Inputs, anyoneCanPay)
	h.Write(prevoutsDigest[:])

	// S.2c: amounts_sig_digest
	amountsDigest := computeAmountsSigDigest(p.Transparent.Inputs, anyoneCanPay)
	h.Write(amountsDigest[:])

	// S.2d: scriptpubkeys_sig_digest
	scriptsDigest := computeScriptsSigDigest(p.Transparent.Inputs, anyoneCanPay)
	h.Write(scriptsDigest[:])

	// S.2e: sequence_sig_digest
	sequenceDigest := computeSequenceSigDigest(p.Transparent.Inputs, anyoneCanPay)
	h.Write(sequenceDigest[:])

	// S.2f: outputs_sig_digest
	outputsDigest := computeOutputsSigDigest(p.Transparent.Outputs, sigHashMask, inputIndex)
	h.Write(outputsDigest[:])

	// S.2g: txin_sig_digest
	txinDigest := computeTxInSigDigest(input)
	h.Write(txinDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computePrevoutsSigDigest(inputs []pczt.TransparentInput, anyoneCanPay bool) [32]byte {
	h, _ := blake2bNew256([]byte(PrevoutDigestPersonalization))

	if !anyoneCanPay {
		for _, input := range inputs {
			h.Write(input.PrevoutTxID[:])
			binary.Write(h, binary.LittleEndian, input.PrevoutIndex)
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeAmountsSigDigest(inputs []pczt.TransparentInput, anyoneCanPay bool) [32]byte {
	h, _ := blake2bNew256([]byte(AmountsDigestPersonalization))

	if !anyoneCanPay {
		for _, input := range inputs {
			binary.Write(h, binary.LittleEndian, input.Value)
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeScriptsSigDigest(inputs []pczt.TransparentInput, anyoneCanPay bool) [32]byte {
	h, _ := blake2bNew256([]byte(ScriptsDigestPersonalization))

	if !anyoneCanPay {
		for _, input := range inputs {
			writeCompactSize(h, uint64(len(input.ScriptPubKey)))
			h.Write(input.ScriptPubKey)
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeSequenceSigDigest(inputs []pczt.TransparentInput, anyoneCanPay bool) [32]byte {
	h, _ := blake2bNew256([]byte(SequenceDigestPersonalization))

	if !anyoneCanPay {
		for _, input := range inputs {
			seq := uint32(0xFFFFFFFF)
			if input.Sequence != nil {
				seq = *input.Sequence
			}
			binary.Write(h, binary.LittleEndian, seq)
		}
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeOutputsSigDigest(outputs []pczt.TransparentOutput, sigHashMask uint8, inputIndex uint32) [32]byte {
	h, _ := blake2bNew256([]byte(OutputsDigestPersonalization))

	switch sigHashMask {
	case pczt.SighashAll:
		// Hash all outputs
		for _, output := range outputs {
			binary.Write(h, binary.LittleEndian, output.Value)
			writeCompactSize(h, uint64(len(output.ScriptPubKey)))
			h.Write(output.ScriptPubKey)
		}
	case pczt.SighashSingle:
		// Hash only the output at inputIndex if it exists
		if int(inputIndex) < len(outputs) {
			output := outputs[inputIndex]
			binary.Write(h, binary.LittleEndian, output.Value)
			writeCompactSize(h, uint64(len(output.ScriptPubKey)))
			h.Write(output.ScriptPubKey)
		}
		// Otherwise return empty hash
	case pczt.SighashNone:
		// Return empty hash (no outputs signed)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func computeTxInSigDigest(input *pczt.TransparentInput) [32]byte {
	h, _ := blake2bNew256([]byte(TxInDigestPersonalization))

	// prevout (txid + index)
	h.Write(input.PrevoutTxID[:])
	binary.Write(h, binary.LittleEndian, input.PrevoutIndex)

	// amount
	binary.Write(h, binary.LittleEndian, input.Value)

	// scriptPubKey (with compact size prefix)
	writeCompactSize(h, uint64(len(input.ScriptPubKey)))
	h.Write(input.ScriptPubKey)

	// sequence
	seq := uint32(0xFFFFFFFF)
	if input.Sequence != nil {
		seq = *input.Sequence
	}
	binary.Write(h, binary.LittleEndian, seq)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// Helper: write compact size (Bitcoin-style varint)
func writeCompactSize(w io.Writer, n uint64) {
	if n < 253 {
		w.Write([]byte{byte(n)})
	} else if n <= 0xFFFF {
		w.Write([]byte{253})
		binary.Write(w, binary.LittleEndian, uint16(n))
	} else if n <= 0xFFFFFFFF {
		w.Write([]byte{254})
		binary.Write(w, binary.LittleEndian, uint32(n))
	} else {
		w.Write([]byte{255})
		binary.Write(w, binary.LittleEndian, n)
	}
}
