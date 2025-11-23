// Package crypto implements ZIP 244 signature hash computation.
//
// ZIP 244 defines the v5 transaction digest algorithm used for signing Zcash
// transactions. It replaces the previous ZIP 143 algorithm used in v4.
//
// This implementation corresponds to:
//   - librustzcash/zcash_primitives/src/transaction/sighash_v5.rs
//   - librustzcash/zcash_primitives/src/transaction/txid.rs
//
// References:
//   - ZIP 244: https://zips.z.cash/zip-0244
//   - The signature hash is computed by hashing together 4 digests:
//     1. Header digest (version, lock time, expiry)
//     2. Transparent digest (prevouts, sequences, outputs)
//     3. Sapling digest (empty for this implementation)
//     4. Orchard digest (actions, value balance, anchor)
package crypto

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
	"golang.org/x/crypto/blake2b"
)

// ZIP 244 constants - personalization strings for BLAKE2b hashing
const (
	Zip244HashPersonalization       = "ZcashTxHash_"
	HeaderDigestPersonalization     = "ZTxIdHeadersHash"
	TransparentDigestPersonalization = "ZTxIdTranspaHash"
	SaplingDigestPersonalization    = "ZTxIdSaplingHash"
	OrchardDigestPersonalization    = "ZTxIdOrchardHash"
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

	// Sapling digest (empty for Orchard-only)
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
	h, _ := blake2b.New256([]byte(HeaderDigestPersonalization))

	buf := new(bytes.Buffer)

	// Serialize header fields:
	// version (4) || version_group_id (4) || consensus_branch_id (4) ||
	// lock_time (4) || expiry_height (4)

	binary.Write(buf, binary.LittleEndian, p.Global.TxVersion)
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
	// If no transparent inputs/outputs, return special digest
	if len(p.Transparent.Inputs) == 0 && len(p.Transparent.Outputs) == 0 {
		var digest [32]byte
		return digest, nil
	}

	// T.2a: prevouts_digest
	prevoutsDigest, err := computePrevoutsDigest(p.Transparent.Inputs)
	if err != nil {
		return [32]byte{}, err
	}

	// T.2b: sequence_digest
	sequenceDigest, err := computeSequenceDigest(p.Transparent.Inputs)
	if err != nil {
		return [32]byte{}, err
	}

	// T.2c: outputs_digest
	outputsDigest, err := computeOutputsDigest(p.Transparent.Outputs)
	if err != nil {
		return [32]byte{}, err
	}

	// Combine into transparent digest
	h, _ := blake2b.New256([]byte(TransparentDigestPersonalization))
	h.Write(prevoutsDigest[:])
	h.Write(sequenceDigest[:])
	h.Write(outputsDigest[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computePrevoutsDigest(inputs []pczt.TransparentInput) ([32]byte, error) {
	h, _ := blake2b.New256([]byte("ZTxIdPrevoutHash"))

	for _, input := range inputs {
		h.Write(input.PrevoutTxID[:])
		binary.Write(h, binary.LittleEndian, input.PrevoutIndex)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func computeSequenceDigest(inputs []pczt.TransparentInput) ([32]byte, error) {
	h, _ := blake2b.New256([]byte("ZTxIdSequencHash"))

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
	h, _ := blake2b.New256([]byte("ZTxIdOutputsHash"))

	for _, output := range outputs {
		binary.Write(h, binary.LittleEndian, output.Value)
		writeCompactSize(h, uint64(len(output.ScriptPubKey)))
		h.Write(output.ScriptPubKey)
	}

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// computeSaplingDigest computes the Sapling digest (T.3) - empty for Orchard-only
func computeSaplingDigest(p *pczt.PCZT) ([32]byte, error) {
	var digest [32]byte
	return digest, nil
}

// computeOrchardDigest computes the Orchard digest (T.4)
func computeOrchardDigest(p *pczt.PCZT) ([32]byte, error) {
	if len(p.Orchard.Actions) == 0 {
		var digest [32]byte
		return digest, nil
	}

	h, _ := blake2b.New256([]byte(OrchardDigestPersonalization))

	// Serialize Orchard bundle digest components
	// (See ZIP 244 section 4.4 for exact format)

	// For each action: nullifier || cmx || ephemeral_key || enc_ciphertext || out_ciphertext
	for _, action := range p.Orchard.Actions {
		h.Write(action.Spend.Nullifier[:])
		h.Write(action.Output.Cmx[:])
		h.Write(action.Output.EphemeralKey[:])
		writeCompactSize(h, uint64(len(action.Output.EncCiphertext)))
		h.Write(action.Output.EncCiphertext)
		writeCompactSize(h, uint64(len(action.Output.OutCiphertext)))
		h.Write(action.Output.OutCiphertext)
	}

	// flags || value_balance || anchor
	h.Write([]byte{p.Orchard.Flags})
	binary.Write(h, binary.LittleEndian, p.Orchard.ValueSum.Magnitude)
	if p.Orchard.ValueSum.IsNegative {
		h.Write([]byte{0x01})
	} else {
		h.Write([]byte{0x00})
	}
	h.Write(p.Orchard.Anchor[:])

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
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

	input := &p.Transparent.Inputs[inputIndex]

	// Compute all digests
	digests, err := ComputeTxDigests(p)
	if err != nil {
		return [32]byte{}, err
	}

	// Compute per-input sighash according to ZIP 244
	return computeTransparentSighash(
		p,
		digests,
		inputIndex,
		input,
		sighashType,
	)
}

// computeTransparentSighash implements the transparent signature hash algorithm
// See ZIP 244 Section 4.3
func computeTransparentSighash(
	p *pczt.PCZT,
	digests *TxDigests,
	inputIndex uint32,
	input *pczt.TransparentInput,
	sighashType uint8,
) ([32]byte, error) {
	h, _ := blake2b.New256([]byte("ZcashTxHash_"))

	// S.1: header_digest
	h.Write(digests.HeaderDigest[:])

	// S.2: transparent signature digest
	transparentSigDigest, err := computeTransparentSigDigest(
		p,
		inputIndex,
		input,
		sighashType,
	)
	if err != nil {
		return [32]byte{}, err
	}
	h.Write(transparentSigDigest[:])

	// S.3: sapling_digest (empty)
	h.Write(digests.SaplingDigest[:])

	// S.4: orchard_digest
	h.Write(digests.OrchardDigest[:])

	var sighash [32]byte
	copy(sighash[:], h.Sum(nil))
	return sighash, nil
}

// computeTransparentSigDigest computes S.2 based on sighash type
func computeTransparentSigDigest(
	p *pczt.PCZT,
	inputIndex uint32,
	input *pczt.TransparentInput,
	sighashType uint8,
) ([32]byte, error) {
	h, _ := blake2b.New256([]byte("ZTxIdTranspaHash"))

	// S.2a: hash_type (1 byte)
	h.Write([]byte{sighashType})

	// S.2b: prevout being spent
	h.Write(input.PrevoutTxID[:])
	binary.Write(h, binary.LittleEndian, input.PrevoutIndex)
	binary.Write(h, binary.LittleEndian, input.Value)
	writeCompactSize(h, uint64(len(input.ScriptPubKey)))
	h.Write(input.ScriptPubKey)

	// S.2c: sequence
	seq := uint32(0xFFFFFFFF)
	if input.Sequence != nil {
		seq = *input.Sequence
	}
	binary.Write(h, binary.LittleEndian, seq)

	// S.2d: input_index
	binary.Write(h, binary.LittleEndian, inputIndex)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
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
