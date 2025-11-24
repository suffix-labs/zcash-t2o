// Package pczt serialization implements Postcard encoding/decoding for PCZT.
//
// Postcard is a compact binary serialization format (https://postcard.jamesmunns.com/).
// The PCZT format wraps Postcard with a magic header and version:
//
//	File format: "PCZT" (4 bytes) || version (u32le) || postcard-encoded-data
//
// This corresponds to the Rust implementation in:
//   - librustzcash/pczt/src/lib.rs (Serialize/Deserialize traits via serde + postcard)
//
// The encoding follows the exact field order and structure defined in the Rust
// implementation to ensure compatibility. All Option<T> types use 0x00 for None
// and 0x01 for Some, all sequences use varint length prefixes, and all integers
// are little-endian.
package pczt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PCZT file format: "PCZT" || version (u32le) || postcard-encoded data

const (
	MagicBytes   = "PCZT"
	PCZTVersion1 = uint32(1)
)

// Serialize encodes a PCZT to bytes
// Format: [0x50, 0x43, 0x5a, 0x54] || I2LEOSP_32(1) || POSTCARD_ENCODED
func Serialize(pczt *PCZT) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write magic bytes
	buf.WriteString(MagicBytes)

	// Write version (little-endian u32)
	if err := binary.Write(buf, binary.LittleEndian, PCZTVersion1); err != nil {
		return nil, err
	}

	// Encode PCZT using Postcard
	encoded, err := postcardEncode(pczt)
	if err != nil {
		return nil, err
	}

	buf.Write(encoded)
	return buf.Bytes(), nil
}

// Parse decodes a PCZT from bytes
func Parse(data []byte) (*PCZT, error) {
	if len(data) < 8 {
		return nil, &ParseError{Message: "data too short"}
	}

	// Check magic bytes
	if string(data[0:4]) != MagicBytes {
		return nil, &ParseError{Message: "invalid magic bytes"}
	}

	// Check version
	version := binary.LittleEndian.Uint32(data[4:8])
	if version != PCZTVersion1 {
		return nil, &ParseError{Message: fmt.Sprintf("unsupported version: %d", version)}
	}

	// Decode Postcard data
	pczt, err := postcardDecode(data[8:])
	if err != nil {
		return nil, &ParseError{Message: "postcard decode failed", Cause: err}
	}

	return pczt, nil
}

// postcardEncode implements Postcard wire format encoding
// See: https://postcard.jamesmunns.com/wire-format
func postcardEncode(pczt *PCZT) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Encode Global
	if err := encodeGlobal(buf, &pczt.Global); err != nil {
		return nil, err
	}

	// Encode TransparentBundle
	if err := encodeTransparentBundle(buf, &pczt.Transparent); err != nil {
		return nil, err
	}

	// Encode SaplingBundle (empty)
	if err := encodeSaplingBundle(buf, &pczt.Sapling); err != nil {
		return nil, err
	}

	// Encode OrchardBundle
	if err := encodeOrchardBundle(buf, &pczt.Orchard); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodeGlobal encodes the Global struct
func encodeGlobal(w io.Writer, g *Global) error {
	// Write u32 fields (little-endian)
	binary.Write(w, binary.LittleEndian, g.TxVersion)
	binary.Write(w, binary.LittleEndian, g.VersionGroupID)
	binary.Write(w, binary.LittleEndian, g.ConsensusBranchID)

	// Write Option<u32> (0x00 = None, 0x01 = Some)
	if g.FallbackLockTime == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		binary.Write(w, binary.LittleEndian, *g.FallbackLockTime)
	}

	binary.Write(w, binary.LittleEndian, g.ExpiryHeight)
	binary.Write(w, binary.LittleEndian, g.CoinType)
	w.Write([]byte{g.TxModifiable})

	// Write Map (varint length, then key-value pairs)
	encodeVarInt(w, uint64(len(g.Proprietary)))
	for k, v := range g.Proprietary {
		encodeString(w, k)
		encodeBytes(w, v)
	}

	return nil
}

// encodeTransparentBundle encodes TransparentBundle
func encodeTransparentBundle(w io.Writer, tb *TransparentBundle) error {
	// List<TransparentInput>
	encodeVarInt(w, uint64(len(tb.Inputs)))
	for i := range tb.Inputs {
		if err := encodeTransparentInput(w, &tb.Inputs[i]); err != nil {
			return err
		}
	}

	// List<TransparentOutput>
	encodeVarInt(w, uint64(len(tb.Outputs)))
	for i := range tb.Outputs {
		if err := encodeTransparentOutput(w, &tb.Outputs[i]); err != nil {
			return err
		}
	}

	return nil
}

// encodeTransparentInput encodes a single TransparentInput
func encodeTransparentInput(w io.Writer, ti *TransparentInput) error {
	w.Write(ti.PrevoutTxID[:])
	binary.Write(w, binary.LittleEndian, ti.PrevoutIndex)

	// Option<u32> for Sequence
	encodeOption32(w, ti.Sequence)
	encodeOption32(w, ti.RequiredTimeLockTime)
	encodeOption32(w, ti.RequiredHeightLockTime)

	// Option<Vec<u8>> for ScriptSig
	encodeOptionBytes(w, ti.ScriptSig)

	binary.Write(w, binary.LittleEndian, ti.Value)
	encodeBytes(w, ti.ScriptPubKey)

	encodeOptionBytes(w, ti.RedeemScript)

	// Map<[u8; 33], Vec<u8>> for PartialSignatures
	encodeVarInt(w, uint64(len(ti.PartialSignatures)))
	for pubkey, sig := range ti.PartialSignatures {
		w.Write(pubkey[:])
		encodeBytes(w, sig)
	}

	w.Write([]byte{ti.SighashType})

	// Map<[u8; 33], Zip32Derivation> for Bip32Derivation
	encodeVarInt(w, uint64(len(ti.Bip32Derivation)))
	for pubkey, deriv := range ti.Bip32Derivation {
		w.Write(pubkey[:])
		encodeZip32Derivation(w, &deriv)
	}

	// Hash preimage maps
	encodeMap20(w, ti.Ripemd160Preimages)
	encodeMap32(w, ti.Sha256Preimages)
	encodeMap20(w, ti.Hash160Preimages)
	encodeMap32(w, ti.Hash256Preimages)

	// Proprietary map
	encodeVarInt(w, uint64(len(ti.Proprietary)))
	for k, v := range ti.Proprietary {
		encodeString(w, k)
		encodeBytes(w, v)
	}

	return nil
}

// encodeTransparentOutput encodes a single TransparentOutput
func encodeTransparentOutput(w io.Writer, to *TransparentOutput) error {
	binary.Write(w, binary.LittleEndian, to.Value)
	encodeBytes(w, to.ScriptPubKey)
	encodeOptionBytes(w, to.RedeemScript)

	// Map<[u8; 33], Zip32Derivation>
	encodeVarInt(w, uint64(len(to.Bip32Derivation)))
	for pubkey, deriv := range to.Bip32Derivation {
		w.Write(pubkey[:])
		encodeZip32Derivation(w, &deriv)
	}

	// Option<String>
	encodeOptionString(w, to.UserAddress)

	// Proprietary map
	encodeVarInt(w, uint64(len(to.Proprietary)))
	for k, v := range to.Proprietary {
		encodeString(w, k)
		encodeBytes(w, v)
	}

	return nil
}

// encodeSaplingBundle encodes SaplingBundle (empty for Orchard-only)
func encodeSaplingBundle(w io.Writer, sb *SaplingBundle) error {
	// Empty arrays
	encodeVarInt(w, 0) // Spends
	encodeVarInt(w, 0) // Outputs

	binary.Write(w, binary.LittleEndian, sb.ValueSum)
	w.Write(sb.Anchor[:])

	// Option<[u8; 32]> for Bsk (always None)
	w.Write([]byte{0x00})

	return nil
}

// encodeOrchardBundle encodes OrchardBundle
func encodeOrchardBundle(w io.Writer, ob *OrchardBundle) error {
	// List<OrchardAction>
	encodeVarInt(w, uint64(len(ob.Actions)))
	for i := range ob.Actions {
		if err := encodeOrchardAction(w, &ob.Actions[i]); err != nil {
			return err
		}
	}

	w.Write([]byte{ob.Flags})

	// ValueBalance (u64, bool)
	binary.Write(w, binary.LittleEndian, ob.ValueSum.Magnitude)
	if ob.ValueSum.IsNegative {
		w.Write([]byte{0x01})
	} else {
		w.Write([]byte{0x00})
	}

	w.Write(ob.Anchor[:])

	// Option<Vec<u8>> for ZkProof
	encodeOptionBytes(w, ob.ZkProof)

	// Option<[u8; 32]> for Bsk
	if ob.Bsk == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(ob.Bsk[:])
	}

	// Option<[u8; 64]> for BindingSig
	if ob.BindingSig == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(ob.BindingSig[:])
	}

	return nil
}

// encodeOrchardAction encodes a single OrchardAction
func encodeOrchardAction(w io.Writer, oa *OrchardAction) error {
	w.Write(oa.CvNet[:])

	if err := encodeOrchardSpend(w, &oa.Spend); err != nil {
		return err
	}

	if err := encodeOrchardOutput(w, &oa.Output); err != nil {
		return err
	}

	// Option<[u8; 32]> for Rcv
	if oa.Rcv == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(oa.Rcv[:])
	}

	return nil
}

// encodeOrchardSpend encodes an OrchardSpend
func encodeOrchardSpend(w io.Writer, os *OrchardSpend) error {
	w.Write(os.Nullifier[:])
	w.Write(os.Rk[:])

	// Option<[u8; 64]> for SpendAuthSig
	if os.SpendAuthSig == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(os.SpendAuthSig[:])
	}

	// Optional fields
	encodeOption43(w, os.Recipient)
	encodeOptionU64(w, os.Value)
	encodeOption32Bytes(w, os.Rho)
	encodeOption32Bytes(w, os.Rseed)
	encodeOption96(w, os.Fvk)
	encodeOptionWitness(w, os.Witness)
	encodeOption32Bytes(w, os.Alpha)
	encodeOptionZip32Derivation(w, os.Zip32Derivation)
	encodeOption32Bytes(w, os.DummySk)

	// Proprietary map
	encodeVarInt(w, uint64(len(os.Proprietary)))
	for k, v := range os.Proprietary {
		encodeString(w, k)
		encodeBytes(w, v)
	}

	return nil
}

// encodeOrchardOutput encodes an OrchardOutput
func encodeOrchardOutput(w io.Writer, oo *OrchardOutput) error {
	w.Write(oo.Cmx[:])
	w.Write(oo.EphemeralKey[:])
	encodeBytes(w, oo.EncCiphertext)
	encodeBytes(w, oo.OutCiphertext)

	// Optional fields
	encodeOption43(w, oo.Recipient)
	encodeOptionU64(w, oo.Value)
	encodeOption32Bytes(w, oo.Rseed)
	encodeOption32Bytes(w, oo.Ock)
	encodeOptionZip32Derivation(w, oo.Zip32Derivation)
	encodeOptionString(w, oo.UserAddress)

	// Proprietary map
	encodeVarInt(w, uint64(len(oo.Proprietary)))
	for k, v := range oo.Proprietary {
		encodeString(w, k)
		encodeBytes(w, v)
	}

	return nil
}

// Helper encoding functions

func encodeVarInt(w io.Writer, n uint64) error {
	// Postcard varint encoding (LEB128)
	for {
		b := uint8(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		w.Write([]byte{b})
		if n == 0 {
			break
		}
	}
	return nil
}

func encodeString(w io.Writer, s string) error {
	bytes := []byte(s)
	encodeVarInt(w, uint64(len(bytes)))
	w.Write(bytes)
	return nil
}

func encodeBytes(w io.Writer, b []byte) error {
	encodeVarInt(w, uint64(len(b)))
	w.Write(b)
	return nil
}

func encodeOption32(w io.Writer, opt *uint32) {
	if opt == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		binary.Write(w, binary.LittleEndian, *opt)
	}
}

func encodeOptionU64(w io.Writer, opt *uint64) {
	if opt == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		binary.Write(w, binary.LittleEndian, *opt)
	}
}

func encodeOption43(w io.Writer, opt *[43]byte) {
	if opt == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(opt[:])
	}
}

func encodeOption32Bytes(w io.Writer, opt *[32]byte) {
	if opt == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(opt[:])
	}
}

func encodeOption96(w io.Writer, opt *[96]byte) {
	if opt == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		w.Write(opt[:])
	}
}

func encodeOptionBytes(w io.Writer, b []byte) {
	if len(b) == 0 {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		encodeBytes(w, b)
	}
}

func encodeOptionString(w io.Writer, s *string) {
	if s == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		encodeString(w, *s)
	}
}

func encodeOptionWitness(w io.Writer, mw *MerkleWitness) {
	if mw == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		binary.Write(w, binary.LittleEndian, mw.Position)
		for i := 0; i < 32; i++ {
			w.Write(mw.Path[i][:])
		}
	}
}

func encodeOptionZip32Derivation(w io.Writer, zd *Zip32Derivation) {
	if zd == nil {
		w.Write([]byte{0x00})
	} else {
		w.Write([]byte{0x01})
		encodeZip32Derivation(w, zd)
	}
}

func encodeZip32Derivation(w io.Writer, zd *Zip32Derivation) {
	w.Write(zd.SeedFingerprint[:])
	encodeVarInt(w, uint64(len(zd.DerivationPath)))
	for _, idx := range zd.DerivationPath {
		binary.Write(w, binary.LittleEndian, idx)
	}
}

func encodeMap20(w io.Writer, m map[[20]byte][]byte) {
	encodeVarInt(w, uint64(len(m)))
	for k, v := range m {
		w.Write(k[:])
		encodeBytes(w, v)
	}
}

func encodeMap32(w io.Writer, m map[[32]byte][]byte) {
	encodeVarInt(w, uint64(len(m)))
	for k, v := range m {
		w.Write(k[:])
		encodeBytes(w, v)
	}
}

// Decoding functions (mirror of encoding)

func postcardDecode(data []byte) (*PCZT, error) {
	r := bytes.NewReader(data)
	pczt := &PCZT{}

	if err := decodeGlobal(r, &pczt.Global); err != nil {
		return nil, err
	}

	if err := decodeTransparentBundle(r, &pczt.Transparent); err != nil {
		return nil, err
	}

	if err := decodeSaplingBundle(r, &pczt.Sapling); err != nil {
		return nil, err
	}

	if err := decodeOrchardBundle(r, &pczt.Orchard); err != nil {
		return nil, err
	}

	return pczt, nil
}

func decodeVarInt(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for {
		var b [1]byte
		if _, err := r.Read(b[:]); err != nil {
			return 0, err
		}

		result |= uint64(b[0]&0x7F) << shift
		if b[0]&0x80 == 0 {
			break
		}
		shift += 7
	}

	return result, nil
}

func decodeBytes(r io.Reader) ([]byte, error) {
	length, err := decodeVarInt(r)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func decodeString(r io.Reader) (string, error) {
	b, err := decodeBytes(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeGlobal(r io.Reader, g *Global) error {
	if err := binary.Read(r, binary.LittleEndian, &g.TxVersion); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &g.VersionGroupID); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &g.ConsensusBranchID); err != nil {
		return err
	}

	// Option<u32> for FallbackLockTime
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return err
	}
	if hasValue[0] == 0x01 {
		var val uint32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return err
		}
		g.FallbackLockTime = &val
	}

	if err := binary.Read(r, binary.LittleEndian, &g.ExpiryHeight); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &g.CoinType); err != nil {
		return err
	}

	var modifiable [1]byte
	if _, err := r.Read(modifiable[:]); err != nil {
		return err
	}
	g.TxModifiable = modifiable[0]

	// Proprietary map
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	g.Proprietary = make(map[string][]byte)
	for i := uint64(0); i < mapLen; i++ {
		key, err := decodeString(r)
		if err != nil {
			return err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return err
		}
		g.Proprietary[key] = val
	}

	return nil
}

func decodeTransparentBundle(r io.Reader, tb *TransparentBundle) error {
	// Decode inputs
	inputLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	tb.Inputs = make([]TransparentInput, inputLen)
	for i := uint64(0); i < inputLen; i++ {
		if err := decodeTransparentInput(r, &tb.Inputs[i]); err != nil {
			return err
		}
	}

	// Decode outputs
	outputLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	tb.Outputs = make([]TransparentOutput, outputLen)
	for i := uint64(0); i < outputLen; i++ {
		if err := decodeTransparentOutput(r, &tb.Outputs[i]); err != nil {
			return err
		}
	}

	return nil
}

func decodeTransparentInput(r io.Reader, ti *TransparentInput) error {
	if _, err := io.ReadFull(r, ti.PrevoutTxID[:]); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &ti.PrevoutIndex); err != nil {
		return err
	}

	// Decode optional fields
	ti.Sequence = decodeOption32(r)
	ti.RequiredTimeLockTime = decodeOption32(r)
	ti.RequiredHeightLockTime = decodeOption32(r)

	var err error
	ti.ScriptSig, err = decodeOptionBytes(r)
	if err != nil {
		return err
	}

	if err := binary.Read(r, binary.LittleEndian, &ti.Value); err != nil {
		return err
	}

	ti.ScriptPubKey, err = decodeBytes(r)
	if err != nil {
		return err
	}

	ti.RedeemScript, err = decodeOptionBytes(r)
	if err != nil {
		return err
	}

	// PartialSignatures map
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	ti.PartialSignatures = make(map[[33]byte][]byte)
	for i := uint64(0); i < mapLen; i++ {
		var pubkey [33]byte
		if _, err := io.ReadFull(r, pubkey[:]); err != nil {
			return err
		}
		sig, err := decodeBytes(r)
		if err != nil {
			return err
		}
		ti.PartialSignatures[pubkey] = sig
	}

	var sighash [1]byte
	if _, err := r.Read(sighash[:]); err != nil {
		return err
	}
	ti.SighashType = sighash[0]

	// Bip32Derivation map
	mapLen, err = decodeVarInt(r)
	if err != nil {
		return err
	}
	ti.Bip32Derivation = make(map[[33]byte]Zip32Derivation)
	for i := uint64(0); i < mapLen; i++ {
		var pubkey [33]byte
		if _, err := io.ReadFull(r, pubkey[:]); err != nil {
			return err
		}
		deriv, err := decodeZip32Derivation(r)
		if err != nil {
			return err
		}
		ti.Bip32Derivation[pubkey] = *deriv
	}

	// Hash preimage maps
	ti.Ripemd160Preimages, err = decodeMap20(r)
	if err != nil {
		return err
	}
	ti.Sha256Preimages, err = decodeMap32(r)
	if err != nil {
		return err
	}
	ti.Hash160Preimages, err = decodeMap20(r)
	if err != nil {
		return err
	}
	ti.Hash256Preimages, err = decodeMap32(r)
	if err != nil {
		return err
	}

	// Proprietary map
	mapLen, err = decodeVarInt(r)
	if err != nil {
		return err
	}
	ti.Proprietary = make(map[string][]byte)
	for i := uint64(0); i < mapLen; i++ {
		key, err := decodeString(r)
		if err != nil {
			return err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return err
		}
		ti.Proprietary[key] = val
	}

	return nil
}

func decodeTransparentOutput(r io.Reader, to *TransparentOutput) error {
	if err := binary.Read(r, binary.LittleEndian, &to.Value); err != nil {
		return err
	}

	var err error
	to.ScriptPubKey, err = decodeBytes(r)
	if err != nil {
		return err
	}

	to.RedeemScript, err = decodeOptionBytes(r)
	if err != nil {
		return err
	}

	// Bip32Derivation map
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	to.Bip32Derivation = make(map[[33]byte]Zip32Derivation)
	for i := uint64(0); i < mapLen; i++ {
		var pubkey [33]byte
		if _, err := io.ReadFull(r, pubkey[:]); err != nil {
			return err
		}
		deriv, err := decodeZip32Derivation(r)
		if err != nil {
			return err
		}
		to.Bip32Derivation[pubkey] = *deriv
	}

	to.UserAddress = decodeOptionString(r)

	// Proprietary map
	mapLen, err = decodeVarInt(r)
	if err != nil {
		return err
	}
	to.Proprietary = make(map[string][]byte)
	for i := uint64(0); i < mapLen; i++ {
		key, err := decodeString(r)
		if err != nil {
			return err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return err
		}
		to.Proprietary[key] = val
	}

	return nil
}

func decodeSaplingBundle(r io.Reader, sb *SaplingBundle) error {
	// Skip empty spends
	spendLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	if spendLen != 0 {
		return fmt.Errorf("expected empty Sapling spends")
	}

	// Skip empty outputs
	outputLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	if outputLen != 0 {
		return fmt.Errorf("expected empty Sapling outputs")
	}

	if err := binary.Read(r, binary.LittleEndian, &sb.ValueSum); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, sb.Anchor[:]); err != nil {
		return err
	}

	// Option<[u8; 32]> for Bsk (should always be None)
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return err
	}
	if hasValue[0] == 0x01 {
		return fmt.Errorf("unexpected Sapling Bsk value")
	}

	return nil
}

func decodeOrchardBundle(r io.Reader, ob *OrchardBundle) error {
	// Decode actions
	actionLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	ob.Actions = make([]OrchardAction, actionLen)
	for i := uint64(0); i < actionLen; i++ {
		if err := decodeOrchardAction(r, &ob.Actions[i]); err != nil {
			return err
		}
	}

	var flags [1]byte
	if _, err := r.Read(flags[:]); err != nil {
		return err
	}
	ob.Flags = flags[0]

	if err := binary.Read(r, binary.LittleEndian, &ob.ValueSum.Magnitude); err != nil {
		return err
	}

	var isNeg [1]byte
	if _, err := r.Read(isNeg[:]); err != nil {
		return err
	}
	ob.ValueSum.IsNegative = isNeg[0] == 0x01

	if _, err := io.ReadFull(r, ob.Anchor[:]); err != nil {
		return err
	}

	ob.ZkProof, err = decodeOptionBytes(r)
	if err != nil {
		return err
	}

	// Option<[u8; 32]> for Bsk
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return err
	}
	if hasValue[0] == 0x01 {
		var bsk [32]byte
		if _, err := io.ReadFull(r, bsk[:]); err != nil {
			return err
		}
		ob.Bsk = &bsk
	}

	// Option<[u8; 64]> for BindingSig
	var hasBindingSig [1]byte
	if _, err := r.Read(hasBindingSig[:]); err != nil {
		return err
	}
	if hasBindingSig[0] == 0x01 {
		var bindingSig [64]byte
		if _, err := io.ReadFull(r, bindingSig[:]); err != nil {
			return err
		}
		ob.BindingSig = &bindingSig
	}

	return nil
}

func decodeOrchardAction(r io.Reader, oa *OrchardAction) error {
	if _, err := io.ReadFull(r, oa.CvNet[:]); err != nil {
		return err
	}

	if err := decodeOrchardSpend(r, &oa.Spend); err != nil {
		return err
	}

	if err := decodeOrchardOutput(r, &oa.Output); err != nil {
		return err
	}

	// Option<[u8; 32]> for Rcv
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return err
	}
	if hasValue[0] == 0x01 {
		var rcv [32]byte
		if _, err := io.ReadFull(r, rcv[:]); err != nil {
			return err
		}
		oa.Rcv = &rcv
	}

	return nil
}

func decodeOrchardSpend(r io.Reader, os *OrchardSpend) error {
	if _, err := io.ReadFull(r, os.Nullifier[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, os.Rk[:]); err != nil {
		return err
	}

	// Option<[u8; 64]> for SpendAuthSig
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return err
	}
	if hasValue[0] == 0x01 {
		var sig [64]byte
		if _, err := io.ReadFull(r, sig[:]); err != nil {
			return err
		}
		os.SpendAuthSig = &sig
	}

	// Decode optional fields
	os.Recipient = decodeOption43(r)
	os.Value = decodeOptionU64(r)
	os.Rho = decodeOption32Bytes(r)
	os.Rseed = decodeOption32Bytes(r)
	os.Fvk = decodeOption96(r)

	witness, err := decodeOptionWitness(r)
	if err != nil {
		return err
	}
	os.Witness = witness

	os.Alpha = decodeOption32Bytes(r)

	zip32, err := decodeOptionZip32Derivation(r)
	if err != nil {
		return err
	}
	os.Zip32Derivation = zip32

	os.DummySk = decodeOption32Bytes(r)

	// Proprietary map
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	os.Proprietary = make(map[string][]byte)
	for i := uint64(0); i < mapLen; i++ {
		key, err := decodeString(r)
		if err != nil {
			return err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return err
		}
		os.Proprietary[key] = val
	}

	return nil
}

func decodeOrchardOutput(r io.Reader, oo *OrchardOutput) error {
	if _, err := io.ReadFull(r, oo.Cmx[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, oo.EphemeralKey[:]); err != nil {
		return err
	}

	var err error
	oo.EncCiphertext, err = decodeBytes(r)
	if err != nil {
		return err
	}
	oo.OutCiphertext, err = decodeBytes(r)
	if err != nil {
		return err
	}

	// Decode optional fields
	oo.Recipient = decodeOption43(r)
	oo.Value = decodeOptionU64(r)
	oo.Rseed = decodeOption32Bytes(r)
	oo.Ock = decodeOption32Bytes(r)

	zip32, err := decodeOptionZip32Derivation(r)
	if err != nil {
		return err
	}
	oo.Zip32Derivation = zip32

	oo.UserAddress = decodeOptionString(r)

	// Proprietary map
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return err
	}
	oo.Proprietary = make(map[string][]byte)
	for i := uint64(0); i < mapLen; i++ {
		key, err := decodeString(r)
		if err != nil {
			return err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return err
		}
		oo.Proprietary[key] = val
	}

	return nil
}

// Helper decode functions

func decodeOption32(r io.Reader) *uint32 {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		var val uint32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil
		}
		return &val
	}
	return nil
}

func decodeOptionU64(r io.Reader) *uint64 {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		var val uint64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil
		}
		return &val
	}
	return nil
}

func decodeOption32Bytes(r io.Reader) *[32]byte {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		var val [32]byte
		if _, err := io.ReadFull(r, val[:]); err != nil {
			return nil
		}
		return &val
	}
	return nil
}

func decodeOption43(r io.Reader) *[43]byte {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		var val [43]byte
		if _, err := io.ReadFull(r, val[:]); err != nil {
			return nil
		}
		return &val
	}
	return nil
}

func decodeOption96(r io.Reader) *[96]byte {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		var val [96]byte
		if _, err := io.ReadFull(r, val[:]); err != nil {
			return nil
		}
		return &val
	}
	return nil
}

func decodeOptionBytes(r io.Reader) ([]byte, error) {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil, err
	}
	if hasValue[0] == 0x01 {
		return decodeBytes(r)
	}
	return nil, nil
}

func decodeOptionString(r io.Reader) *string {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil
	}
	if hasValue[0] == 0x01 {
		str, err := decodeString(r)
		if err != nil {
			return nil
		}
		return &str
	}
	return nil
}

func decodeOptionWitness(r io.Reader) (*MerkleWitness, error) {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil, err
	}
	if hasValue[0] == 0x01 {
		var mw MerkleWitness
		if err := binary.Read(r, binary.LittleEndian, &mw.Position); err != nil {
			return nil, err
		}
		for i := 0; i < 32; i++ {
			if _, err := io.ReadFull(r, mw.Path[i][:]); err != nil {
				return nil, err
			}
		}
		return &mw, nil
	}
	return nil, nil
}

func decodeOptionZip32Derivation(r io.Reader) (*Zip32Derivation, error) {
	var hasValue [1]byte
	if _, err := r.Read(hasValue[:]); err != nil {
		return nil, err
	}
	if hasValue[0] == 0x01 {
		return decodeZip32Derivation(r)
	}
	return nil, nil
}

func decodeZip32Derivation(r io.Reader) (*Zip32Derivation, error) {
	var zd Zip32Derivation
	if _, err := io.ReadFull(r, zd.SeedFingerprint[:]); err != nil {
		return nil, err
	}

	pathLen, err := decodeVarInt(r)
	if err != nil {
		return nil, err
	}

	zd.DerivationPath = make([]uint32, pathLen)
	for i := uint64(0); i < pathLen; i++ {
		if err := binary.Read(r, binary.LittleEndian, &zd.DerivationPath[i]); err != nil {
			return nil, err
		}
	}

	return &zd, nil
}

func decodeMap20(r io.Reader) (map[[20]byte][]byte, error) {
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return nil, err
	}

	result := make(map[[20]byte][]byte)
	for i := uint64(0); i < mapLen; i++ {
		var key [20]byte
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return nil, err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}

	return result, nil
}

func decodeMap32(r io.Reader) (map[[32]byte][]byte, error) {
	mapLen, err := decodeVarInt(r)
	if err != nil {
		return nil, err
	}

	result := make(map[[32]byte][]byte)
	for i := uint64(0); i < mapLen; i++ {
		var key [32]byte
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return nil, err
		}
		val, err := decodeBytes(r)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}

	return result, nil
}
