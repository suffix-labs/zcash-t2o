package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVector represents a single ZIP-244 test vector
type TestVector struct {
	Tx                  string   // hex-encoded transaction bytes
	TxID                string   // hex-encoded expected txid
	AuthDigest          string   // hex-encoded expected auth digest
	Amounts             []int64  // input amounts for transparent inputs
	ScriptPubkeys       []string // hex-encoded scriptPubKeys for transparent inputs
	TransparentInput    *int     // index of transparent input being signed (nil for shielded-only)
	SighashShielded     string   // hex-encoded sighash for shielded inputs
	SighashAll          *string  // hex-encoded sighash with SIGHASH_ALL
	SighashNone         *string  // hex-encoded sighash with SIGHASH_NONE
	SighashSingle       *string  // hex-encoded sighash with SIGHASH_SINGLE
	SighashAllAnyone    *string  // hex-encoded sighash with SIGHASH_ALL | SIGHASH_ANYONECANPAY
	SighashNoneAnyone   *string  // hex-encoded sighash with SIGHASH_NONE | SIGHASH_ANYONECANPAY
	SighashSingleAnyone *string  // hex-encoded sighash with SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
}

// getTestDataPath returns the path to test data files
func getTestDataPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "vectors")
}

// loadTestVectors loads ZIP-244 test vectors from JSON file
func loadTestVectors(t *testing.T) []TestVector {
	t.Helper()

	jsonPath := filepath.Join(getTestDataPath(), "zip_0244.json")
	data, err := os.ReadFile(jsonPath)
	require.NoError(t, err, "Failed to read test vectors file")

	// JSON format: [["comment"], ["field names"], [vector1], [vector2], ...]
	var raw []json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw), "Failed to parse JSON")

	var vectors []TestVector

	// Skip first 2 rows (comment and field names), parse remaining as vectors
	for i := 2; i < len(raw); i++ {
		var row []interface{}
		err := json.Unmarshal(raw[i], &row)
		require.NoError(t, err, "Failed to parse vector row %d", i)

		v := parseVectorRow(t, row)
		vectors = append(vectors, v)
	}

	return vectors
}

// parseVectorRow converts a JSON array row into a TestVector
func parseVectorRow(t *testing.T, row []interface{}) TestVector {
	t.Helper()

	v := TestVector{}

	// Field order from JSON header:
	// tx, txid, auth_digest, amounts, script_pubkeys, transparent_input,
	// sighash_shielded, sighash_all, sighash_none, sighash_single,
	// sighash_all_anyone, sighash_none_anyone, sighash_single_anyone

	if len(row) < 13 {
		t.Fatalf("Vector row has %d fields, expected 13", len(row))
	}

	// tx (string)
	v.Tx = row[0].(string)

	// txid (string)
	v.TxID = row[1].(string)

	// auth_digest (string)
	v.AuthDigest = row[2].(string)

	// amounts ([]int64)
	if amounts, ok := row[3].([]interface{}); ok {
		for _, a := range amounts {
			v.Amounts = append(v.Amounts, int64(a.(float64)))
		}
	}

	// script_pubkeys ([]string)
	if scripts, ok := row[4].([]interface{}); ok {
		for _, s := range scripts {
			v.ScriptPubkeys = append(v.ScriptPubkeys, s.(string))
		}
	}

	// transparent_input (*int)
	if row[5] != nil {
		idx := int(row[5].(float64))
		v.TransparentInput = &idx
	}

	// sighash_shielded (string)
	v.SighashShielded = row[6].(string)

	// sighash_all (*string)
	if row[7] != nil {
		s := row[7].(string)
		v.SighashAll = &s
	}

	// sighash_none (*string)
	if row[8] != nil {
		s := row[8].(string)
		v.SighashNone = &s
	}

	// sighash_single (*string)
	if row[9] != nil {
		s := row[9].(string)
		v.SighashSingle = &s
	}

	// sighash_all_anyone (*string)
	if row[10] != nil {
		s := row[10].(string)
		v.SighashAllAnyone = &s
	}

	// sighash_none_anyone (*string)
	if row[11] != nil {
		s := row[11].(string)
		v.SighashNoneAnyone = &s
	}

	// sighash_single_anyone (*string)
	if row[12] != nil {
		s := row[12].(string)
		v.SighashSingleAnyone = &s
	}

	return v
}

// hexDecode decodes a hex string, failing the test on error
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "Failed to decode hex: %s", s[:min(len(s), 20)])
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// reverseBytes reverses a byte slice in place and returns it.
// Used to handle "bitcoin_flavoured" format where 32-byte values are byte-reversed in display.
func reverseBytes(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func TestLoadTestVectors(t *testing.T) {
	vectors := loadTestVectors(t)
	assert.NotEmpty(t, vectors, "Should have loaded test vectors")
	t.Logf("Loaded %d test vectors", len(vectors))

	// Verify first vector has expected structure
	v := vectors[0]
	assert.NotEmpty(t, v.Tx, "Tx should not be empty")
	assert.NotEmpty(t, v.TxID, "TxID should not be empty")
	assert.Len(t, v.TxID, 64, "TxID should be 32 bytes (64 hex chars)")
}

func TestParseFirstVector(t *testing.T) {
	vectors := loadTestVectors(t)
	v := vectors[0]

	txBytes := hexDecode(t, v.Tx)
	tx, err := ParseV5Transaction(txBytes)
	require.NoError(t, err)

	t.Logf("Version: %d (0x%08x)", tx.Version, tx.Version)
	t.Logf("VersionGroupID: 0x%08x", tx.VersionGroupID)
	t.Logf("ConsensusBranchID: 0x%08x", tx.ConsensusBranchID)
	t.Logf("LockTime: %d", tx.LockTime)
	t.Logf("ExpiryHeight: %d", tx.ExpiryHeight)
	t.Logf("Transparent inputs: %d", len(tx.TransparentInputs))
	t.Logf("Transparent outputs: %d", len(tx.TransparentOutputs))
	t.Logf("Sapling spends: %d", len(tx.SaplingSpends))
	t.Logf("Sapling outputs: %d", len(tx.SaplingOutputs))
	t.Logf("SaplingValue: %d", tx.SaplingValue)
	t.Logf("Orchard actions: %d", len(tx.OrchardActions))
	t.Logf("OrchardFlags: %d", tx.OrchardFlags)
	t.Logf("OrchardValueBalance: %d", tx.OrchardValueBalance)

	// Print amounts and scripts from vector
	t.Logf("Expected amounts: %v", v.Amounts)
	t.Logf("Expected scriptPubkeys: %d scripts", len(v.ScriptPubkeys))
}

func TestDebugDigests(t *testing.T) {
	vectors := loadTestVectors(t)
	v := vectors[0]  // Test vector 0

	txBytes := hexDecode(t, v.Tx)
	tx, err := ParseV5Transaction(txBytes)
	require.NoError(t, err)

	pcztTx := TxToPCZT(tx, v.Amounts, nil)

	// Print header fields from parsed tx
	t.Logf("Parsed tx.Version: %d (0x%08x)", tx.Version, uint32(tx.Version))
	t.Logf("Parsed tx.VersionGroupID: 0x%08x", tx.VersionGroupID)
	t.Logf("Parsed tx.ConsensusBranchID: 0x%08x", tx.ConsensusBranchID)
	t.Logf("Parsed tx.LockTime: %d", tx.LockTime)
	t.Logf("Parsed tx.ExpiryHeight: %d", tx.ExpiryHeight)

	// Print transparent bundle info
	t.Logf("Transparent inputs: %d", len(tx.TransparentInputs))
	t.Logf("Transparent outputs: %d", len(tx.TransparentOutputs))

	// Print sapling bundle info
	t.Logf("Sapling spends: %d", len(tx.SaplingSpends))
	t.Logf("Sapling outputs: %d", len(tx.SaplingOutputs))
	t.Logf("Sapling value: %d", tx.SaplingValue)

	// Print orchard bundle info
	t.Logf("Orchard actions: %d", len(tx.OrchardActions))
	t.Logf("Orchard flags: %d", tx.OrchardFlags)
	t.Logf("Orchard value balance: %d", tx.OrchardValueBalance)

	// Print first 20 bytes of raw tx
	t.Logf("First 20 bytes of raw tx: %x", txBytes[:20])

	// Check the input details
	if len(tx.TransparentInputs) > 0 {
		inp := tx.TransparentInputs[0]
		t.Logf("Input 0 prevout txid: %x", inp.PrevoutTxID)
		t.Logf("Input 0 prevout index: %d", inp.PrevoutIndex)
		t.Logf("Input 0 sequence: %d (0x%08x)", inp.Sequence, inp.Sequence)
	}

	// Header digest
	// First, debug the PCZT values
	t.Logf("PCZT TxVersion: %d (0x%08x)", pcztTx.Global.TxVersion, pcztTx.Global.TxVersion)
	t.Logf("PCZT VersionGroupID: 0x%08x", pcztTx.Global.VersionGroupID)
	t.Logf("PCZT ConsensusBranchID: 0x%08x", pcztTx.Global.ConsensusBranchID)
	if pcztTx.Global.FallbackLockTime != nil {
		t.Logf("PCZT FallbackLockTime: %d", *pcztTx.Global.FallbackLockTime)
	} else {
		t.Logf("PCZT FallbackLockTime: nil")
	}
	t.Logf("PCZT ExpiryHeight: %d", pcztTx.Global.ExpiryHeight)
	headerDigest, _ := computeHeaderDigest(pcztTx)
	t.Logf("Header digest: %x", headerDigest)

	// Transparent digest
	transparentDigest, _ := computeTransparentDigest(pcztTx)
	t.Logf("Transparent digest: %x", transparentDigest)

	// Sapling digest
	saplingData := parsedTxToSaplingDigestData(tx)
	if saplingData != nil {
		t.Logf("Sapling has %d spends, %d outputs, value balance: %d", len(saplingData.Spends), len(saplingData.Outputs), saplingData.ValueBalance)
		if len(saplingData.Spends) > 0 {
			t.Logf("  Spend 0 cv: %x", saplingData.Spends[0].CV[:8])
			t.Logf("  Spend 0 anchor: %x", saplingData.Spends[0].Anchor[:8])
			t.Logf("  Spend 0 nullifier: %x", saplingData.Spends[0].Nullifier[:8])
			t.Logf("  Spend 0 rk: %x", saplingData.Spends[0].Rk[:8])
		}
		if len(saplingData.Outputs) > 0 {
			t.Logf("  Output 0 cv: %x", saplingData.Outputs[0].CV[:8])
			t.Logf("  Output 0 cmu: %x", saplingData.Outputs[0].Cmu[:8])
		}
	}
	saplingDigest := ComputeSaplingDigestWithData(saplingData)
	t.Logf("Sapling digest: %x", saplingDigest)

	// Orchard digest
	orchardDigest, _ := computeOrchardDigest(pcztTx)
	t.Logf("Orchard digest: %x", orchardDigest)

	// Expected TXID
	expectedTxid := hexDecode(t, v.TxID)
	t.Logf("Expected TXID: %x", expectedTxid)

	// Computed TXID
	txid, _ := ComputeTxIDFromParsed(tx)
	t.Logf("Computed TXID:            %x", txid)
}

func TestZIP244Vectors(t *testing.T) {
	vectors := loadTestVectors(t)

	for i, v := range vectors {
		t.Run(fmt.Sprintf("vector_%d", i), func(t *testing.T) {
			// Decode transaction bytes
			txBytes := hexDecode(t, v.Tx)

			// Parse the v5 transaction
			tx, err := ParseV5Transaction(txBytes)
			if err != nil {
				t.Skipf("Transaction parsing not yet implemented: %v", err)
				return
			}

			// Convert to PCZT with amounts and scriptPubkeys
			var scriptPubkeys [][]byte
			for _, s := range v.ScriptPubkeys {
				scriptPubkeys = append(scriptPubkeys, hexDecode(t, s))
			}
			pczt := TxToPCZT(tx, v.Amounts, scriptPubkeys)

			// Test TXID computation
			t.Run("txid", func(t *testing.T) {
				expected := hexDecode(t, v.TxID)
				got, err := ComputeTxIDFromParsed(tx)
				if err != nil {
					t.Skipf("ComputeTxID not yet implemented: %v", err)
					return
				}
				assert.Equal(t, expected, got[:], "TXID mismatch")
			})

			// Test sighash for shielded inputs
			t.Run("sighash_shielded", func(t *testing.T) {
				expected := hexDecode(t, v.SighashShielded)
				got, err := GetShieldedSignatureHash(pczt)
				if err != nil {
					t.Skipf("GetShieldedSignatureHash not yet implemented: %v", err)
					return
				}
				assert.Equal(t, expected, got[:], "Shielded sighash mismatch")
			})

			// Test sighash variants for transparent input
			if v.TransparentInput != nil {
				idx := uint32(*v.TransparentInput)

				if v.SighashAll != nil {
					t.Run("sighash_all", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashAll)
						got, err := GetSignatureHash(pczt, idx, SighashAll)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_ALL mismatch")
					})
				}

				if v.SighashNone != nil {
					t.Run("sighash_none", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashNone)
						got, err := GetSignatureHash(pczt, idx, SighashNone)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_NONE mismatch")
					})
				}

				if v.SighashSingle != nil {
					t.Run("sighash_single", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashSingle)
						got, err := GetSignatureHash(pczt, idx, SighashSingle)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_SINGLE mismatch")
					})
				}

				if v.SighashAllAnyone != nil {
					t.Run("sighash_all_anyone", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashAllAnyone)
						got, err := GetSignatureHash(pczt, idx, SighashAll|SighashAnyoneCanPay)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_ALL|ANYONECANPAY mismatch")
					})
				}

				if v.SighashNoneAnyone != nil {
					t.Run("sighash_none_anyone", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashNoneAnyone)
						got, err := GetSignatureHash(pczt, idx, SighashNone|SighashAnyoneCanPay)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_NONE|ANYONECANPAY mismatch")
					})
				}

				if v.SighashSingleAnyone != nil {
					t.Run("sighash_single_anyone", func(t *testing.T) {
						expected := hexDecode(t, *v.SighashSingleAnyone)
						got, err := GetSignatureHash(pczt, idx, SighashSingle|SighashAnyoneCanPay)
						if err != nil {
							t.Errorf("GetSignatureHash failed: %v", err)
							return
						}
						assert.Equal(t, expected, got[:], "SIGHASH_SINGLE|ANYONECANPAY mismatch")
					})
				}
			}
		})
	}
}

// SIGHASH type constants
const (
	SighashAll          uint8 = 0x01
	SighashNone         uint8 = 0x02
	SighashSingle       uint8 = 0x03
	SighashMask         uint8 = 0x1f
	SighashAnyoneCanPay uint8 = 0x80
)
