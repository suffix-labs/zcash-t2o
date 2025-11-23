// Package pczt implements the Partially Created Zcash Transaction (PCZT) format.
//
// This is a Go implementation of the PCZT specification defined in ZIP 374.
// The types in this file correspond to the Rust implementation found in:
//   - librustzcash/pczt/src/lib.rs (main Pczt struct)
//   - librustzcash/pczt/src/common.rs (Global and shared types)
//   - librustzcash/pczt/src/transparent.rs (TransparentBundle, Input, Output)
//   - librustzcash/pczt/src/orchard.rs (OrchardBundle, Action, Spend, Output)
//   - librustzcash/pczt/src/sapling.rs (SaplingBundle - unused in this implementation)
//
// References:
//   - ZIP 374: https://zips.z.cash/zip-0374
//   - Rust implementation: https://github.com/zcash/librustzcash/tree/main/pczt
package pczt

// PCZT represents a Partially Created Zcash Transaction (v1).
//
// Corresponds to the Rust type: pczt::Pczt (librustzcash/pczt/src/lib.rs)
//
// A PCZT contains all the information needed to construct a Zcash transaction
// across multiple roles (Creator, Constructor, Signer, Prover, etc.). Unlike
// the final transaction format, PCZTs can contain additional metadata needed
// for signing and proving operations.
type PCZT struct {
	Global      Global            // Transaction-wide metadata
	Transparent TransparentBundle // Transparent inputs and outputs
	Sapling     SaplingBundle     // Empty for Orchard-only (Sapling not supported)
	Orchard     OrchardBundle     // Orchard shielded inputs/outputs
}

// Global contains transaction-wide metadata fields.
//
// Corresponds to: pczt::common::Global (librustzcash/pczt/src/common.rs)
//
// These fields apply to the entire transaction and must be agreed upon
// by all parties involved in constructing the PCZT.
type Global struct {
	TxVersion         uint32            // Transaction version (always 5 for v5 transactions)
	VersionGroupID    uint32            // Version group ID (0x26A7270A for v5)
	ConsensusBranchID uint32            // Consensus branch ID (network-specific, e.g., NU5)
	FallbackLockTime  *uint32           // Optional nLockTime (defaults to 0 if nil)
	ExpiryHeight      uint32            // Block height at which tx expires (ZIP 203)
	CoinType          uint32            // SLIP 44 coin type (133 for mainnet, 1 for testnet)
	TxModifiable      uint8             // Bitfield indicating which parts can be modified
	Proprietary       map[string][]byte // Reserved for future extensions
}

// Modification flags for the TxModifiable bitfield.
//
// These flags indicate which parts of the transaction can be modified
// by subsequent roles. This is important for security - signers need to
// know what they're committing to.
const (
	FlagTransparentInputsModifiable  uint8 = 1 << 0 // Bit 0: Transparent inputs may be added/removed
	FlagTransparentOutputsModifiable uint8 = 1 << 1 // Bit 1: Transparent outputs may be added/removed
	FlagHasSighashSingle             uint8 = 1 << 2 // Bit 2: At least one input uses SIGHASH_SINGLE
	FlagShieldedModifiable           uint8 = 1 << 7 // Bit 7: Shielded (Orchard/Sapling) parts modifiable
)

// TransparentBundle contains transparent inputs and outputs.
//
// Corresponds to: pczt::transparent::Bundle (librustzcash/pczt/src/transparent.rs)
//
// Transparent transactions work similarly to Bitcoin - inputs reference
// previous transaction outputs (UTXOs) and outputs create new UTXOs.
type TransparentBundle struct {
	Inputs  []TransparentInput  // Coins being spent
	Outputs []TransparentOutput // Coins being created
}

// TransparentInput represents a transparent coin being spent.
//
// Corresponds to: pczt::transparent::Input (librustzcash/pczt/src/transparent.rs)
//
// This contains both the information needed to spend a UTXO (similar to Bitcoin's
// PSBT input) and metadata for signing. The Constructor role populates the basic
// fields, the Signer adds signatures, and the Spend Finalizer creates the scriptSig.
type TransparentInput struct {
	// Required fields (set by Constructor)
	PrevoutTxID  [32]byte // Previous transaction ID (txid of the UTXO being spent)
	PrevoutIndex uint32   // Output index in previous tx (which output of that tx)
	Value        uint64   // Value in zatoshis (1 ZEC = 100,000,000 zatoshis)
	ScriptPubKey []byte   // Locking script from UTXO (the script that must be satisfied)
	SighashType  uint8    // SIGHASH type (default: ALL = 0x01, signs entire transaction)

	// Optional fields
	Sequence               *uint32                      // Sequence number (default: 0xffffffff, used for timelocks)
	RequiredTimeLockTime   *uint32                      // Required nLockTime >= 500000000 (UNIX timestamp)
	RequiredHeightLockTime *uint32                      // Required nLockTime < 500000000 (block height)
	ScriptSig              []byte                       // Unlocking script (set by Spend Finalizer after signing)
	RedeemScript           []byte                       // P2SH redeem script (only for P2SH inputs)
	PartialSignatures      map[[33]byte][]byte          // Map of pubkey -> DER signature (collected before finalizing)
	Bip32Derivation        map[[33]byte]Zip32Derivation // HD wallet derivation paths for keys

	// Hash preimages (for complex scripts that require revealing preimages)
	// These are used for scripts with OP_HASH160, OP_HASH256, etc.
	Ripemd160Preimages map[[20]byte][]byte // RIPEMD160 preimages
	Sha256Preimages    map[[32]byte][]byte // SHA256 preimages
	Hash160Preimages   map[[20]byte][]byte // HASH160 (SHA256 then RIPEMD160) preimages
	Hash256Preimages   map[[32]byte][]byte // HASH256 (double SHA256) preimages
	Proprietary        map[string][]byte   // Extension mechanism for future features
}

// TransparentOutput represents a transparent coin being created.
//
// Corresponds to: pczt::transparent::Output (librustzcash/pczt/src/transparent.rs)
//
// This defines a new UTXO that will be created by the transaction.
type TransparentOutput struct {
	Value           uint64                       // Value in zatoshis (amount being sent to this output)
	ScriptPubKey    []byte                       // Locking script (defines how this output can be spent)
	RedeemScript    []byte                       // P2SH redeem script (only if this is a P2SH output)
	Bip32Derivation map[[33]byte]Zip32Derivation // HD derivation paths (for change outputs)
	UserAddress     *string                      // Human-readable address (for verification by signer)
	Proprietary     map[string][]byte            // Extension mechanism
}

// SaplingBundle is empty for Orchard-only implementation.
//
// Corresponds to: pczt::sapling::Bundle (librustzcash/pczt/src/sapling.rs)
//
// Sapling is Zcash's previous shielded protocol. This implementation focuses
// on Orchard (the newer protocol) and does not support Sapling transactions.
// All fields are always empty/zero.
type SaplingBundle struct {
	Spends   []interface{} // Always empty (no Sapling spends)
	Outputs  []interface{} // Always empty (no Sapling outputs)
	ValueSum int64         // Always 0 (no value balance)
	Anchor   [32]byte      // Empty Merkle tree anchor
	Bsk      *[32]byte     // Always nil (no binding signature key)
}

// OrchardBundle contains Orchard shielded protocol actions.
//
// Corresponds to: pczt::orchard::Bundle (librustzcash/pczt/src/orchard.rs)
//
// Orchard is Zcash's latest shielded protocol. Unlike transparent transactions,
// Orchard uses "actions" which combine a spend and an output into a single
// cryptographic object. This provides better privacy by making the transaction
// graph harder to analyze.
type OrchardBundle struct {
	Actions  []OrchardAction // List of spend+output pairs
	Flags    uint8           // 0b00000011 = spends and outputs enabled (see Zcash protocol spec)
	ValueSum ValueBalance    // Net value leaving/entering the Orchard pool
	Anchor   [32]byte        // Merkle tree anchor (root of the note commitment tree)
	ZkProof  []byte          // Zero-knowledge proof (set by Prover role)
	Bsk      *[32]byte       // Binding signature private key (set by IO Finalizer, cleared before extraction)
}

// OrchardAction represents a combined spend + output.
//
// Corresponds to: pczt::orchard::Action (librustzcash/pczt/src/orchard.rs)
//
// In Orchard, every action consumes one note (spend) and creates one note (output).
// Even if you only want to create an output (like sending to someone), you must
// include a dummy spend. This is a key privacy feature - it makes all actions
// look the same, preventing observers from distinguishing sends from receives.
type OrchardAction struct {
	CvNet  [32]byte      // Net value commitment (cryptographic commitment to spend_value - output_value)
	Spend  OrchardSpend  // The note being consumed (may be a dummy)
	Output OrchardOutput // The note being created
	Rcv    *[32]byte     // Value commitment randomness (blinding factor, set by Constructor)
}

// OrchardSpend represents a note being consumed.
//
// Corresponds to: pczt::orchard::Spend (librustzcash/pczt/src/orchard.rs)
//
// For transparent-to-Orchard transactions, this will be a "dummy spend" - a
// synthetic spend that doesn't actually consume any value. The dummy spend is
// necessary because Orchard actions always pair a spend with an output.
type OrchardSpend struct {
	Nullifier    [32]byte  // Nullifier (prevents double-spending; dummy for synthetic spends)
	Rk           [32]byte  // Randomized verification key (for spend authorization)
	SpendAuthSig *[64]byte // Spend authorization signature (set by IO Finalizer for dummy spends)

	// Optional fields (for dummy spends)
	Recipient       *[43]byte         // Raw Orchard address (43 bytes: diversifier + pk_d, required by Prover)
	Value           *uint64           // Note value (always 0 for dummy spends)
	Rho             *[32]byte         // Nullifier derivation seed
	Rseed           *[32]byte         // Note randomness seed
	Fvk             *[96]byte         // Full viewing key (96 bytes, allows viewing this note)
	Witness         *MerkleWitness    // Merkle path proving note inclusion (not needed for dummies)
	Alpha           *[32]byte         // Spend authorization randomizer (blinding factor)
	Zip32Derivation *Zip32Derivation  // HD wallet derivation path
	DummySk         *[32]byte         // Dummy spend private key (cleared by IO Finalizer before extraction)
	Proprietary     map[string][]byte // Extension mechanism
}

// OrchardOutput represents an Orchard note being created.
//
// Corresponds to: pczt::orchard::Output (librustzcash/pczt/src/orchard.rs)
//
// This is the actual shielded output that gets sent to the recipient. The note
// details are encrypted so only the recipient (who has the corresponding viewing key)
// can see the amount and decrypt the payment.
type OrchardOutput struct {
	Cmx           [32]byte // Note commitment (cryptographic commitment to the note, goes on-chain)
	EphemeralKey  [32]byte // Ephemeral Diffie-Hellman public key (for encryption)
	EncCiphertext []byte   // Encrypted note plaintext (580 bytes: recipient sees value, memo, etc.)
	OutCiphertext []byte   // Encrypted outgoing ciphertext (80 bytes: sender can recover sent amount)

	// Required by Prover (can be redacted after proving to reduce PCZT size)
	Recipient *[43]byte // Raw Orchard address (diversifier + transmission key)
	Value     *uint64   // Value in zatoshis (amount being sent)
	Rseed     *[32]byte // Note randomness seed (32 bytes of entropy)

	// Optional fields
	Ock             *[32]byte         // Outgoing cipher key (for sender to recover details)
	Zip32Derivation *Zip32Derivation  // HD wallet derivation path
	UserAddress     *string           // Human-readable Unified Address (for signer validation)
	Proprietary     map[string][]byte // Extension mechanism
}

// ValueBalance represents a signed value (can be positive or negative).
//
// Used for Orchard value balance (net flow in/out of shielded pool).
// Positive = value entering pool (from transparent), Negative = value leaving pool (to transparent)
type ValueBalance struct {
	Magnitude  uint64 // Absolute value
	IsNegative bool   // Sign bit (true = negative)
}

// MerkleWitness represents a Merkle tree authentication path.
//
// Proves that a note commitment exists in the global note commitment tree.
// Required for spending existing notes (not needed for dummy spends).
type MerkleWitness struct {
	Position uint32       // Leaf position in the tree
	Path     [32][32]byte // 32 sibling hashes (Orchard tree has depth 32)
}

// Zip32Derivation represents a HD (Hierarchical Deterministic) wallet derivation path.
//
// Corresponds to ZIP 32 (Zcash's HD wallet spec, similar to BIP 32 for Bitcoin).
// Allows wallets to derive keys from a master seed using a path like m/32'/133'/0'/0/0
type Zip32Derivation struct {
	SeedFingerprint [32]byte // Fingerprint of the master seed (identifies the wallet)
	DerivationPath  []uint32 // Sequence of indices (values ≥ 2^31 indicate hardened derivation)
}

// Transaction version constants (Zcash protocol specification)
const (
	V5TxVersion      uint32 = 5          // Zcash v5 transaction format (current version)
	V5VersionGroupID uint32 = 0x26A7270A // Version group ID for v5 (indicates tx format version)
	MainNetCoinType  uint32 = 133        // SLIP 44 coin type for Zcash mainnet
	TestNetCoinType  uint32 = 1          // SLIP 44 coin type for Zcash testnet
)

// SIGHASH types (Bitcoin-derived signature hash flags)
//
// These control what parts of the transaction are signed. See ZIP 244 for details.
const (
	SighashAll             uint8 = 0x01                       // Sign all inputs and outputs (most common)
	SighashNone            uint8 = 0x02                       // Sign all inputs but no outputs
	SighashSingle          uint8 = 0x03                       // Sign all inputs and one output (at same index)
	SighashAnyoneCanPay    uint8 = 0x80                       // Sign only this input (can be combined with others)
	SighashAllAnyoneCanPay uint8 = SighashAll | SighashAnyoneCanPay // Sign this input and all outputs
)

// Orchard bundle flags
const (
	OrchardFlagsEnabled uint8 = 0b00000011 // Bits 0-1 set: both spends and outputs are enabled
)
