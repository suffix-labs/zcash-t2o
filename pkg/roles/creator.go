// Package roles implements the PCZT role pattern.
//
// PCZT roles separate transaction construction into distinct responsibilities:
//   - Creator: Initializes empty PCZT structure
//   - Constructor: Adds inputs/outputs, builds Orchard actions
//   - IO Finalizer: Creates dummy spends, generates binding signatures
//   - Signer: Adds transparent signatures
//   - Prover: Generates zero-knowledge proofs
//   - Spend Finalizer: Finalizes transparent scripts
//   - Transaction Extractor: Produces final transaction bytes
//   - Combiner: Merges parallel PCZTs
//
// This corresponds to the Rust implementation in:
//   - librustzcash/pczt/src/roles/ (all role implementations)
//
// Each role can be executed by different parties or at different times,
// enabling collaborative transaction construction.
package roles

import (
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// Creator initializes a base PCZT with no spends or outputs.
//
// Corresponds to: pczt::roles::creator::Creator (librustzcash/pczt/src/roles/creator/)
//
// The Creator role sets up the transaction-wide metadata (version, expiry,
// branch ID, anchors, etc.) that all parties must agree on. It doesn't add
// any inputs or outputs - those are added by the Constructor role.
type Creator struct {
	consensusBranchID uint32   // Network upgrade branch ID (e.g., NU5)
	expiryHeight      uint32   // Block height at which tx expires
	coinType          uint32   // SLIP 44 coin type (133 = mainnet, 1 = testnet)
	saplingAnchor     [32]byte // Sapling tree anchor (empty for Orchard-only)
	orchardAnchor     [32]byte // Orchard tree anchor (root of commitment tree)
	fallbackLockTime  *uint32  // Optional nLockTime
}

// NewCreator creates a new Creator with required parameters.
//
// Parameters:
//   - consensusBranchID: Network upgrade consensus branch ID
//   - expiryHeight: Block height at which the transaction expires
//   - coinType: SLIP 44 coin type (133 for mainnet, 1 for testnet)
//   - orchardAnchor: Root of the Orchard note commitment tree
func NewCreator(
	consensusBranchID uint32,
	expiryHeight uint32,
	coinType uint32,
	orchardAnchor [32]byte,
) *Creator {
	return &Creator{
		consensusBranchID: consensusBranchID,
		expiryHeight:      expiryHeight,
		coinType:          coinType,
		saplingAnchor:     [32]byte{}, // Empty tree (Sapling not supported)
		orchardAnchor:     orchardAnchor,
		fallbackLockTime:  nil,
	}
}

// WithFallbackLockTime sets an optional nLockTime value.
//
// The fallback lock time is used if no input has a required lock time.
// It can be either a block height (< 500000000) or UNIX timestamp (>= 500000000).
func (c *Creator) WithFallbackLockTime(lockTime uint32) *Creator {
	c.fallbackLockTime = &lockTime
	return c
}

// Create creates the base PCZT structure.
//
// Returns a PCZT with:
//   - Global metadata initialized
//   - Empty transparent, Sapling, and Orchard bundles
//   - All modification flags set (inputs/outputs can be added)
//
// This PCZT is ready to be passed to the Constructor role to add I/O.
func (c *Creator) Create() *pczt.PCZT {
	return &pczt.PCZT{
		Global: pczt.Global{
			TxVersion:         pczt.V5TxVersion,
			VersionGroupID:    pczt.V5VersionGroupID,
			ConsensusBranchID: c.consensusBranchID,
			FallbackLockTime:  c.fallbackLockTime,
			ExpiryHeight:      c.expiryHeight,
			CoinType:          c.coinType,
			// All modification flags set - Constructor can add anything
			TxModifiable: pczt.FlagTransparentInputsModifiable |
				pczt.FlagTransparentOutputsModifiable |
				pczt.FlagShieldedModifiable,
			Proprietary: make(map[string][]byte),
		},
		Transparent: pczt.TransparentBundle{
			Inputs:  []pczt.TransparentInput{},
			Outputs: []pczt.TransparentOutput{},
		},
		Sapling: pczt.SaplingBundle{
			Spends:   []interface{}{},
			Outputs:  []interface{}{},
			ValueSum: 0,
			Anchor:   c.saplingAnchor,
			Bsk:      nil,
		},
		Orchard: pczt.OrchardBundle{
			Actions:  []pczt.OrchardAction{},
			Flags:    pczt.OrchardFlagsEnabled,
			ValueSum: pczt.ValueBalance{Magnitude: 0, IsNegative: false},
			Anchor:   c.orchardAnchor,
			ZkProof:  nil,
			Bsk:      nil,
		},
	}
}
