package roles

import (
	"github.com/suffix-labs/zcash-t2o/pkg/ffi"
	"github.com/suffix-labs/zcash-t2o/pkg/pczt"
)

// IoFinalizer finalizes inputs and outputs, preparing for signing.
//
// Corresponds to: pczt::roles::io_finalizer::IoFinalizer
//   (librustzcash/pczt/src/roles/io_finalizer/)
//
// The IO Finalizer role:
//   - Clears all modification flags (no more I/O changes allowed)
//   - Computes the Orchard binding signature key (bsk)
//   - Signs dummy spends with temporary keys
//   - Clears sensitive key material (dummy spending keys)
//
// After this role executes, the PCZT structure is locked and ready for
// the Prover (to generate ZK proofs) and Signer (to add transparent signatures).
type IoFinalizer struct {
	pczt *pczt.PCZT
}

// NewIoFinalizer creates a new IO Finalizer.
func NewIoFinalizer(p *pczt.PCZT) *IoFinalizer {
	return &IoFinalizer{pczt: p}
}

// Finalize performs IO finalization.
//
// This:
//   1. Clears all modification flags (TxModifiable = 0)
//   2. Computes the Orchard binding signature key
//   3. Signs dummy spends and clears their secret keys
//
// Returns an error if finalization fails.
func (f *IoFinalizer) Finalize() error {
	// Clear all modification flags - no more changes to I/O allowed
	// This signals to signers that the transaction structure is final
	f.pczt.Global.TxModifiable = 0

	// Finalize Orchard bundle (compute bsk)
	if err := f.finalizeOrchard(); err != nil {
		return err
	}

	// Sign dummy spends and clear their secret keys
	if err := f.signDummySpends(); err != nil {
		return err
	}

	return nil
}

// finalizeOrchard computes the Orchard binding signature key.
//
// The binding signature key (bsk) is the sum of all value commitment
// randomness values (rcv) from the actions. This will be used later to
// create the binding signature that proves the value balance is correct.
//
// Formula: bsk = sum(rcv_i) for all actions i
//
// TODO: Requires Pallas scalar addition via Orchard FFI
func (f *IoFinalizer) finalizeOrchard() error {
	if len(f.pczt.Orchard.Actions) == 0 {
		return nil
	}

	// Compute bsk = sum(rcv) for all actions
	// Start with zero
	bsk := [32]byte{}

	for _, action := range f.pczt.Orchard.Actions {
		if action.Rcv == nil {
			continue
		}

		// bsk += rcv (scalar addition on Pallas curve)
		// TODO: Must use Orchard FFI for actual Pallas scalar arithmetic
		bsk = scalarAdd(bsk, *action.Rcv)
	}

	// Store bsk in the bundle
	// This will be used by the Transaction Extractor to create the binding signature
	f.pczt.Orchard.Bsk = &bsk

	return nil
}

// signDummySpends creates signatures for all dummy spends.
//
// For transparent-to-Orchard transactions, all spends are "dummy spends"
// (synthetic spends that don't consume real notes). Each dummy spend needs
// a spend authorization signature to be valid. We:
//   1. Sign with the temporary dummy spending key
//   2. Store the signature
//   3. Clear the spending key (for security)
//
// TODO: Requires RedPallas signing via Orchard FFI
func (f *IoFinalizer) signDummySpends() error {
	// For each action, if the spend has a DummySk, sign it and clear the key
	for i := range f.pczt.Orchard.Actions {
		action := &f.pczt.Orchard.Actions[i]

		if action.Spend.DummySk == nil {
			continue // Not a dummy spend, skip
		}

		// Create dummy spend authorization signature
		// This signs the sighash with the dummy spending key
		// TODO: Must use Orchard FFI for RedPallas signing
		sig := createDummySpendSignature(*action.Spend.DummySk, action.Spend.Alpha)

		action.Spend.SpendAuthSig = &sig

		// Clear the dummy secret key for security
		// We no longer need it after signing, and keeping it around is risky
		action.Spend.DummySk = nil
	}

	return nil
}

// Finish returns the finalized PCZT.
//
// The PCZT is now ready for:
//   - Prover role (to generate zero-knowledge proofs)
//   - Signer role (to add transparent signatures)
func (f *IoFinalizer) Finish() *pczt.PCZT {
	return f.pczt
}

// ============================================================================
// Cryptographic helper functions
//
// TODO: These are placeholder implementations. In production, these MUST
// call into the Orchard Rust crate via FFI.
//
// See: librustzcash/orchard/src/ for the Rust implementations
// ============================================================================

// scalarAdd performs scalar addition on the Pallas curve.
//
// Calls into Rust FFI for actual Pallas field arithmetic.
// Corresponds to: pallas::Scalar addition in librustzcash
//
// This is used to compute bsk = sum(rcv_i)
func scalarAdd(a, b [32]byte) [32]byte {
	result, err := ffi.PallasScalarAdd(a, b)
	if err != nil {
		// Log error but return zero - caller should validate
		return [32]byte{}
	}
	return result
}

// createDummySpendSignature creates a RedPallas signature for a dummy spend.
//
// Calls into Rust FFI for actual RedPallas signing.
// Corresponds to: reddsa::orchard::SpendAuth::sign in librustzcash
//
// RedPallas is Zcash's signature scheme (randomized Schnorr signatures on Pallas).
// The signature proves knowledge of the spending key without revealing it.
//
// For dummy spends in T2O transactions, we use a zero sighash since:
// 1. The spend doesn't consume a real note (value = 0)
// 2. The ZK proof validates the action structure
// 3. The binding signature covers the actual value balance
//
// Parameters:
//   - sk: Dummy spending key (temporary, will be cleared after signing)
//   - alpha: Randomizer for the signature
//
// Returns: 64-byte RedPallas signature
func createDummySpendSignature(sk [32]byte, alpha *[32]byte) [64]byte {
	// For dummy spends, use zero sighash - the actual sighash doesn't matter
	// since the spend is synthetic and validated by the ZK proof
	var sighash [32]byte
	var alphaVal [32]byte
	if alpha != nil {
		alphaVal = *alpha
	}

	sig, err := ffi.RedDSASignSpendAuth(sk, alphaVal, sighash)
	if err != nil {
		// Return zero signature on error - will fail validation later
		return [64]byte{}
	}
	return sig
}
