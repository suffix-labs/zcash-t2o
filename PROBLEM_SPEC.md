Sending to Shielded for Transparent Users
Implement a library in one of TypeScript, Go, Kotlin, or Java that permits any user that currently uses Bitcoin-derived, transparent-only Zcash functionality for transaction creation to send shielded outputs to the recipient(s) of the transaction. It is only necessary to implement Orchard support; Sapling support is not required. This API should be based on the Partially Constructed Zcash Transaction (PCZT) API defined in ZIP 374 and implemented by the pczt Rust crate. Note that the draft of ZIP 374 may currently be incomplete; the documentation and implementation of the Rust crate may be treated as a complete specification for the time being.

The first step is to propose a transaction. This operation takes as input the information about the transparent UTXOs to be spent, along with a ZIP 321 payment request that specifies the outputs of the transaction. Each recipient address must be either a unified address containing an Orchard receiver, or a Zcash transparent address.

This function implements the Creator, Constructor, and IO Finalizer roles. It may be implemented using the role implementations for these operations provided by the pczt rust crate, or it may be implemented natively in the host language.

propose_transaction(
  inputs_to_spend: [(TxIn, PrevTxOut)],
  transaction_request: TransactionRequest
) -> Result<PCZT, ProposalError>`
Once a PCZT has been created, if there are any shielded Orchard recipients of the transaction, proofs must be added to the PCZT. This MUST be implemented using the Prover role provided by the pczt Rust crate; it is not feasible to implement proving directly in the host language. It will add the required proofs to the PCZT, and may be executed on the PCZT at any time prior to finalization and extraction. The proving operation may be done in parallel with other verification and signing operations.
This function implements the Prover role. The proving key is for Orchard is closed over or otherwise embedded in the function implementation.

prove_transaction(pczt: PCZT) -> Result<PCZT, ProverError>
The following function may be used to perform pre-signing checks on the contents of the PCZT. If the entity that invoked propose_transaction is the same as the entity that is adding the signatures, and no third party may have malleated the PCZT before signing, this step may be skipped.

verify_before_signing(
  pczt: PCZT,
  transaction_request: TransactionRequest,
  expected_change: [TxOut]
) -> Result<Success, VerificationFailure>
Adding signatures to the PCZT is a two step process. First, for each input provided to the propose_transaction call, the caller should use get_sighash to obtain the signature hash for that input. Then, each signature is added to the PCZT using append_signature. These two operations conceptually enable the caller to implement the Signer role. Implementation of get_sighash may either rely on the Rust implementation of signature hashing provided by the pczt and/or zcash_primitives crates, or complete ZIP 244 support may be implemented in the host language.

get_sighash(
  pczt: PCZT,
  input_index: usize,
) -> Result<SigHash, SighashError>
After obtaining the sighash, the caller may sign the sighash using whatever normal signing infrastructure they use, and then apply the signature to the PCZT, indicating the input that it applies to. The implementation of this method should verify that the signature validates for the input being spent.

append_signature(
  pczt: PCZT,
  input_index: usize,
  signature: [u8; 32]
) -> Result<PCZT, SignatureError>
Once all signatures have been added to the PCZT, either sequentially in parallel, and proofs have been created, combine is used to create the PCZT that is ready for finalization and extraction. If the same entity invokes prove_transaction and append_signature, and does so in sequence in a single thread, this step may be skipped.

combine(pczt: PCZT) -> Result<PCZT, CombineError>
The final step is to execute the the Spend Finalizer and Transaction Extractor roles. This function performs the final non-contextual verification that ensures that the transaction is valid and produces the bytes of the transaction ready to be sent to the chain.

finalize_and_extract(pczt: PCZT) -> Result<TransactionBytes, FinalizationError>
The following two functions are desirable so that the PCZT can be readily transformed to and from the byte encoding of the format for transmission, in the case that signing or proving are done by another process or in some other system.

parse_pczt(pczt_bytes: [u8]) -> Result<PCZT, ParseError>
serialize_pczt(pczt: PCZT) -> [u8]
