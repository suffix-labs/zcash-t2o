// zcash-t2o CLI - Transparent-to-Orchard transaction builder
//
// This CLI demonstrates the zcash-t2o library's capabilities for creating
// Zcash transactions that send from transparent addresses to shielded
// Orchard addresses.
//
// Example usage:
//   # Parse a ZIP 321 payment request
//   zcash-t2o parse-uri "zcash:addr?amount=1.5&memo=coffee"
//
//   # Create a transaction proposal
//   zcash-t2o propose --input txid:index:value --output addr:amount
//
//   # Sign a PCZT
//   zcash-t2o sign --pczt file.pczt --key privatekey.wif --input 0
//
//   # Extract final transaction
//   zcash-t2o extract --pczt signed.pczt
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/suffix-labs/zcash-t2o/pkg/api"
	"github.com/suffix-labs/zcash-t2o/pkg/crypto"
	"github.com/suffix-labs/zcash-t2o/pkg/zip321"
)

const (
	// NU5 consensus branch ID for mainnet
	NU5ConsensusBranchID = 0xC2D6D0B4

	// Testnet coin type
	TestnetCoinType = 1
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "parse-uri":
		cmdParseURI()
	case "propose":
		cmdPropose()
	case "sign":
		cmdSign()
	case "extract":
		cmdExtract()
	case "version":
		cmdVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`zcash-t2o - Transparent-to-Orchard transaction builder

Usage:
  zcash-t2o <command> [options]

Commands:
  parse-uri <uri>              Parse a ZIP 321 payment request URI
  propose                      Create a transaction proposal
  sign                         Sign a PCZT
  extract                      Extract final transaction from PCZT
  version                      Show version information
  help                         Show this help message

Examples:
  # Parse a payment request
  zcash-t2o parse-uri "zcash:uaddr1...?amount=1.5&memo=payment"

  # Create a simple transaction proposal (not yet implemented)
  zcash-t2o propose \
    --input <txid>:<index>:<value> \
    --output <address>:<amount> \
    --expiry 2500000

  # Sign an input (not yet implemented)
  zcash-t2o sign \
    --pczt proposal.pczt \
    --key private.wif \
    --input 0 \
    --output signed.pczt

  # Extract transaction (not yet implemented)
  zcash-t2o extract \
    --pczt signed.pczt \
    --output transaction.raw

For more information, see: https://github.com/suffix-labs/zcash-t2o`)
}

func cmdVersion() {
	fmt.Println("zcash-t2o v0.1.0")
	fmt.Println("PCZT library for Zcash transparent-to-Orchard transactions")
	fmt.Println("Based on ZIP 374 and librustzcash")
}

func cmdParseURI() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: URI argument required")
		fmt.Fprintln(os.Stderr, "Usage: zcash-t2o parse-uri <uri>")
		os.Exit(1)
	}

	uri := os.Args[2]

	// Parse the payment request
	req, err := zip321.Parse(uri)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse URI: %v\n", err)
		os.Exit(1)
	}

	// Display parsed information
	fmt.Println("Payment Request:")
	fmt.Printf("  Payments: %d\n\n", len(req.Payments))

	for i, payment := range req.Payments {
		fmt.Printf("Payment %d:\n", i+1)
		fmt.Printf("  Address: %s\n", payment.Address)

		if payment.Amount != nil {
			fmt.Printf("  Amount:  %.8f ZEC\n", *payment.Amount)
		} else {
			fmt.Println("  Amount:  (user specified)")
		}

		if payment.Memo != nil {
			fmt.Printf("  Memo:    %s\n", *payment.Memo)
		}

		if payment.Label != nil {
			fmt.Printf("  Label:   %s\n", *payment.Label)
		}

		if payment.Message != nil {
			fmt.Printf("  Message: %s\n", *payment.Message)
		}

		fmt.Println()
	}

	// Show how to encode it back
	encoded := req.Encode()
	fmt.Printf("Re-encoded URI:\n%s\n", encoded)
}

func cmdPropose() {
	fmt.Println("Transaction proposal creation not yet fully implemented.")
	fmt.Println()
	fmt.Println("Example code structure:")
	fmt.Println()
	fmt.Println("  proposal := &api.TransactionProposal{")
	fmt.Println("    ConsensusBranchID: NU5ConsensusBranchID,")
	fmt.Println("    ExpiryHeight:      2500000,")
	fmt.Println("    CoinType:          TestnetCoinType,")
	fmt.Println("    OrchardAnchor:     [32]byte{...},")
	fmt.Println("    TransparentInputs: []api.TransparentInput{...},")
	fmt.Println("    OrchardOutputs:    []api.OrchardOutput{...},")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("  pcztBytes, err := api.ProposeTransaction(proposal)")
	fmt.Println()
	fmt.Println("See pkg/api/api.go for full API documentation.")
}

func cmdSign() {
	fmt.Println("PCZT signing not yet fully implemented.")
	fmt.Println()
	fmt.Println("Example code structure:")
	fmt.Println()
	fmt.Println("  // Load PCZT")
	fmt.Println("  pcztBytes, _ := os.ReadFile(\"proposal.pczt\")")
	fmt.Println()
	fmt.Println("  // Load private key")
	fmt.Println("  privateKey, _ := crypto.PrivateKeyFromWIF(\"KxYZ...\")")
	fmt.Println()
	fmt.Println("  // Get sighash")
	fmt.Println("  sighash, _ := api.GetSighash(pcztBytes, 0)")
	fmt.Println("  fmt.Printf(\"Sighash: %x\\n\", sighash)")
	fmt.Println()
	fmt.Println("  // Sign")
	fmt.Println("  signedBytes, _ := api.AppendSignature(pcztBytes, 0, privateKey)")
	fmt.Println()
	fmt.Println("  // Save")
	fmt.Println("  os.WriteFile(\"signed.pczt\", signedBytes, 0644)")
	fmt.Println()
	fmt.Println("See pkg/api/api.go for full API documentation.")
}

func cmdExtract() {
	fmt.Println("Transaction extraction not yet fully implemented.")
	fmt.Println()
	fmt.Println("Example code structure:")
	fmt.Println()
	fmt.Println("  // Load signed PCZT")
	fmt.Println("  pcztBytes, _ := os.ReadFile(\"signed.pczt\")")
	fmt.Println()
	fmt.Println("  // Verify before extraction")
	fmt.Println("  err := api.VerifyBeforeSigning(pcztBytes)")
	fmt.Println("  if err != nil {")
	fmt.Println("    log.Fatal(\"Invalid PCZT:\", err)")
	fmt.Println("  }")
	fmt.Println()
	fmt.Println("  // Extract transaction")
	fmt.Println("  txBytes, _ := api.FinalizeAndExtract(pcztBytes)")
	fmt.Println()
	fmt.Println("  // Display transaction hex")
	fmt.Println("  fmt.Printf(\"Transaction: %x\\n\", txBytes)")
	fmt.Println()
	fmt.Println("See pkg/api/api.go for full API documentation.")
}

// Example function showing complete workflow
func exampleCompleteWorkflow() {
	fmt.Println("Complete workflow example:")
	fmt.Println()

	// Step 1: Create proposal
	proposal := &api.TransactionProposal{
		ConsensusBranchID: NU5ConsensusBranchID,
		ExpiryHeight:      2500000,
		CoinType:          TestnetCoinType,
		OrchardAnchor:     [32]byte{}, // TODO: Get from blockchain
		TransparentInputs: []api.TransparentInput{
			{
				TxID:         [32]byte{}, // TODO: Fill in
				OutputIndex:  0,
				Value:        100000000, // 1 ZEC
				ScriptPubKey: []byte{}, // TODO: Fill in
			},
		},
		OrchardOutputs: []api.OrchardOutput{
			{
				Address: "uaddr1...", // TODO: Real address
				Value:   95000000,    // 0.95 ZEC (0.05 ZEC fee)
				Memo:    []byte("Payment"),
			},
		},
	}

	// Step 2: Propose
	pcztBytes, err := api.ProposeTransaction(proposal)
	if err != nil {
		fmt.Printf("Propose failed: %v\n", err)
		return
	}
	fmt.Printf("Created PCZT (%d bytes)\n", len(pcztBytes))

	// Step 3: Prove (generate ZK proofs)
	provedBytes, err := api.ProveTransaction(pcztBytes)
	if err != nil {
		fmt.Printf("Proving failed: %v\n", err)
		return
	}
	fmt.Printf("Generated proofs (%d bytes)\n", len(provedBytes))

	// Step 4: Verify
	err = api.VerifyBeforeSigning(provedBytes)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}
	fmt.Println("PCZT verified successfully")

	// Step 5: Get sighash
	sighash, err := api.GetSighash(provedBytes, 0)
	if err != nil {
		fmt.Printf("Get sighash failed: %v\n", err)
		return
	}
	fmt.Printf("Sighash: %x\n", hex.EncodeToString(sighash[:]))

	// Step 6: Sign
	privateKey, _ := crypto.ParsePrivateKeyWIF("KxYZ...") // TODO: Real key
	signedBytes, err := api.AppendSignature(provedBytes, 0, privateKey)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}
	fmt.Printf("Signed PCZT (%d bytes)\n", len(signedBytes))

	// Step 7: Extract final transaction
	txBytes, err := api.FinalizeAndExtract(signedBytes)
	if err != nil {
		fmt.Printf("Extraction failed: %v\n", err)
		return
	}
	fmt.Printf("Final transaction: %x\n", hex.EncodeToString(txBytes))
}
