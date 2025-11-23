// Package zip321 implements the ZIP 321 payment request URI format.
//
// ZIP 321 defines a standardized URI format for Zcash payment requests,
// similar to Bitcoin's BIP 21. It allows encoding payment information
// (recipient addresses, amounts, memos) in a URI that can be shared
// via QR codes, links, or text.
//
// URI Format:
//   zcash:<address>?amount=<amount>&memo=<memo>&message=<message>
//
// Multiple recipients are supported with indexed parameters:
//   zcash:?address.1=<addr1>&amount.1=<amt1>&address.2=<addr2>&amount.2=<amt2>
//
// See: https://zips.z.cash/zip-0321
// Corresponds to: librustzcash/components/zcash_address/src/kind/unified.rs
//   (for address parsing) and various wallet implementations for ZIP 321
package zip321

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// PaymentRequest represents a parsed ZIP 321 payment request.
//
// A payment request can have multiple recipients (payments), each with
// their own address, amount, and memo.
type PaymentRequest struct {
	Payments []Payment // List of payment recipients
}

// Payment represents a single payment within a ZIP 321 request.
//
// Each payment specifies:
//   - Address: Zcash address (transparent, Sapling, or Orchard unified address)
//   - Amount: Value in ZEC (can be nil for user-specified amount)
//   - Memo: Optional memo field (512 bytes max for shielded recipients)
//   - Label: Optional label for the recipient
//   - Message: Optional message to the user
type Payment struct {
	Address string   // Zcash address (t-addr, z-addr, or unified address)
	Amount  *float64 // Amount in ZEC (nil = user specifies)
	Memo    *string  // Optional memo (base64-encoded or plain text)
	Label   *string  // Optional label for recipient
	Message *string  // Optional message to display to user
}

// Parse parses a ZIP 321 payment request URI.
//
// URI formats supported:
//   1. Single recipient: zcash:<address>?amount=1.5&memo=hello
//   2. Multiple recipients: zcash:?address.1=addr1&amount.1=1.0&address.2=addr2&amount.2=2.0
//   3. No address (user specifies): zcash:?amount=1.5
//
// Parameters:
//   - uri: The ZIP 321 URI string (with or without "zcash:" prefix)
//
// Returns:
//   - PaymentRequest with one or more payments
//   - Error if URI is malformed or invalid
//
// Example:
//   req, err := zip321.Parse("zcash:tmFooBar123?amount=1.5&memo=coffee")
func Parse(uri string) (*PaymentRequest, error) {
	// Strip "zcash:" prefix if present
	uri = strings.TrimPrefix(uri, "zcash:")

	// Split into address and query components
	parts := strings.SplitN(uri, "?", 2)

	var baseAddress string
	var query string

	if len(parts) == 2 {
		baseAddress = parts[0]
		query = parts[1]
	} else if len(parts) == 1 {
		// Check if it's just an address or just a query
		if strings.Contains(parts[0], "=") {
			// It's a query without base address
			query = parts[0]
		} else {
			// It's just an address
			baseAddress = parts[0]
		}
	}

	// Parse query parameters
	params, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %w", err)
	}

	// Check if this is a multi-recipient request (has indexed parameters)
	isMultiRecipient := hasIndexedParams(params)

	var payments []Payment

	if isMultiRecipient {
		// Parse multiple recipients using indexed parameters
		payments, err = parseIndexedPayments(params)
		if err != nil {
			return nil, err
		}
	} else {
		// Single recipient (possibly with base address)
		payment, err := parseSinglePayment(baseAddress, params)
		if err != nil {
			return nil, err
		}
		payments = []Payment{payment}
	}

	if len(payments) == 0 {
		return nil, fmt.Errorf("no payments found in URI")
	}

	return &PaymentRequest{
		Payments: payments,
	}, nil
}

// parseSinglePayment parses a single-recipient payment request.
func parseSinglePayment(address string, params url.Values) (Payment, error) {
	payment := Payment{
		Address: address,
	}

	// Parse address (might be in params instead of base)
	if addrParam := params.Get("address"); addrParam != "" {
		payment.Address = addrParam
	}

	// Parse amount
	if amountStr := params.Get("amount"); amountStr != "" {
		amount, err := parseAmount(amountStr)
		if err != nil {
			return payment, fmt.Errorf("invalid amount: %w", err)
		}
		payment.Amount = &amount
	}

	// Parse memo
	if memo := params.Get("memo"); memo != "" {
		payment.Memo = &memo
	}

	// Parse label
	if label := params.Get("label"); label != "" {
		payment.Label = &label
	}

	// Parse message
	if message := params.Get("message"); message != "" {
		payment.Message = &message
	}

	return payment, nil
}

// parseIndexedPayments parses multiple recipients using indexed parameters.
//
// Format: address.1=addr1&amount.1=1.0&address.2=addr2&amount.2=2.0
//
// ZIP 321 allows indices from 0-9999. Index 0 can be written without suffix.
func parseIndexedPayments(params url.Values) ([]Payment, error) {
	payments := make(map[int]Payment)

	// Find all unique indices
	indices := make(map[int]bool)
	for key := range params {
		if idx := extractIndex(key); idx >= 0 {
			indices[idx] = true
		}
	}

	// Parse payment for each index
	for idx := range indices {
		payment := Payment{}

		// Get address
		address := getIndexedParam(params, "address", idx)
		if address == "" {
			return nil, fmt.Errorf("payment %d missing address", idx)
		}
		payment.Address = address

		// Get amount (optional)
		if amountStr := getIndexedParam(params, "amount", idx); amountStr != "" {
			amount, err := parseAmount(amountStr)
			if err != nil {
				return nil, fmt.Errorf("payment %d invalid amount: %w", idx, err)
			}
			payment.Amount = &amount
		}

		// Get memo (optional)
		if memo := getIndexedParam(params, "memo", idx); memo != "" {
			payment.Memo = &memo
		}

		// Get label (optional)
		if label := getIndexedParam(params, "label", idx); label != "" {
			payment.Label = &label
		}

		// Get message (optional)
		if message := getIndexedParam(params, "message", idx); message != "" {
			payment.Message = &message
		}

		payments[idx] = payment
	}

	// Convert to ordered slice
	result := make([]Payment, 0, len(payments))
	for i := 0; i < 10000; i++ {
		if payment, exists := payments[i]; exists {
			result = append(result, payment)
		}
	}

	return result, nil
}

// hasIndexedParams checks if the query contains indexed parameters.
//
// Indexed parameters have format "name.N" where N is 0-9999.
func hasIndexedParams(params url.Values) bool {
	for key := range params {
		if strings.Contains(key, ".") {
			return true
		}
	}
	return false
}

// extractIndex extracts the index from a parameter name.
//
// Examples:
//   - "address.1" -> 1
//   - "amount.42" -> 42
//   - "address" -> -1 (no index)
//   - "memo.0" -> 0
//
// Returns -1 if no index found.
func extractIndex(paramName string) int {
	parts := strings.Split(paramName, ".")
	if len(parts) != 2 {
		return -1
	}

	idx, err := strconv.Atoi(parts[1])
	if err != nil {
		return -1
	}

	if idx < 0 || idx > 9999 {
		return -1
	}

	return idx
}

// getIndexedParam gets a parameter value for a specific index.
//
// For index 0, tries both "name" and "name.0".
// For other indices, tries "name.N".
func getIndexedParam(params url.Values, name string, index int) string {
	if index == 0 {
		// Index 0 can be written without suffix
		if val := params.Get(name); val != "" {
			return val
		}
	}

	// Try with index suffix
	return params.Get(fmt.Sprintf("%s.%d", name, index))
}

// parseAmount parses a ZEC amount string.
//
// Valid formats:
//   - "1.5" (decimal ZEC)
//   - "0.001" (small amounts)
//   - "1000" (whole ZEC)
//
// Amounts must be non-negative.
func parseAmount(amountStr string) (float64, error) {
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		return 0, fmt.Errorf("not a valid number: %w", err)
	}

	if amount < 0 {
		return 0, fmt.Errorf("amount cannot be negative")
	}

	return amount, nil
}

// ============================================================================
// Helper functions for creating ZIP 321 URIs
// ============================================================================

// Encode creates a ZIP 321 URI from a PaymentRequest.
//
// This is the inverse of Parse(). It creates a properly formatted URI
// that can be shared or encoded in a QR code.
//
// Example:
//   req := &PaymentRequest{
//       Payments: []Payment{
//           {Address: "tmFoo123", Amount: ptr(1.5), Memo: ptr("coffee")},
//       },
//   }
//   uri := req.Encode() // "zcash:tmFoo123?amount=1.5&memo=coffee"
func (req *PaymentRequest) Encode() string {
	if len(req.Payments) == 0 {
		return "zcash:"
	}

	if len(req.Payments) == 1 {
		// Single recipient - use simple format
		return encodeSinglePayment(req.Payments[0])
	}

	// Multiple recipients - use indexed format
	return encodeMultiplePayments(req.Payments)
}

// encodeSinglePayment encodes a single payment as a URI.
func encodeSinglePayment(p Payment) string {
	uri := "zcash:" + p.Address

	params := url.Values{}
	if p.Amount != nil {
		params.Add("amount", formatAmount(*p.Amount))
	}
	if p.Memo != nil {
		params.Add("memo", *p.Memo)
	}
	if p.Label != nil {
		params.Add("label", *p.Label)
	}
	if p.Message != nil {
		params.Add("message", *p.Message)
	}

	if len(params) > 0 {
		uri += "?" + params.Encode()
	}

	return uri
}

// encodeMultiplePayments encodes multiple payments with indexed parameters.
func encodeMultiplePayments(payments []Payment) string {
	params := url.Values{}

	for i, p := range payments {
		idx := fmt.Sprintf(".%d", i)

		params.Add("address"+idx, p.Address)

		if p.Amount != nil {
			params.Add("amount"+idx, formatAmount(*p.Amount))
		}
		if p.Memo != nil {
			params.Add("memo"+idx, *p.Memo)
		}
		if p.Label != nil {
			params.Add("label"+idx, *p.Label)
		}
		if p.Message != nil {
			params.Add("message"+idx, *p.Message)
		}
	}

	return "zcash:?" + params.Encode()
}

// formatAmount formats a ZEC amount for URI encoding.
//
// Removes unnecessary trailing zeros and decimal point.
func formatAmount(amount float64) string {
	// Format with up to 8 decimal places (ZEC precision)
	str := strconv.FormatFloat(amount, 'f', 8, 64)

	// Remove trailing zeros
	str = strings.TrimRight(str, "0")
	str = strings.TrimRight(str, ".")

	return str
}
