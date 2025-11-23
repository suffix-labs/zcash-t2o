// Package crypto implements secp256k1 ECDSA signing for transparent inputs.
//
// Transparent inputs in Zcash use Bitcoin-style secp256k1 ECDSA signatures.
// This package provides key management and signature operations.
//
// Key formats:
//   - Private keys: WIF (Wallet Import Format) or raw 32 bytes
//   - Public keys: Compressed 33-byte format (0x02/0x03 prefix + x-coordinate)
//   - Signatures: DER-encoded
//
// This corresponds to Bitcoin's signing infrastructure and is compatible with
// Zcash transparent addresses.
package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// PrivateKey wraps secp256k1 private key
type PrivateKey struct {
	key *secp256k1.PrivateKey
}

// PublicKey wraps secp256k1 public key
type PublicKey struct {
	key *secp256k1.PublicKey
}

// ParsePrivateKeyWIF parses a WIF-encoded private key
func ParsePrivateKeyWIF(wif string) (*PrivateKey, error) {
	decoded, err := decodeWIF(wif)
	if err != nil {
		return nil, err
	}

	key := secp256k1.PrivKeyFromBytes(decoded)
	return &PrivateKey{key: key}, nil
}

// PrivateKeyFromBytes creates a private key from raw bytes
func PrivateKeyFromBytes(keyBytes []byte) (*PrivateKey, error) {
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(keyBytes))
	}

	key := secp256k1.PrivKeyFromBytes(keyBytes)
	return &PrivateKey{key: key}, nil
}

// Sign creates an ECDSA signature
func (pk *PrivateKey) Sign(hash [32]byte) ([]byte, error) {
	sig := ecdsa.Sign(pk.key, hash[:])

	// Serialize to DER format
	return sig.Serialize(), nil
}

// PublicKey derives the public key
func (pk *PrivateKey) PublicKey() *PublicKey {
	pubKey := pk.key.PubKey()
	return &PublicKey{key: pubKey}
}

// Bytes returns the raw 32-byte private key
func (pk *PrivateKey) Bytes() []byte {
	return pk.key.Serialize()
}

// SerializeCompressed returns the 33-byte compressed public key
func (pub *PublicKey) SerializeCompressed() [33]byte {
	var result [33]byte
	copy(result[:], pub.key.SerializeCompressed())
	return result
}

// Bytes returns the compressed public key bytes
func (pub *PublicKey) Bytes() []byte {
	return pub.key.SerializeCompressed()
}

// ParsePublicKey parses a compressed public key
func ParsePublicKey(pubKeyBytes []byte) (*PublicKey, error) {
	if len(pubKeyBytes) != 33 {
		return nil, fmt.Errorf("compressed public key must be 33 bytes, got %d", len(pubKeyBytes))
	}

	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &PublicKey{key: pubKey}, nil
}

// VerifySignature verifies an ECDSA signature
func VerifySignature(pubkey *PublicKey, hash [32]byte, signature []byte) bool {
	sig, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false
	}

	return sig.Verify(hash[:], pubkey.key)
}

// decodeWIF decodes a WIF-encoded private key
// WIF format: version_byte || private_key (32 bytes) || [compression_flag] || checksum (4 bytes)
func decodeWIF(wif string) ([]byte, error) {
	// Decode base58
	decoded := base58.Decode(wif)
	if len(decoded) != 37 && len(decoded) != 38 {
		return nil, errors.New("invalid WIF length")
	}

	// Check version byte (0x80 for mainnet, 0xef for testnet)
	version := decoded[0]
	if version != 0x80 && version != 0xef {
		return nil, fmt.Errorf("invalid WIF version byte: 0x%02x", version)
	}

	// Extract checksum (last 4 bytes)
	checksumOffset := len(decoded) - 4
	providedChecksum := decoded[checksumOffset:]
	payload := decoded[:checksumOffset]

	// Compute checksum
	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	computedChecksum := hash2[:4]

	// Verify checksum
	for i := 0; i < 4; i++ {
		if providedChecksum[i] != computedChecksum[i] {
			return nil, errors.New("WIF checksum mismatch")
		}
	}

	// Extract private key (32 bytes after version byte)
	privateKey := payload[1:33]
	return privateKey, nil
}

// EncodeWIF encodes a private key to WIF format
func EncodeWIF(privateKey []byte, compressed bool, testnet bool) (string, error) {
	if len(privateKey) != 32 {
		return "", errors.New("private key must be 32 bytes")
	}

	// Version byte
	version := byte(0x80) // mainnet
	if testnet {
		version = 0xef // testnet
	}

	// Build payload: version || private_key || [compression_flag]
	var payload []byte
	payload = append(payload, version)
	payload = append(payload, privateKey...)
	if compressed {
		payload = append(payload, 0x01)
	}

	// Compute checksum
	hash1 := sha256.Sum256(payload)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Append checksum
	payload = append(payload, checksum...)

	// Encode to base58
	return base58.Encode(payload), nil
}
