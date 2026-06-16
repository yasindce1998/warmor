package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// SigningKey holds an ed25519 key pair for signing policy bundles.
type SigningKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateSigningKey creates a new ed25519 key pair for policy signing.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &SigningKey{Public: pub, Private: priv}, nil
}

// Sign produces an ed25519 signature over the given data.
func (sk *SigningKey) Sign(data []byte) []byte {
	return ed25519.Sign(sk.Private, data)
}

// Verify checks that sig is a valid signature of data by this key.
func (sk *SigningKey) Verify(data, sig []byte) bool {
	return ed25519.Verify(sk.Public, data, sig)
}

// VerifyWithPublicKey checks a signature using a standalone public key.
func VerifyWithPublicKey(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}

// MarshalPrivateKey encodes the private key as PKCS8 PEM.
func (sk *SigningKey) MarshalPrivateKey() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(sk.Private)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKey encodes the public key as PKIX PEM.
func (sk *SigningKey) MarshalPublicKey() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(sk.Public)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadSigningKey loads a signing key pair from PEM files.
func LoadSigningKey(privPath string) (*SigningKey, error) {
	data, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return LoadSigningKeyFromPEM(data)
}

// LoadSigningKeyFromPEM parses a private key PEM into a SigningKey.
func LoadSigningKeyFromPEM(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := keyIface.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &SigningKey{
		Public:  pub,
		Private: priv,
	}, nil
}

// LoadPublicKey loads an ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return LoadPublicKeyFromPEM(data)
}

// LoadPublicKeyFromPEM parses a public key PEM into an ed25519 public key.
func LoadPublicKeyFromPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	keyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := keyIface.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519")
	}
	return pub, nil
}

// SignedPolicy represents a WASM policy with its cryptographic signature.
type SignedPolicy struct {
	WASMData  []byte `json:"wasm_data"`
	Signature []byte `json:"signature"`
	PolicyID  string `json:"policy_id"`
	Version   int64  `json:"version"`
}

// SignPolicy signs a WASM binary and returns a SignedPolicy bundle.
func SignPolicy(sk *SigningKey, policyID string, version int64, wasmData []byte) *SignedPolicy {
	sig := sk.Sign(wasmData)
	return &SignedPolicy{
		WASMData:  wasmData,
		Signature: sig,
		PolicyID:  policyID,
		Version:   version,
	}
}

// VerifyPolicy checks that a signed policy's signature is valid.
func VerifyPolicy(pub ed25519.PublicKey, sp *SignedPolicy) bool {
	return VerifyWithPublicKey(pub, sp.WASMData, sp.Signature)
}
