package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Kid        string
}

// JWKS represents the JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
}

// GenerateKeyPair generates a new ECDSA key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        generateKid(),
	}, nil
}

// GetJWKS returns the JSON Web Key Set for the key pair
func (kp *KeyPair) GetJWKS() JWKS {
	// Convert big.Int coordinates to bytes and then to Base64URL
	xBytes := kp.PublicKey.X.Bytes()
	yBytes := kp.PublicKey.Y.Bytes()

	// Ensure proper byte length for P-256 (32 bytes)
	if len(xBytes) < 32 {
		xBytes = append(make([]byte, 32-len(xBytes)), xBytes...)
	}
	if len(yBytes) < 32 {
		yBytes = append(make([]byte, 32-len(yBytes)), yBytes...)
	}

	return JWKS{
		Keys: []JWK{
			{
				Kid:    kp.Kid,
				Kty:    "EC",
				Crv:    "P-256",
				X:      base64.RawURLEncoding.EncodeToString(xBytes),
				Y:      base64.RawURLEncoding.EncodeToString(yBytes),
				Use:    "sig",
				Alg:    "ES256",
				KeyOps: []string{"verify"},
			},
		},
	}
}

// generateKid generates a random key ID
func generateKid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random kid: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}
