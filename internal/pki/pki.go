package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"mock-oidc/internal/logger"
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
	log := logger.Get()
	log.Info("Starting ECDSA key pair generation", "curve", "P-256")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error("Failed to generate ECDSA private key", "error", err, "curve", "P-256")
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	kid := generateKid()
	log.Debug("Generated key ID", "kid", kid)

	keyPair := &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        kid,
	}

	log.Info("ECDSA key pair generated successfully",
		"kid", kid,
		"curve", "P-256",
		"algorithm", "ES256",
	)

	return keyPair, nil
}

// GetJWKS returns the JSON Web Key Set for the key pair
func (kp *KeyPair) GetJWKS() JWKS {
	log := logger.Get()
	log.Debug("Generating JWKS", "kid", kp.Kid)

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

	jwks := JWKS{
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

	log.Debug("JWKS generated successfully",
		"kid", kp.Kid,
		"key_count", len(jwks.Keys),
		"curve", "P-256",
		"algorithm", "ES256",
	)

	return jwks
}

// generateKid generates a random key ID
func generateKid() string {
	log := logger.Get()

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Error("Failed to generate random KID", "error", err)
		panic("failed to generate random kid: " + err.Error())
	}

	kid := fmt.Sprintf("%x", b)
	log.Debug("Generated random KID", "kid", kid)

	return kid
}
