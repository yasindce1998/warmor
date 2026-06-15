package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTClaims holds the token payload fields.
type JWTClaims struct {
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Role      string `json:"role"`
}

// IsExpired returns true if the token is past its expiry.
func (c *JWTClaims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// JWTIssuer creates and validates JWT tokens using HMAC-SHA256.
type JWTIssuer struct {
	secret []byte
}

// NewJWTIssuer creates a JWT issuer with a shared secret.
func NewJWTIssuer(secret []byte) *JWTIssuer {
	return &JWTIssuer{secret: secret}
}

// Issue creates a signed JWT token.
func (j *JWTIssuer) Issue(subject, role string, ttl time.Duration) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := JWTClaims{
		Subject:   subject,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Role:      role,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	payload := headerB64 + "." + claimsB64
	sig := j.sign([]byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payload + "." + sigB64, nil
}

// Validate parses and verifies a JWT token, returning its claims.
func (j *JWTIssuer) Validate(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	expected := j.sign([]byte(payload))
	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if claims.IsExpired() {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func (j *JWTIssuer) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, j.secret)
	mac.Write(data)
	return mac.Sum(nil)
}

// Ed25519JWTIssuer creates and validates JWT tokens using Ed25519.
type Ed25519JWTIssuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewEd25519JWTIssuer creates a JWT issuer using ed25519 keys.
func NewEd25519JWTIssuer(priv ed25519.PrivateKey) *Ed25519JWTIssuer {
	return &Ed25519JWTIssuer{
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

// Issue creates an Ed25519-signed JWT.
func (j *Ed25519JWTIssuer) Issue(subject, role string, ttl time.Duration) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	claims := JWTClaims{
		Subject:   subject,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Role:      role,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	payload := headerB64 + "." + claimsB64
	sig := ed25519.Sign(j.priv, []byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payload + "." + sigB64, nil
}

// Validate verifies an Ed25519-signed JWT and returns claims.
func (j *Ed25519JWTIssuer) Validate(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(j.pub, []byte(payload), sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if claims.IsExpired() {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}
