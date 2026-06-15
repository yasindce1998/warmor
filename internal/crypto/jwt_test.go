package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestJWTIssuerRoundtrip(t *testing.T) {
	issuer := NewJWTIssuer([]byte("test-secret-key-32bytes-long!!!!"))

	token, err := issuer.Issue("admin@warmor", "admin", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := issuer.Validate(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Subject != "admin@warmor" {
		t.Errorf("expected subject admin@warmor, got %s", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role admin, got %s", claims.Role)
	}
}

func TestJWTExpired(t *testing.T) {
	issuer := NewJWTIssuer([]byte("secret"))

	token, err := issuer.Issue("user", "viewer", -1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = issuer.Validate(token)
	if err == nil {
		t.Error("expected expiry error")
	}
}

func TestJWTInvalidSignature(t *testing.T) {
	issuer1 := NewJWTIssuer([]byte("secret-1"))
	issuer2 := NewJWTIssuer([]byte("secret-2"))

	token, err := issuer1.Issue("user", "admin", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = issuer2.Validate(token)
	if err == nil {
		t.Error("expected signature error with wrong secret")
	}
}

func TestJWTMalformed(t *testing.T) {
	issuer := NewJWTIssuer([]byte("secret"))

	_, err := issuer.Validate("not.a.valid.token")
	if err == nil {
		t.Error("expected error for malformed token")
	}

	_, err = issuer.Validate("only-one-part")
	if err == nil {
		t.Error("expected error for single part token")
	}
}

func TestEd25519JWTRoundtrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewEd25519JWTIssuer(priv)

	token, err := issuer.Issue("agent-1", "agent", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := issuer.Validate(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Subject != "agent-1" {
		t.Errorf("expected subject agent-1, got %s", claims.Subject)
	}
	if claims.Role != "agent" {
		t.Errorf("expected role agent, got %s", claims.Role)
	}
}

func TestEd25519JWTWrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)

	issuer1 := NewEd25519JWTIssuer(priv1)
	issuer2 := NewEd25519JWTIssuer(priv2)

	token, err := issuer1.Issue("user", "admin", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = issuer2.Validate(token)
	if err == nil {
		t.Error("expected signature error with wrong key")
	}
}
