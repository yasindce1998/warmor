package crypto

import (
	"testing"
)

func TestGenerateSigningKey(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk.Private) != 64 {
		t.Errorf("expected 64-byte private key, got %d", len(sk.Private))
	}
	if len(sk.Public) != 32 {
		t.Errorf("expected 32-byte public key, got %d", len(sk.Public))
	}
}

func TestSignVerify(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("warmor policy binary content")
	sig := sk.Sign(data)

	if !sk.Verify(data, sig) {
		t.Error("valid signature rejected")
	}
	if sk.Verify([]byte("tampered"), sig) {
		t.Error("tampered data accepted")
	}
	if sk.Verify(data, []byte("badsig")) {
		t.Error("bad signature accepted")
	}
}

func TestVerifyWithPublicKey(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test payload")
	sig := sk.Sign(data)

	if !VerifyWithPublicKey(sk.Public, data, sig) {
		t.Error("standalone verify failed")
	}
}

func TestMarshalRoundtrip(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	privPEM, err := sk.MarshalPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSigningKeyFromPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("roundtrip test")
	sig := sk.Sign(data)
	if !loaded.Verify(data, sig) {
		t.Error("loaded key cannot verify original signature")
	}
}

func TestMarshalPublicKey(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, err := sk.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := LoadPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("public key roundtrip")
	sig := sk.Sign(data)
	if !VerifyWithPublicKey(pub, data, sig) {
		t.Error("loaded public key verify failed")
	}
}

func TestSignPolicy(t *testing.T) {
	sk, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	wasmData := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	sp := SignPolicy(sk, "deny-network", 1, wasmData)

	if sp.PolicyID != "deny-network" {
		t.Errorf("expected policy_id deny-network, got %s", sp.PolicyID)
	}
	if sp.Version != 1 {
		t.Errorf("expected version 1, got %d", sp.Version)
	}
	if !VerifyPolicy(sk.Public, sp) {
		t.Error("policy signature verification failed")
	}

	sp.WASMData[0] = 0xFF
	if VerifyPolicy(sk.Public, sp) {
		t.Error("tampered policy passed verification")
	}
}
