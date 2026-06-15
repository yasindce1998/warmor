package crypto

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA(CertConfig{
		CommonName: "warmor-test-ca",
		ValidFor:   24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("expected CA cert")
	}
	if ca.Cert.Subject.CommonName != "warmor-test-ca" {
		t.Errorf("expected CN=warmor-test-ca, got %s", ca.Cert.Subject.CommonName)
	}
	if len(ca.CertPEM) == 0 {
		t.Error("empty cert PEM")
	}
	if len(ca.KeyPEM) == 0 {
		t.Error("empty key PEM")
	}
}

func TestIssueCert(t *testing.T) {
	ca, err := GenerateCA(CertConfig{CommonName: "test-ca"})
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := ca.IssueCert(CertConfig{
		CommonName: "warmor-server",
		DNSNames:   []string{"localhost", "warmor.local"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		ValidFor:   1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM output")
	}

	// Should parse as valid TLS keypair
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("invalid keypair: %v", err)
	}
}

func TestLoadCAFromPEM(t *testing.T) {
	ca, err := GenerateCA(CertConfig{CommonName: "reload-ca"})
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadCAFromPEM(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cert.Subject.CommonName != "reload-ca" {
		t.Errorf("expected CN=reload-ca, got %s", loaded.Cert.Subject.CommonName)
	}
}

func TestMTLSConfig(t *testing.T) {
	ca, err := GenerateCA(CertConfig{CommonName: "mtls-ca"})
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverKey, err := ca.IssueCert(CertConfig{
		CommonName: "server",
		DNSNames:   []string{"localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey, err := ca.IssueCert(CertConfig{
		CommonName: "agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	serverTLS, err := NewServerTLSConfig(serverCert, serverKey, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("expected mTLS client auth")
	}
	if serverTLS.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}

	clientTLS, err := NewClientTLSConfig(clientCert, clientKey, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientTLS.Certificates) != 1 {
		t.Error("expected 1 client cert")
	}
}
