package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yasindce1998/warmor/internal/crypto"
)

type certsModel struct {
	message string
	err     error
	cursor  int
}

type certGenMsg struct{ message string }

func newCertsModel() *certsModel {
	return &certsModel{}
}

func (m *certsModel) Init() tea.Cmd {
	m.message = ""
	m.err = nil
	return nil
}

func (m *certsModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case certGenMsg:
		m.message = msg.message
		m.err = nil
	case errMsg:
		m.err = msg.err
	case tea.KeyMsg:
		switch msg.String() {
		case "g":
			return m.generateCA
		case "s":
			return m.generateSigningKey
		case "j", "down":
			if m.cursor < 1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		}
	}
	return nil
}

func (m *certsModel) View() string {
	var sb strings.Builder

	sb.WriteString(headerStyle.Render("Certificate & Key Management"))
	sb.WriteString("\n\n")

	actions := []string{
		"Generate CA + server/agent certs",
		"Generate policy signing key pair",
	}

	for i, action := range actions {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		key := []string{"g", "s"}[i]
		sb.WriteString(fmt.Sprintf("%s[%s] %s\n", prefix, key, action))
	}

	sb.WriteString("\n")

	if m.err != nil {
		sb.WriteString(errorStyle.Render(fmt.Sprintf("  Error: %v", m.err)))
	} else if m.message != "" {
		sb.WriteString(successStyle.Render(m.message))
	} else {
		sb.WriteString(dimStyle.Render("  Press g or s to generate keys"))
	}

	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("  Output directory: ./warmor-certs/"))

	return sb.String()
}

func (m *certsModel) generateCA() tea.Msg {
	dir := "warmor-certs"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errMsg{err}
	}

	ca, err := crypto.GenerateCA(crypto.CertConfig{
		CommonName: "warmor-ca",
	})
	if err != nil {
		return errMsg{err}
	}

	if err := crypto.WritePEM(filepath.Join(dir, "ca.crt"), ca.CertPEM); err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "ca.key"), ca.KeyPEM); err != nil {
		return errMsg{err}
	}

	serverCert, serverKey, err := ca.IssueCert(crypto.CertConfig{
		CommonName: "warmor-server",
		DNSNames:   []string{"localhost", "warmor-server"},
	})
	if err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "server.crt"), serverCert); err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "server.key"), serverKey); err != nil {
		return errMsg{err}
	}

	agentCert, agentKey, err := ca.IssueCert(crypto.CertConfig{
		CommonName: "warmor-agent",
	})
	if err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "agent.crt"), agentCert); err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "agent.key"), agentKey); err != nil {
		return errMsg{err}
	}

	return certGenMsg{
		message: fmt.Sprintf("  Generated in %s/:\n    ca.crt, ca.key\n    server.crt, server.key\n    agent.crt, agent.key", dir),
	}
}

func (m *certsModel) generateSigningKey() tea.Msg {
	dir := "warmor-certs"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errMsg{err}
	}

	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		return errMsg{err}
	}

	privPEM, err := sk.MarshalPrivateKey()
	if err != nil {
		return errMsg{err}
	}
	pubPEM, err := sk.MarshalPublicKey()
	if err != nil {
		return errMsg{err}
	}

	if err := crypto.WritePEM(filepath.Join(dir, "signing.key"), privPEM); err != nil {
		return errMsg{err}
	}
	if err := crypto.WritePEM(filepath.Join(dir, "signing.pub"), pubPEM); err != nil {
		return errMsg{err}
	}

	return certGenMsg{
		message: fmt.Sprintf("  Generated in %s/:\n    signing.key (private)\n    signing.pub (public)", dir),
	}
}
