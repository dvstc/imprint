package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCAGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(CAConfig{
		CertDir:      dir,
		Organization: "Test Org",
	})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// CA cert and key should exist on disk
	if !fileExists(filepath.Join(dir, caCertFilename)) {
		t.Fatal("CA cert file not created")
	}
	if !fileExists(filepath.Join(dir, caKeyFilename)) {
		t.Fatal("CA key file not created")
	}

	// CACertPEM should return valid PEM
	block, _ := pem.Decode(ca.CACertPEM())
	if block == nil {
		t.Fatal("CACertPEM returned invalid PEM")
	}

	// Parsed cert should be a CA
	if !ca.cert.IsCA {
		t.Fatal("certificate is not a CA")
	}
	if ca.cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("expected org 'Test Org', got %v", ca.cert.Subject.Organization)
	}
}

func TestNewCALoadFromDisk(t *testing.T) {
	dir := t.TempDir()

	// Generate
	ca1, err := NewCA(CAConfig{CertDir: dir, Organization: "Persist Test"})
	if err != nil {
		t.Fatalf("NewCA (generate): %v", err)
	}

	// Load
	ca2, err := NewCA(CAConfig{CertDir: dir, Organization: "Persist Test"})
	if err != nil {
		t.Fatalf("NewCA (load): %v", err)
	}

	// Both should have the same CA cert
	if string(ca1.CACertPEM()) != string(ca2.CACertPEM()) {
		t.Fatal("loaded CA cert differs from generated CA cert")
	}
}

func TestCASignCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(CAConfig{CertDir: dir, Organization: "Sign Test"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	csr, _ := createTestCSR(t)
	certPEM, serialHex, err := ca.SignCSR(csr, "srv_test123")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if serialHex == "" {
		t.Fatal("serial hex should not be empty")
	}

	// Parse the signed cert
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("SignCSR returned invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}

	// CN should be the server ID
	if cert.Subject.CommonName != "srv_test123" {
		t.Fatalf("expected CN 'srv_test123', got %q", cert.Subject.CommonName)
	}

	// Should have client auth EKU
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Fatal("cert missing ClientAuth EKU")
	}

	// Should have imprint SAN URI
	if len(cert.URIs) == 0 {
		t.Fatal("cert has no SAN URIs")
	}
	uri := cert.URIs[0]
	if uri.Scheme != "imprint" || uri.Path != "/srv_test123" {
		t.Fatalf("unexpected SAN URI: %s", uri.String())
	}

	// Should be verifiable by CA cert pool
	pool := ca.CertPool()
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert verification failed: %v", err)
	}
}

func TestCASignCSRUniqueSerials(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})

	csr, _ := createTestCSR(t)
	_, serial1, _ := ca.SignCSR(csr, "srv1")
	_, serial2, _ := ca.SignCSR(csr, "srv2")

	if serial1 == serial2 {
		t.Fatal("two signed certs should have different serial numbers")
	}
}

func TestCASignCSRValidity(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{
		CertDir:  dir,
		Validity: 30 * 24 * time.Hour, // 30 days
	})

	csr, _ := createTestCSR(t)
	certPEM, _, _ := ca.SignCSR(csr, "srv_validity")

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Should expire roughly 30 days from now
	expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
	diff := cert.NotAfter.Sub(expectedExpiry)
	if diff < -1*time.Hour || diff > 1*time.Hour {
		t.Fatalf("cert expires at %v, expected around %v", cert.NotAfter, expectedExpiry)
	}
}

func TestCACertPool(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})

	pool := ca.CertPool()
	if pool == nil {
		t.Fatal("CertPool returned nil")
	}
}

func TestCAServerTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})

	cfg := ca.ServerTLSConfig()
	if cfg.ClientCAs == nil {
		t.Fatal("ServerTLSConfig: ClientCAs is nil")
	}
	if cfg.ClientAuth != 3 { // tls.VerifyClientCertIfGiven = 3
		t.Fatalf("expected VerifyClientCertIfGiven, got %d", cfg.ClientAuth)
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Fatalf("expected TLS 1.2 min, got %d", cfg.MinVersion)
	}
}

func TestNewCARequiresCertDir(t *testing.T) {
	_, err := NewCA(CAConfig{})
	if err == nil {
		t.Fatal("expected error for empty CertDir")
	}
}

func TestCAKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	NewCA(CAConfig{CertDir: dir})

	info, err := os.Stat(filepath.Join(dir, caKeyFilename))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("CA key file should not be empty")
	}
}

// createTestCSR generates a throwaway ECDSA key and CSR for testing.
func createTestCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-device",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr, key
}
