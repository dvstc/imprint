package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/dvstc/imprint"
	"github.com/dvstc/imprint/server"
)

func TestSaveAndLoadEnrollment(t *testing.T) {
	dir := t.TempDir()

	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----\n")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")

	err := SaveEnrollment(dir, keyPEM, certPEM, caPEM, "srv_123", "sha256:fp")
	if err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	if !IsEnrolled(dir) {
		t.Fatal("IsEnrolled should return true after save")
	}

	meta, err := LoadMeta(dir)
	if err != nil {
		t.Fatalf("LoadMeta: %v", err)
	}
	if meta.ServerID != "srv_123" {
		t.Fatalf("expected server_id 'srv_123', got %q", meta.ServerID)
	}
	if meta.Fingerprint != "sha256:fp" {
		t.Fatalf("expected fingerprint 'sha256:fp', got %q", meta.Fingerprint)
	}
}

func TestIsEnrolledFalseWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	if IsEnrolled(dir) {
		t.Fatal("IsEnrolled should return false for empty dir")
	}
}

func TestSaveEnrollmentCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "path")

	err := SaveEnrollment(dir, []byte("k"), []byte("c"), []byte("ca"), "s", "f")
	if err != nil {
		t.Fatalf("SaveEnrollment should create nested dir: %v", err)
	}
	if !IsEnrolled(dir) {
		t.Fatal("should be enrolled after save to nested dir")
	}
}

func TestLoadTLSRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Generate a real keypair and self-signed cert for testing LoadTLS
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed cert (acts as both client cert and CA for this test)
	template := &x509.Certificate{
		SerialNumber: mustBigInt(t),
		Subject:      pkix.Name{CommonName: "test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := SaveEnrollment(dir, keyPEM, certPEM, certPEM, "srv_tls", "sha256:tls"); err != nil {
		t.Fatal(err)
	}

	tlsCfg, err := LoadTLS(dir)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}

	if len(tlsCfg.Certificates) != 1 {
		t.Fatal("expected exactly 1 client certificate")
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("RootCAs should not be nil")
	}
	if tlsCfg.MinVersion != 0x0303 {
		t.Fatalf("expected TLS 1.2 min version, got %d", tlsCfg.MinVersion)
	}
}

func TestLoadTLSMissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadTLS(dir)
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

func TestEnrollEndToEnd(t *testing.T) {
	caDir := t.TempDir()
	ca, err := server.NewCA(server.CAConfig{CertDir: caDir, Organization: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	store := server.NewMemStore()
	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{"test-secret"},
		Mode:         imprint.ModeAuto,
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	storeDir := t.TempDir()
	resp, err := Enroll(context.Background(), EnrollConfig{
		ServiceURL:  ts.URL,
		BuildSecret: "test-secret",
		Fingerprint: "sha256:e2e-test",
		Hostname:    "e2e-host",
		StoreDir:    storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if resp.ServerID == "" {
		t.Fatal("expected a server_id")
	}
	if resp.Certificate == "" {
		t.Fatal("expected a certificate")
	}

	// Files should be persisted
	if !IsEnrolled(storeDir) {
		t.Fatal("should be enrolled after successful Enroll()")
	}

	meta, _ := LoadMeta(storeDir)
	if meta.ServerID != resp.ServerID {
		t.Fatalf("persisted server_id doesn't match: %s vs %s", meta.ServerID, resp.ServerID)
	}
}

func TestEnrollInvalidSecret(t *testing.T) {
	caDir := t.TempDir()
	ca, _ := server.NewCA(server.CAConfig{CertDir: caDir})
	store := server.NewMemStore()
	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{"correct"},
		Mode:         imprint.ModeAuto,
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	_, err := Enroll(context.Background(), EnrollConfig{
		ServiceURL:  ts.URL,
		BuildSecret: "wrong",
		Fingerprint: "sha256:test",
		StoreDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error for wrong build secret")
	}
}

func TestEnrollResponseJSON(t *testing.T) {
	// Test that EnrollmentResponse JSON serialization works
	resp := imprint.EnrollmentResponse{
		ServerID:      "srv_abc",
		Certificate:   "cert-pem",
		CACertificate: "ca-pem",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var decoded imprint.EnrollmentResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ServerID != resp.ServerID {
		t.Fatal("JSON round-trip failed")
	}
}

func mustBigInt(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
