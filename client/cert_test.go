package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := SaveEnrollment(dir, keyPEM, certPEM, certPEM, "srv_test", "sha256:fp"); err != nil {
		t.Fatalf("save test cert: %v", err)
	}
}

func TestCertExpiry(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(90 * 24 * time.Hour)
	writeTestCert(t, dir, expiry)

	got, err := CertExpiry(dir)
	if err != nil {
		t.Fatalf("CertExpiry: %v", err)
	}
	diff := got.Sub(expiry)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Fatalf("expiry mismatch: expected ~%v, got %v", expiry, got)
	}
}

func TestNeedsRenewalTrue(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, time.Now().Add(10*24*time.Hour))

	needs, err := NeedsRenewal(dir, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !needs {
		t.Fatal("should need renewal when expiry is within threshold")
	}
}

func TestNeedsRenewalFalse(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, time.Now().Add(90*24*time.Hour))

	needs, err := NeedsRenewal(dir, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needs {
		t.Fatal("should not need renewal when expiry is far away")
	}
}

func TestNeedsRenewalExpiredReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, time.Now().Add(-1*time.Hour))

	needs, err := NeedsRenewal(dir, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needs {
		t.Fatal("NeedsRenewal should return false for expired cert (use IsExpired)")
	}
}

func TestIsExpiredTrue(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, time.Now().Add(-1*time.Hour))

	expired, err := IsExpired(dir)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if !expired {
		t.Fatal("should be expired")
	}
}

func TestIsExpiredFalse(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, time.Now().Add(90*24*time.Hour))

	expired, err := IsExpired(dir)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if expired {
		t.Fatal("should not be expired")
	}
}

func TestLoadCertMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCert(dir)
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}
