package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dvstc/imprint"
)

func TestRequireMTLSNoCert(t *testing.T) {
	store := NewMemStore()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	// Request with no TLS at all
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for no TLS, got %d", w.Code)
	}
}

func TestRequireMTLSEmptyPeerCerts(t *testing.T) {
	store := NewMemStore()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty peer certs, got %d", w.Code)
	}
}

func TestRequireMTLSValidCert(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()

	// Create an enrollment
	csr, _ := createTestCSR(t)
	certPEM, serialHex, _ := ca.SignCSR(csr, "srv_valid")

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     "srv_valid",
		Fingerprint:  "sha256:test",
		SerialNumber: serialHex,
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now(),
	})

	// Parse the cert for the TLS state
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	var receivedIdentity *imprint.Enrollment
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedIdentity = ServerIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if receivedIdentity == nil {
		t.Fatal("ServerIdentity should be set in context")
	}
	if receivedIdentity.ServerID != "srv_valid" {
		t.Fatalf("expected server_id 'srv_valid', got %q", receivedIdentity.ServerID)
	}
}

func TestRequireMTLSRevokedCert(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()

	csr, _ := createTestCSR(t)
	certPEM, serialHex, _ := ca.SignCSR(csr, "srv_revoked")

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     "srv_revoked",
		Fingerprint:  "sha256:revoked",
		SerialNumber: serialHex,
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now(),
	})

	// Revoke it
	store.Revoke(nil, "srv_revoked")

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked cert, got %d", w.Code)
	}
}

func TestRequireMTLSMissingCN(t *testing.T) {
	store := NewMemStore()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	// Cert with empty CN
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing CN, got %d", w.Code)
	}
}

func TestRequireMTLSSupersededSerial(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()

	csr, _ := createTestCSR(t)
	certPEM, _, _ := ca.SignCSR(csr, "srv_superseded")

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     "srv_superseded",
		Fingerprint:  "sha256:test",
		SerialNumber: "different_serial",
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now(),
	})

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for superseded cert, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRequireMTLSUnknownDevice(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()

	csr, _ := createTestCSR(t)
	certPEM, _, _ := ca.SignCSR(csr, "srv_not_enrolled")

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown device, got %d", w.Code)
	}
}

func TestRequireMTLSCertExpiresHeader(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()

	csr, _ := createTestCSR(t)
	certPEM, serialHex, _ := ca.SignCSR(csr, "srv_header")

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     "srv_header",
		Fingerprint:  "sha256:test",
		SerialNumber: serialHex,
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now(),
	})

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireMTLS(store, inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	expiresHeader := w.Header().Get("X-Imprint-Cert-Expires")
	if expiresHeader == "" {
		t.Fatal("X-Imprint-Cert-Expires header not set")
	}
	if _, err := time.Parse(time.RFC3339, expiresHeader); err != nil {
		t.Fatalf("invalid RFC3339 in X-Imprint-Cert-Expires: %s", expiresHeader)
	}
}

func TestServerIdentityNilWhenNoContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	identity := ServerIdentity(req.Context())
	if identity != nil {
		t.Fatal("expected nil identity when no mTLS context")
	}
}
