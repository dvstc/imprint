package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dvstc/imprint"
)

func setupRenewTest(t *testing.T) (*CA, *MemStore) {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCA(CAConfig{CertDir: dir, Organization: "Renew Test"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca, NewMemStore()
}

func enrollTestDevice(t *testing.T, ca *CA, store *MemStore, serverID, fingerprint string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csr, key)
	parsedCSR, _ := x509.ParseCertificateRequest(csrDER)

	certPEM, serialHex, err := ca.SignCSR(parsedCSR, serverID)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     serverID,
		Fingerprint:  fingerprint,
		SerialNumber: serialHex,
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now(),
	})

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert, key, serialHex
}

// --- Tier 1: mTLS Renewal Tests ---

func TestRenewHandlerSuccess(t *testing.T) {
	ca, store := setupRenewTest(t)
	cert, _, _ := enrollTestDevice(t, ca, store, "srv_renew", "sha256:fp1")

	handler := NewRenewHandler(RenewConfig{CA: ca, Store: store})

	csrPEM, _ := makeCSRPEM(t)
	body, _ := json.Marshal(imprint.RenewalRequest{CSR: csrPEM})

	req := httptest.NewRequest(http.MethodPost, "/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp imprint.EnrollmentResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ServerID != "srv_renew" {
		t.Fatalf("expected server_id 'srv_renew', got %q", resp.ServerID)
	}
	if resp.Certificate == "" {
		t.Fatal("expected a new certificate")
	}

	e, _ := store.GetByServerID(nil, "srv_renew")
	if e.RenewedAt.IsZero() {
		t.Fatal("RenewedAt should be set after renewal")
	}
}

func TestRenewHandlerRevokedRejected(t *testing.T) {
	ca, store := setupRenewTest(t)
	cert, _, _ := enrollTestDevice(t, ca, store, "srv_revoke", "sha256:fp2")
	store.Revoke(nil, "srv_revoke")

	handler := NewRenewHandler(RenewConfig{CA: ca, Store: store})

	csrPEM, _ := makeCSRPEM(t)
	body, _ := json.Marshal(imprint.RenewalRequest{CSR: csrPEM})

	req := httptest.NewRequest(http.MethodPost, "/renew", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked, got %d", w.Code)
	}
}

func TestRenewHandlerUnknownServerID(t *testing.T) {
	ca, store := setupRenewTest(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csr, key)
	parsedCSR, _ := x509.ParseCertificateRequest(csrDER)
	certPEM, _, _ := ca.SignCSR(parsedCSR, "srv_unknown")
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	handler := NewRenewHandler(RenewConfig{CA: ca, Store: store})

	csrPEM2, _ := makeCSRPEM(t)
	body, _ := json.Marshal(imprint.RenewalRequest{CSR: csrPEM2})

	req := httptest.NewRequest(http.MethodPost, "/renew", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown server, got %d", w.Code)
	}
}

func TestRenewHandlerNoCert(t *testing.T) {
	ca, store := setupRenewTest(t)
	handler := NewRenewHandler(RenewConfig{CA: ca, Store: store})

	req := httptest.NewRequest(http.MethodPost, "/renew", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// --- Tier 2: Challenge Renewal Tests ---

func makeChallengeRequest(t *testing.T, serverID, fingerprint string, oldKey *ecdsa.PrivateKey, expiredCert *x509.Certificate) ([]byte, string) {
	t.Helper()
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: serverID}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, newKey)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	expiredCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredCert.Raw}))

	digest := sha256.Sum256([]byte(serverID + "\n" + fingerprint + "\n" + csrPEM))
	sigBytes, err := oldKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	proof := base64.StdEncoding.EncodeToString(sigBytes)

	body, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID:    serverID,
		Fingerprint: fingerprint,
		ExpiredCert: expiredCertPEM,
		CSR:         csrPEM,
		Proof:       proof,
	})
	return body, csrPEM
}

func enrollExpiredDevice(t *testing.T, ca *CA, store *MemStore, serverID, fingerprint string, expiredAgo time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)

	serial := ca.nextSerial()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverID, Organization: ca.cert.Subject.Organization},
		NotBefore:    time.Now().Add(-30 * time.Minute),
		NotAfter:     time.Now().Add(-expiredAgo),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_ = csrDER
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create expired cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	serialHex := serial.Text(16)

	store.SaveEnrollment(nil, &imprint.Enrollment{
		ServerID:     serverID,
		Fingerprint:  fingerprint,
		SerialNumber: serialHex,
		Status:       imprint.StatusActive,
		EnrolledAt:   time.Now().Add(-30 * time.Minute),
	})

	return cert, key, serialHex
}

func TestChallengeRenewHandlerSuccess(t *testing.T) {
	ca, store := setupRenewTest(t)
	expiredCert, oldKey, _ := enrollExpiredDevice(t, ca, store, "srv_chal", "sha256:chal-fp", 5*time.Minute)

	handler := NewChallengeRenewHandler(ChallengeRenewConfig{
		CA: ca, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	body, _ := makeChallengeRequest(t, "srv_chal", "sha256:chal-fp", oldKey, expiredCert)

	req := httptest.NewRequest(http.MethodPost, "/renew/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp imprint.EnrollmentResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ServerID != "srv_chal" {
		t.Fatalf("unexpected server_id: %s", resp.ServerID)
	}

	e, _ := store.GetByServerID(nil, "srv_chal")
	if e.RenewedAt.IsZero() {
		t.Fatal("RenewedAt should be set after challenge renewal")
	}
}

func TestChallengeRenewBeyondWindow(t *testing.T) {
	ca, store := setupRenewTest(t)
	expiredCert, oldKey, _ := enrollExpiredDevice(t, ca, store, "srv_old", "sha256:old-fp", 60*24*time.Hour)

	handler := NewChallengeRenewHandler(ChallengeRenewConfig{
		CA: ca, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	body, _ := makeChallengeRequest(t, "srv_old", "sha256:old-fp", oldKey, expiredCert)

	req := httptest.NewRequest(http.MethodPost, "/renew/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for beyond window, got %d", w.Code)
	}
}

func TestChallengeRenewFingerprintMismatch(t *testing.T) {
	ca, store := setupRenewTest(t)
	expiredCert, oldKey, _ := enrollExpiredDevice(t, ca, store, "srv_fpm", "sha256:real-fp", 5*time.Minute)

	handler := NewChallengeRenewHandler(ChallengeRenewConfig{
		CA: ca, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	body, _ := makeChallengeRequest(t, "srv_fpm", "sha256:wrong-fp", oldKey, expiredCert)

	req := httptest.NewRequest(http.MethodPost, "/renew/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for fingerprint mismatch, got %d", w.Code)
	}
}

func TestChallengeRenewBadSignature(t *testing.T) {
	ca, store := setupRenewTest(t)
	expiredCert, _, _ := enrollExpiredDevice(t, ca, store, "srv_badsig", "sha256:sig-fp", 5*time.Minute)

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	handler := NewChallengeRenewHandler(ChallengeRenewConfig{
		CA: ca, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	body, _ := makeChallengeRequest(t, "srv_badsig", "sha256:sig-fp", wrongKey, expiredCert)

	req := httptest.NewRequest(http.MethodPost, "/renew/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", w.Code)
	}
}

func TestChallengeRenewSupersededSerial(t *testing.T) {
	ca, store := setupRenewTest(t)
	expiredCert, oldKey, _ := enrollExpiredDevice(t, ca, store, "srv_super", "sha256:super-fp", 5*time.Minute)

	e, _ := store.GetByServerID(nil, "srv_super")
	e.SerialNumber = "deadbeef"
	store.SaveEnrollment(nil, e)

	handler := NewChallengeRenewHandler(ChallengeRenewConfig{
		CA: ca, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	body, _ := makeChallengeRequest(t, "srv_super", "sha256:super-fp", oldKey, expiredCert)

	req := httptest.NewRequest(http.MethodPost, "/renew/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for superseded serial, got %d", w.Code)
	}
}
