package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dvstc/imprint"
)

func setupEnrollHandler(t *testing.T) (http.Handler, *MemStore) {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCA(CAConfig{CertDir: dir, Organization: "Handler Test"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	store := NewMemStore()
	handler := NewEnrollHandler(EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{"valid-secret-1", "valid-secret-2"},
		Mode:         imprint.ModeAuto,
	})
	return handler, store
}

func makeCSRPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-device"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), key
}

func TestEnrollHandlerValidEnrollment(t *testing.T) {
	handler, store := setupEnrollHandler(t)
	csrPEM, _ := makeCSRPEM(t)

	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: "valid-secret-1",
		Fingerprint: "sha256:test-fp",
		Hostname:    "test-host",
		OS:          "linux",
		Arch:        "amd64",
		CSR:         csrPEM,
	})

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp imprint.EnrollmentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ServerID == "" {
		t.Fatal("server_id should not be empty")
	}
	if resp.Certificate == "" {
		t.Fatal("certificate should not be empty")
	}
	if resp.CACertificate == "" {
		t.Fatal("ca_certificate should not be empty")
	}

	// Verify enrollment was stored
	e, _ := store.GetByFingerprint(nil, "sha256:test-fp")
	if e == nil {
		t.Fatal("enrollment not found in store")
	}
	if e.ServerID != resp.ServerID {
		t.Fatalf("stored server_id %q != response server_id %q", e.ServerID, resp.ServerID)
	}
	if e.Status != imprint.StatusActive {
		t.Fatalf("expected status active, got %q", e.Status)
	}
}

func TestEnrollHandlerInvalidBuildSecret(t *testing.T) {
	handler, _ := setupEnrollHandler(t)
	csrPEM, _ := makeCSRPEM(t)

	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: "wrong-secret",
		Fingerprint: "sha256:test-fp",
		CSR:         csrPEM,
	})

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestEnrollHandlerMissingFields(t *testing.T) {
	handler, _ := setupEnrollHandler(t)

	tests := []struct {
		name string
		req  imprint.EnrollmentRequest
	}{
		{"missing build_secret", imprint.EnrollmentRequest{Fingerprint: "fp", CSR: "csr"}},
		{"missing fingerprint", imprint.EnrollmentRequest{BuildSecret: "s", CSR: "csr"}},
		{"missing csr", imprint.EnrollmentRequest{BuildSecret: "s", Fingerprint: "fp"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestEnrollHandlerInvalidCSR(t *testing.T) {
	handler, _ := setupEnrollHandler(t)

	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: "valid-secret-1",
		Fingerprint: "sha256:test-fp",
		CSR:         "not-valid-pem",
	})

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnrollHandlerReEnrollment(t *testing.T) {
	handler, _ := setupEnrollHandler(t)
	csrPEM, _ := makeCSRPEM(t)

	makeRequest := func() imprint.EnrollmentResponse {
		body, _ := json.Marshal(imprint.EnrollmentRequest{
			BuildSecret: "valid-secret-1",
			Fingerprint: "sha256:reenroll-fp",
			Hostname:    "test-host",
			CSR:         csrPEM,
		})
		req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp imprint.EnrollmentResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}

	resp1 := makeRequest()
	resp2 := makeRequest()

	// Re-enrollment should keep the same server ID
	if resp1.ServerID != resp2.ServerID {
		t.Fatalf("re-enrollment changed server_id: %s -> %s", resp1.ServerID, resp2.ServerID)
	}
	// But issue a new certificate
	if resp1.Certificate == resp2.Certificate {
		t.Fatal("re-enrollment should issue a new certificate")
	}
}

func TestEnrollHandlerWrongMethod(t *testing.T) {
	handler, _ := setupEnrollHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestEnrollHandlerSecondBuildSecret(t *testing.T) {
	handler, _ := setupEnrollHandler(t)
	csrPEM, _ := makeCSRPEM(t)

	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: "valid-secret-2",
		Fingerprint: "sha256:test-fp2",
		CSR:         csrPEM,
	})

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for second build secret, got %d", w.Code)
	}
}

func TestEnrollHandlerCertIsValid(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA(CAConfig{CertDir: dir})
	store := NewMemStore()
	handler := NewEnrollHandler(EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{"secret"},
		Mode:         imprint.ModeAuto,
	})

	csrPEM, _ := makeCSRPEM(t)
	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: "secret",
		Fingerprint: "sha256:cert-test",
		CSR:         csrPEM,
	})

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp imprint.EnrollmentResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Parse and verify the issued certificate
	block, _ := pem.Decode([]byte(resp.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pool := ca.CertPool()
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert verification failed: %v", err)
	}
}

func TestValidateBuildSecretConstantTime(t *testing.T) {
	if validateBuildSecret("correct", []string{"correct"}) != true {
		t.Fatal("should validate correct secret")
	}
	if validateBuildSecret("wrong", []string{"correct"}) != false {
		t.Fatal("should reject wrong secret")
	}
	if validateBuildSecret("", []string{"correct"}) != false {
		t.Fatal("should reject empty secret")
	}
	if validateBuildSecret("correct", nil) != false {
		t.Fatal("should reject when no secrets configured")
	}
}
