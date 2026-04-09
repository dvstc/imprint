package imprint_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dvstc/imprint"
	"github.com/dvstc/imprint/client"
	"github.com/dvstc/imprint/server"
)

// TestIntegrationFullEnrollmentAndMTLS tests the complete flow:
// 1. Client enrolls via the handler
// 2. Client loads mTLS config from persisted certs
// 3. Client makes a request through the RequireMTLS middleware
// 4. Server extracts the client identity from context
func TestIntegrationFullEnrollmentAndMTLS(t *testing.T) {
	caDir := t.TempDir()
	ca, err := server.NewCA(server.CAConfig{
		CertDir:      caDir,
		Organization: "Integration Test",
	})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	store := server.NewMemStore()
	buildSecret := "integration-test-secret"

	// Set up the enrollment handler
	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{buildSecret},
		Mode:         imprint.ModeAuto,
	})

	// Set up a protected endpoint behind RequireMTLS
	protectedHandler := server.RequireMTLS(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := server.ServerIdentity(r.Context())
		if identity == nil {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"server_id":   identity.ServerID,
			"fingerprint": identity.Fingerprint,
			"status":      identity.Status,
		})
	}))

	// Step 1: Enroll the client
	storeDir := t.TempDir()
	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL:  enrollTS.URL,
		BuildSecret: buildSecret,
		Fingerprint: "sha256:integration-fp",
		Hostname:    "integration-host",
		StoreDir:    storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	t.Logf("Enrolled with server_id=%s", resp.ServerID)

	// Step 2: Load the mTLS config from persisted certs
	tlsCfg, err := client.LoadTLS(storeDir)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}

	// Step 3: Make a request through the mTLS-protected handler
	// We use a custom httptest server with TLS that accepts our CA's certs
	protectedTS := httptest.NewUnstartedServer(protectedHandler)
	protectedTS.TLS = &tls.Config{
		ClientCAs:  ca.CertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	protectedTS.StartTLS()
	defer protectedTS.Close()

	// Client needs to trust the test server's self-signed cert
	testServerCert := protectedTS.Certificate()
	tlsCfg.RootCAs = x509.NewCertPool()
	tlsCfg.RootCAs.AddCert(testServerCert)

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	req, _ := http.NewRequest(http.MethodGet, protectedTS.URL+"/data", nil)
	httpResp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("expected 200, got %d: %s", httpResp.StatusCode, string(body))
	}

	var result map[string]string
	json.NewDecoder(httpResp.Body).Decode(&result)

	if result["server_id"] != resp.ServerID {
		t.Fatalf("server_id mismatch: expected %s, got %s", resp.ServerID, result["server_id"])
	}
	if result["fingerprint"] != "sha256:integration-fp" {
		t.Fatalf("fingerprint mismatch: %s", result["fingerprint"])
	}
	if result["status"] != imprint.StatusActive {
		t.Fatalf("expected active status, got %s", result["status"])
	}

	t.Log("Full enrollment -> mTLS request flow succeeded")
}

// TestIntegrationRevokedCertDenied tests that a revoked certificate
// is rejected by the RequireMTLS middleware.
func TestIntegrationRevokedCertDenied(t *testing.T) {
	caDir := t.TempDir()
	ca, _ := server.NewCA(server.CAConfig{CertDir: caDir})
	store := server.NewMemStore()
	buildSecret := "revoke-test-secret"

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{buildSecret},
		Mode:         imprint.ModeAuto,
	})

	protectedHandler := server.RequireMTLS(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("access granted"))
	}))

	// Enroll
	storeDir := t.TempDir()
	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL:  enrollTS.URL,
		BuildSecret: buildSecret,
		Fingerprint: "sha256:revoke-fp",
		Hostname:    "revoke-host",
		StoreDir:    storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Revoke the enrollment
	if err := store.Revoke(context.Background(), resp.ServerID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Try mTLS request with revoked cert
	tlsCfg, _ := client.LoadTLS(storeDir)

	protectedTS := httptest.NewUnstartedServer(protectedHandler)
	protectedTS.TLS = &tls.Config{
		ClientCAs:  ca.CertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	protectedTS.StartTLS()
	defer protectedTS.Close()

	tlsCfg.RootCAs = x509.NewCertPool()
	tlsCfg.RootCAs.AddCert(protectedTS.Certificate())

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	req, _ := http.NewRequest(http.MethodGet, protectedTS.URL+"/data", nil)
	httpResp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("expected 401 for revoked cert, got %d: %s", httpResp.StatusCode, string(body))
	}

	t.Log("Revoked certificate correctly denied")
}

// TestIntegrationReEnrollment tests that re-enrolling with the same
// fingerprint reuses the server ID but issues a new certificate.
func TestIntegrationReEnrollment(t *testing.T) {
	caDir := t.TempDir()
	ca, _ := server.NewCA(server.CAConfig{CertDir: caDir})
	store := server.NewMemStore()
	buildSecret := "reenroll-secret"

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA:           ca,
		Store:        store,
		BuildSecrets: []string{buildSecret},
		Mode:         imprint.ModeAuto,
	})

	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	// First enrollment
	storeDir1 := t.TempDir()
	resp1, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL:  enrollTS.URL,
		BuildSecret: buildSecret,
		Fingerprint: "sha256:reenroll-fp",
		Hostname:    "host1",
		StoreDir:    storeDir1,
	})
	if err != nil {
		t.Fatalf("First enroll: %v", err)
	}

	// Second enrollment (same fingerprint, different hostname)
	storeDir2 := t.TempDir()
	resp2, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL:  enrollTS.URL,
		BuildSecret: buildSecret,
		Fingerprint: "sha256:reenroll-fp",
		Hostname:    "host2",
		StoreDir:    storeDir2,
	})
	if err != nil {
		t.Fatalf("Second enroll: %v", err)
	}

	// Server ID should be the same
	if resp1.ServerID != resp2.ServerID {
		t.Fatalf("server_id changed on re-enrollment: %s -> %s", resp1.ServerID, resp2.ServerID)
	}

	// Certificates should be different
	block1, _ := pem.Decode([]byte(resp1.Certificate))
	block2, _ := pem.Decode([]byte(resp2.Certificate))
	if bytes.Equal(block1.Bytes, block2.Bytes) {
		t.Fatal("re-enrollment should issue a different certificate")
	}

	t.Log("Re-enrollment correctly reused server_id with new certificate")
}

// TestIntegrationMTLSRenewAndOldCertRejected tests Tier 1 renewal:
// enroll, renew via mTLS, verify new cert works and old cert is rejected.
func TestIntegrationMTLSRenewAndOldCertRejected(t *testing.T) {
	caDir := t.TempDir()
	ca, err := server.NewCA(server.CAConfig{CertDir: caDir, Organization: "Renew Integration"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	store := server.NewMemStore()
	buildSecret := "renew-int-secret"

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{buildSecret}, Mode: imprint.ModeAuto,
	})
	renewHandler := server.NewRenewHandler(server.RenewConfig{CA: ca, Store: store})

	protectedHandler := server.RequireMTLS(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := server.ServerIdentity(r.Context())
		json.NewEncoder(w).Encode(map[string]string{"server_id": identity.ServerID})
	}))

	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/renew", renewHandler)
	mux.Handle("GET /data", protectedHandler)

	mtlsTS := httptest.NewUnstartedServer(mux)
	mtlsTS.TLS = &tls.Config{
		ClientCAs:  ca.CertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	mtlsTS.StartTLS()
	defer mtlsTS.Close()

	// Step 1: Enroll
	storeDir := t.TempDir()
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: buildSecret,
		Fingerprint: "sha256:renew-int-fp", Hostname: "renew-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Save old TLS config for later (to test old cert rejection)
	oldTLS, _ := client.LoadTLS(storeDir)
	oldTLS.RootCAs = x509.NewCertPool()
	oldTLS.RootCAs.AddCert(mtlsTS.Certificate())

	// Step 2: Renew via mTLS using manual request construction
	// (client.Renew uses LoadTLS internally which can't trust httptest's cert)
	renewTLS, _ := client.LoadTLS(storeDir)
	renewTLS.RootCAs = x509.NewCertPool()
	renewTLS.RootCAs.AddCert(mtlsTS.Certificate())

	newCSRPEM, newKey := makeTestCSRAndKey(t)
	reqBody, _ := json.Marshal(imprint.RenewalRequest{CSR: newCSRPEM})

	httpReq, _ := http.NewRequest(http.MethodPost, mtlsTS.URL+"/api/v1/renew", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	renewClient := &http.Client{Transport: &http.Transport{TLSClientConfig: renewTLS}}

	httpResp, err := renewClient.Do(httpReq)
	if err != nil {
		t.Fatalf("renewal request failed: %v", err)
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", httpResp.StatusCode, string(body))
	}

	var renewResp imprint.EnrollmentResponse
	json.Unmarshal(body, &renewResp)
	if renewResp.ServerID != resp.ServerID {
		t.Fatalf("server_id changed: %s -> %s", resp.ServerID, renewResp.ServerID)
	}

	// Save new cert to disk
	newKeyPEM, _ := marshalECKey(newKey)
	client.SaveEnrollment(storeDir, newKeyPEM,
		[]byte(renewResp.Certificate), []byte(renewResp.CACertificate),
		renewResp.ServerID, "sha256:renew-int-fp")

	// Step 3: New cert should work
	newTLS, _ := client.LoadTLS(storeDir)
	newTLS.RootCAs = x509.NewCertPool()
	newTLS.RootCAs.AddCert(mtlsTS.Certificate())

	newClient := &http.Client{Transport: &http.Transport{TLSClientConfig: newTLS}}
	httpResp2, err := newClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("new cert request failed: %v", err)
	}
	httpResp2.Body.Close()
	if httpResp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with new cert, got %d", httpResp2.StatusCode)
	}

	// Step 4: Old cert should be rejected (superseded serial)
	oldClient := &http.Client{Transport: &http.Transport{TLSClientConfig: oldTLS}}
	httpResp3, err := oldClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("old cert request failed: %v", err)
	}
	httpResp3.Body.Close()
	if httpResp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old cert, got %d", httpResp3.StatusCode)
	}

	// Verify RenewedAt was set
	enrollment, _ := store.GetByServerID(context.Background(), resp.ServerID)
	if enrollment.RenewedAt.IsZero() {
		t.Fatal("RenewedAt should be set after renewal")
	}
	if enrollment.EnrolledAt.IsZero() {
		t.Fatal("EnrolledAt should be preserved after renewal")
	}

	t.Log("mTLS renewal succeeded, old cert correctly rejected")
}

func makeTestCSRAndKey(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-renew"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), key
}

func marshalECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
