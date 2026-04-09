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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dvstc/imprint"
	"github.com/dvstc/imprint/client"
	"github.com/dvstc/imprint/server"
)

// setupE2E creates a CA, MemStore, and common test fixtures.
func setupE2E(t *testing.T) (*server.CA, *server.MemStore, string) {
	t.Helper()
	ca, err := server.NewCA(server.CAConfig{
		CertDir:      t.TempDir(),
		Organization: "E2E Harness",
	})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca, server.NewMemStore(), "e2e-build-secret"
}

// startEnrollServer creates an httptest server for the enrollment handler.
func startEnrollServer(t *testing.T, ca *server.CA, store *server.MemStore, secret string) *httptest.Server {
	t.Helper()
	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store,
		BuildSecrets: []string{secret},
		Mode:         imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// startMTLSServer creates an httptest TLS server with mTLS + handlers.
func startMTLSServer(t *testing.T, ca *server.CA, store *server.MemStore) *httptest.Server {
	t.Helper()
	renewHandler := server.NewRenewHandler(server.RenewConfig{CA: ca, Store: store})
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

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/renew", renewHandler)
	mux.Handle("GET /data", protectedHandler)

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{
		ClientCAs:  ca.CertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func mtlsClient(t *testing.T, storeDir string, serverCert *x509.Certificate) *http.Client {
	t.Helper()
	tlsCfg, err := client.LoadTLS(storeDir)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}
	tlsCfg.RootCAs = x509.NewCertPool()
	tlsCfg.RootCAs.AddCert(serverCert)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

// ---------- Test 1: Full Enrollment → mTLS Request ----------

func TestE2E_FullEnrollmentAndMTLS(t *testing.T) {
	ca, store, secret := setupE2E(t)
	storeDir := t.TempDir()

	enrollTS := startEnrollServer(t, ca, store, secret)
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-fp-1", Hostname: "e2e-host-1", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if resp.Certificate == "" || resp.CACertificate == "" {
		t.Fatal("enrollment response missing cert or CA cert")
	}
	if !client.IsEnrolled(storeDir) {
		t.Fatal("should be enrolled after successful enrollment")
	}

	meta, err := client.LoadMeta(storeDir)
	if err != nil {
		t.Fatalf("LoadMeta: %v", err)
	}
	if meta.ServerID != resp.ServerID {
		t.Fatalf("server_id mismatch: disk=%s, response=%s", meta.ServerID, resp.ServerID)
	}

	mtlsTS := startMTLSServer(t, ca, store)
	httpClient := mtlsClient(t, storeDir, mtlsTS.Certificate())

	httpResp, err := httpClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", httpResp.StatusCode, string(body))
	}

	var result map[string]string
	json.Unmarshal(body, &result)

	if result["server_id"] != resp.ServerID {
		t.Fatalf("server_id mismatch in mTLS response: %s vs %s", result["server_id"], resp.ServerID)
	}
	if result["fingerprint"] != "sha256:e2e-fp-1" {
		t.Fatalf("fingerprint mismatch: %s", result["fingerprint"])
	}
	if result["status"] != imprint.StatusActive {
		t.Fatalf("expected active, got %s", result["status"])
	}
	if httpResp.Header.Get("X-Imprint-Cert-Expires") == "" {
		t.Fatal("missing X-Imprint-Cert-Expires header")
	}

	t.Logf("Full enrollment → mTLS flow: server_id=%s, cert_expires=%s",
		resp.ServerID, httpResp.Header.Get("X-Imprint-Cert-Expires"))
}

// ---------- Test 2: Tier 1 mTLS Renewal → Old Cert Rejected ----------

func TestE2E_Tier1RenewalAndSupersededCertRejected(t *testing.T) {
	ca, store, secret := setupE2E(t)
	storeDir := t.TempDir()

	enrollTS := startEnrollServer(t, ca, store, secret)
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-renew-fp", Hostname: "e2e-renew-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	mtlsTS := startMTLSServer(t, ca, store)

	oldTLS, _ := client.LoadTLS(storeDir)
	oldTLS.RootCAs = x509.NewCertPool()
	oldTLS.RootCAs.AddCert(mtlsTS.Certificate())
	oldClient := &http.Client{Transport: &http.Transport{TLSClientConfig: oldTLS}}

	enrollmentBefore, _ := store.GetByServerID(context.Background(), resp.ServerID)

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "renew-test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, newKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	renewTLS, _ := client.LoadTLS(storeDir)
	renewTLS.RootCAs = x509.NewCertPool()
	renewTLS.RootCAs.AddCert(mtlsTS.Certificate())

	reqBody, _ := json.Marshal(imprint.RenewalRequest{CSR: string(csrPEM)})
	httpReq, _ := http.NewRequest(http.MethodPost, mtlsTS.URL+"/api/v1/renew", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	renewClient := &http.Client{Transport: &http.Transport{TLSClientConfig: renewTLS}}

	httpResp, err := renewClient.Do(httpReq)
	if err != nil {
		t.Fatalf("renewal request: %v", err)
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("renewal expected 200, got %d: %s", httpResp.StatusCode, string(body))
	}

	var renewResp imprint.EnrollmentResponse
	json.Unmarshal(body, &renewResp)

	if renewResp.ServerID != resp.ServerID {
		t.Fatalf("server_id changed after renewal: %s -> %s", resp.ServerID, renewResp.ServerID)
	}

	newKeyDER, _ := x509.MarshalECPrivateKey(newKey)
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newKeyDER})
	client.SaveEnrollment(storeDir, newKeyPEM,
		[]byte(renewResp.Certificate), []byte(renewResp.CACertificate),
		renewResp.ServerID, "sha256:e2e-renew-fp")

	enrollmentAfter, _ := store.GetByServerID(context.Background(), resp.ServerID)

	if enrollmentAfter.SerialNumber == enrollmentBefore.SerialNumber {
		t.Fatal("serial should change after renewal")
	}
	if enrollmentAfter.RenewedAt.IsZero() {
		t.Fatal("RenewedAt should be set after renewal")
	}
	if enrollmentAfter.EnrolledAt.IsZero() {
		t.Fatal("EnrolledAt should be preserved after renewal")
	}

	newHTTPClient := mtlsClient(t, storeDir, mtlsTS.Certificate())
	httpResp2, err := newHTTPClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("new cert request: %v", err)
	}
	httpResp2.Body.Close()
	if httpResp2.StatusCode != http.StatusOK {
		t.Fatalf("new cert expected 200, got %d", httpResp2.StatusCode)
	}

	httpResp3, err := oldClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("old cert request: %v", err)
	}
	httpResp3.Body.Close()
	if httpResp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old cert expected 401, got %d", httpResp3.StatusCode)
	}

	t.Logf("Tier 1 renewal: serial %s → %s, new cert accepted, old cert rejected",
		enrollmentBefore.SerialNumber, enrollmentAfter.SerialNumber)
}

// ---------- Test 3: Tier 2 Challenge Renewal (Expired Cert) ----------

func TestE2E_Tier2ChallengeRenewal(t *testing.T) {
	fingerprint := "sha256:e2e-challenge-fp"

	// Use a CA with 1ms cert validity so certs expire almost immediately.
	shortCA, err := server.NewCA(server.CAConfig{
		CertDir:      t.TempDir(),
		Organization: "E2E Short-Lived",
		Validity:     1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	store := server.NewMemStore()
	secret := "challenge-secret"

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA: shortCA, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	challengeHandler := server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
		CA: shortCA, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	})

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/enroll", enrollHandler)
	mux.Handle("POST /api/v1/renew/challenge", challengeHandler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	storeDir := t.TempDir()
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: ts.URL, BuildSecret: secret,
		Fingerprint: fingerprint, Hostname: "challenge-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Wait for cert to expire (1ms validity + buffer).
	time.Sleep(50 * time.Millisecond)

	isExp, err := client.IsExpired(storeDir)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if !isExp {
		t.Fatal("cert should be expired after 50ms with 1ms validity")
	}

	// Tier 2: challenge renewal using the expired cert.
	challengeResp, err := client.ChallengeRenew(context.Background(), client.RenewConfig{
		ServiceURL:      ts.URL,
		StoreDir:        storeDir,
		ChallengeWindow: 30 * 24 * time.Hour,
	}, fingerprint)
	if err != nil {
		t.Fatalf("ChallengeRenew: %v", err)
	}

	if challengeResp.ServerID != resp.ServerID {
		t.Fatalf("server_id changed: %s -> %s", resp.ServerID, challengeResp.ServerID)
	}
	if challengeResp.Certificate == "" {
		t.Fatal("expected a new certificate from challenge renewal")
	}

	enrollmentAfter, _ := store.GetByServerID(context.Background(), resp.ServerID)
	if enrollmentAfter.RenewedAt.IsZero() {
		t.Fatal("RenewedAt should be set after challenge renewal")
	}

	t.Logf("Tier 2 challenge renewal succeeded for %s", resp.ServerID)
}

// ---------- Test 4: Revocation → mTLS Denied ----------

func TestE2E_RevocationDeniesAccess(t *testing.T) {
	ca, store, secret := setupE2E(t)
	storeDir := t.TempDir()

	enrollTS := startEnrollServer(t, ca, store, secret)
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-revoke-fp", Hostname: "e2e-revoke-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	mtlsTS := startMTLSServer(t, ca, store)
	httpClient := mtlsClient(t, storeDir, mtlsTS.Certificate())

	preRevokeResp, err := httpClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("pre-revoke request: %v", err)
	}
	preRevokeResp.Body.Close()
	if preRevokeResp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke expected 200, got %d", preRevokeResp.StatusCode)
	}

	if err := store.Revoke(context.Background(), resp.ServerID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	postRevokeResp, err := httpClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("post-revoke request: %v", err)
	}
	postRevokeResp.Body.Close()
	if postRevokeResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke expected 401, got %d", postRevokeResp.StatusCode)
	}

	t.Logf("Revocation: %s access granted then denied after revoke", resp.ServerID)
}

// ---------- Test 5: Re-Enrollment (Same Fingerprint) ----------

func TestE2E_ReEnrollmentPreservesServerID(t *testing.T) {
	ca, store, secret := setupE2E(t)

	enrollTS := startEnrollServer(t, ca, store, secret)

	storeDir1 := t.TempDir()
	resp1, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-reenroll-fp", Hostname: "host-v1", StoreDir: storeDir1,
	})
	if err != nil {
		t.Fatalf("First enroll: %v", err)
	}

	storeDir2 := t.TempDir()
	resp2, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-reenroll-fp", Hostname: "host-v2", StoreDir: storeDir2,
	})
	if err != nil {
		t.Fatalf("Second enroll: %v", err)
	}

	if resp1.ServerID != resp2.ServerID {
		t.Fatalf("server_id changed: %s -> %s", resp1.ServerID, resp2.ServerID)
	}

	block1, _ := pem.Decode([]byte(resp1.Certificate))
	block2, _ := pem.Decode([]byte(resp2.Certificate))
	if bytes.Equal(block1.Bytes, block2.Bytes) {
		t.Fatal("re-enrollment should issue different certificates")
	}

	mtlsTS := startMTLSServer(t, ca, store)
	httpClient := mtlsClient(t, storeDir2, mtlsTS.Certificate())
	httpResp, err := httpClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("post-reenroll mTLS: %v", err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("re-enrolled cert expected 200, got %d", httpResp.StatusCode)
	}

	old1Client := mtlsClient(t, storeDir1, mtlsTS.Certificate())
	oldResp, err := old1Client.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("old cert request: %v", err)
	}
	oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old cert after re-enroll expected 401, got %d", oldResp.StatusCode)
	}

	t.Logf("Re-enrollment: %s preserved, old cert rejected", resp1.ServerID)
}

// ---------- Test 6: Invalid Build Secret Rejected ----------

func TestE2E_InvalidBuildSecretRejected(t *testing.T) {
	ca, store, secret := setupE2E(t)

	enrollTS := startEnrollServer(t, ca, store, secret)

	storeDir := t.TempDir()
	_, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: "wrong-secret",
		Fingerprint: "sha256:e2e-bad-fp", Hostname: "bad-host", StoreDir: storeDir,
	})

	if err == nil {
		t.Fatal("expected enrollment to fail with wrong secret")
	}
	if client.IsEnrolled(storeDir) {
		t.Fatal("should not be enrolled after rejection")
	}

	t.Logf("Invalid secret correctly rejected: %v", err)
}

// ---------- Test 7: Certificate Inspection APIs ----------

func TestE2E_CertificateInspection(t *testing.T) {
	ca, store, secret := setupE2E(t)
	storeDir := t.TempDir()

	enrollTS := startEnrollServer(t, ca, store, secret)
	_, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-inspect-fp", Hostname: "inspect-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	expiry, err := client.CertExpiry(storeDir)
	if err != nil {
		t.Fatalf("CertExpiry: %v", err)
	}
	if time.Until(expiry) < 364*24*time.Hour {
		t.Fatalf("expected ~1 year validity, got %v until expiry", time.Until(expiry))
	}

	needsRenewal, err := client.NeedsRenewal(storeDir, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needsRenewal {
		t.Fatal("fresh cert should not need renewal within 30 days")
	}

	isExpired, err := client.IsExpired(storeDir)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if isExpired {
		t.Fatal("fresh cert should not be expired")
	}

	cert, err := client.LoadCert(storeDir)
	if err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	if !hasClientAuthEKU(cert) {
		t.Fatal("cert should have ClientAuth EKU")
	}
	if len(cert.URIs) == 0 {
		t.Fatal("cert should have SAN URI")
	}

	t.Logf("Cert inspection: CN=%s, issuer=%s, expiry=%s, serial=%s",
		cert.Subject.CommonName, cert.Issuer.CommonName,
		expiry.Format(time.RFC3339), cert.SerialNumber.Text(16))
}

func hasClientAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// ---------- Test 8: Store Operations (List, Delete) ----------

func TestE2E_StoreOperations(t *testing.T) {
	ca, store, secret := setupE2E(t)

	enrollTS := startEnrollServer(t, ca, store, secret)

	for i := 0; i < 3; i++ {
		sd := t.TempDir()
		_, err := client.Enroll(context.Background(), client.EnrollConfig{
			ServiceURL: enrollTS.URL, BuildSecret: secret,
			Fingerprint: fmt.Sprintf("sha256:store-fp-%d", i),
			Hostname:    fmt.Sprintf("store-host-%d", i),
			StoreDir:    sd,
		})
		if err != nil {
			t.Fatalf("Enroll device %d: %v", i, err)
		}
	}

	all, err := store.List(context.Background(), server.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 enrollments, got %d", len(all))
	}

	targetID := all[0].ServerID
	if err := store.Delete(context.Background(), targetID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	afterDelete, _ := store.List(context.Background(), server.ListFilter{})
	if len(afterDelete) != 2 {
		t.Fatalf("expected 2 enrollments after delete, got %d", len(afterDelete))
	}

	deleted, _ := store.GetByServerID(context.Background(), targetID)
	if deleted != nil {
		t.Fatal("deleted enrollment should be nil")
	}

	store.Revoke(context.Background(), afterDelete[0].ServerID)
	active, _ := store.List(context.Background(), server.ListFilter{Status: imprint.StatusActive})
	revoked, _ := store.List(context.Background(), server.ListFilter{Status: imprint.StatusRevoked})

	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked, got %d", len(revoked))
	}

	t.Logf("Store ops: 3 enrolled → deleted %s → 1 active, 1 revoked", targetID)
}

// ---------- Test 9: ReloadableTLS ----------

func TestE2E_ReloadableTLS(t *testing.T) {
	ca, store, secret := setupE2E(t)
	storeDir := t.TempDir()

	enrollTS := startEnrollServer(t, ca, store, secret)
	_, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollTS.URL, BuildSecret: secret,
		Fingerprint: "sha256:e2e-reload-fp", Hostname: "reload-host", StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	reloadCfg, err := client.ReloadableTLS(storeDir)
	if err != nil {
		t.Fatalf("ReloadableTLS: %v", err)
	}

	mtlsTS := startMTLSServer(t, ca, store)
	reloadCfg.RootCAs = x509.NewCertPool()
	reloadCfg.RootCAs.AddCert(mtlsTS.Certificate())

	reloadClient := &http.Client{Transport: &http.Transport{TLSClientConfig: reloadCfg}}
	httpResp, err := reloadClient.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("reloadable TLS request: %v", err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("reloadable TLS expected 200, got %d", httpResp.StatusCode)
	}

	// Renew cert on disk, then verify the reloadable TLS picks it up.
	renewTLS, _ := client.LoadTLS(storeDir)
	renewTLS.RootCAs = x509.NewCertPool()
	renewTLS.RootCAs.AddCert(mtlsTS.Certificate())

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "reload-renew"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csr, newKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	reqBody, _ := json.Marshal(imprint.RenewalRequest{CSR: string(csrPEM)})
	httpReq, _ := http.NewRequest(http.MethodPost, mtlsTS.URL+"/api/v1/renew", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	renewClient := &http.Client{Transport: &http.Transport{TLSClientConfig: renewTLS}}
	renewResp, err := renewClient.Do(httpReq)
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer renewResp.Body.Close()
	body, _ := io.ReadAll(renewResp.Body)

	var rnResp imprint.EnrollmentResponse
	json.Unmarshal(body, &rnResp)

	newKeyDER, _ := x509.MarshalECPrivateKey(newKey)
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newKeyDER})
	client.SaveEnrollment(storeDir, newKeyPEM,
		[]byte(rnResp.Certificate), []byte(rnResp.CACertificate),
		rnResp.ServerID, "sha256:e2e-reload-fp")

	reloadClient2 := &http.Client{Transport: &http.Transport{TLSClientConfig: reloadCfg}}
	httpResp2, err := reloadClient2.Get(mtlsTS.URL + "/data")
	if err != nil {
		t.Fatalf("reloadable TLS after renewal: %v", err)
	}
	httpResp2.Body.Close()
	if httpResp2.StatusCode != http.StatusOK {
		t.Fatalf("reloadable TLS after renewal expected 200, got %d", httpResp2.StatusCode)
	}

	t.Log("ReloadableTLS: correctly picked up renewed cert from disk")
}
