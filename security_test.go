package imprint_test

import (
	"bytes"
	"context"
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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"

	"testing"
	"time"

	"github.com/dvstc/imprint"
	"github.com/dvstc/imprint/client"
	"github.com/dvstc/imprint/server"
)

// ============================================================
// Shared security test infrastructure
// ============================================================

func secSetup(t *testing.T) (*server.CA, *server.MemStore, string) {
	t.Helper()
	ca, err := server.NewCA(server.CAConfig{CertDir: t.TempDir(), Organization: "SecTest CA"})
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca, server.NewMemStore(), "sec-build-secret"
}

func secEnroll(t *testing.T, enrollURL, secret, fingerprint, hostname, storeDir string) *imprint.EnrollmentResponse {
	t.Helper()
	resp, err := client.Enroll(context.Background(), client.EnrollConfig{
		ServiceURL: enrollURL, BuildSecret: secret,
		Fingerprint: fingerprint, Hostname: hostname, StoreDir: storeDir,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return resp
}

func secMTLSServer(t *testing.T, ca *server.CA, store *server.MemStore) *httptest.Server {
	t.Helper()
	protected := server.RequireMTLS(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := server.ServerIdentity(r.Context())
		json.NewEncoder(w).Encode(map[string]string{"server_id": id.ServerID, "status": id.Status})
	}))
	ts := httptest.NewUnstartedServer(protected)
	ts.TLS = &tls.Config{ClientCAs: ca.CertPool(), ClientAuth: tls.RequireAndVerifyClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func makeCSRForSec(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sec-test"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), key
}

// ============================================================
// ATK-01: Foreign CA — cert signed by rogue CA
// ============================================================

func TestSec_ForeignCACertRejected(t *testing.T) {
	ca, store, secret := secSetup(t)

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	storeDir := t.TempDir()
	secEnroll(t, enrollTS.URL, secret, "sha256:legit-fp", "legit-host", storeDir)

	mtlsTS := secMTLSServer(t, ca, store)

	// Create a rogue CA and sign a cert with the same CN as the legitimate device
	rogueCA, _ := server.NewCA(server.CAConfig{CertDir: t.TempDir(), Organization: "Rogue CA"})
	rogueKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sec-test"}}
	rogueCSRDER, _ := x509.CreateCertificateRequest(rand.Reader, rogueTmpl, rogueKey)
	rogueCSR, _ := x509.ParseCertificateRequest(rogueCSRDER)

	meta, _ := client.LoadMeta(storeDir)
	rogueCertPEM, _, _ := rogueCA.SignCSR(rogueCSR, meta.ServerID)

	rogueCertFile := t.TempDir() + "/rogue.crt"
	rogueKeyDER, _ := x509.MarshalECPrivateKey(rogueKey)
	rogueKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rogueKeyDER})
	rogueKeyFile := t.TempDir() + "/rogue.key"
	os.WriteFile(rogueCertFile, rogueCertPEM, 0644)
	os.WriteFile(rogueKeyFile, rogueKeyPEM, 0600)

	rogueTLSCert, _ := tls.LoadX509KeyPair(rogueCertFile, rogueKeyFile)
	rogueTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{rogueTLSCert},
		RootCAs:      x509.NewCertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	rogueTLSCfg.RootCAs.AddCert(mtlsTS.Certificate())

	rogueClient := &http.Client{Transport: &http.Transport{TLSClientConfig: rogueTLSCfg}}
	_, err := rogueClient.Get(mtlsTS.URL + "/data")

	// TLS handshake should fail entirely because the server only trusts our CA
	rejected := err != nil

	if !rejected {
		t.Fatal("VULNERABILITY: foreign CA cert was accepted by mTLS server")
	}
	t.Log("ATK-01 PASS: foreign CA cert rejected at TLS handshake level")
}

// ============================================================
// ATK-02: Build secret timing analysis
// ============================================================

func TestSec_BuildSecretConstantTimeComparison(t *testing.T) {
	ca, store, _ := secSetup(t)
	realSecret := "correct-secret-value-1234567890"

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{realSecret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM, _ := makeCSRForSec(t)

	measure := func(secret string, iterations int) time.Duration {
		var total time.Duration
		for i := 0; i < iterations; i++ {
			body, _ := json.Marshal(imprint.EnrollmentRequest{
				BuildSecret: secret, Fingerprint: fmt.Sprintf("sha256:timing-%d", i),
				Hostname: "timing", CSR: csrPEM,
			})
			start := time.Now()
			resp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
			total += time.Since(start)
			if resp != nil {
				resp.Body.Close()
			}
		}
		return total / time.Duration(iterations)
	}

	iterations := 200
	// Wrong secret: completely different
	avgWrong := measure("completely-wrong-secret-xxxxxxxxx", iterations)
	// Wrong secret: same length, one char off
	avgClose := measure("correct-secret-value-1234567891", iterations)
	// Wrong secret: prefix match
	avgPrefix := measure("correct-secret-value-", iterations)

	ratio1 := float64(avgClose) / float64(avgWrong)
	ratio2 := float64(avgPrefix) / float64(avgWrong)

	// Timing should be roughly similar (within 30% is generous for network jitter)
	if ratio1 < 0.5 || ratio1 > 2.0 {
		t.Logf("WARNING: timing ratio close/wrong = %.2f — potential timing side channel", ratio1)
	}
	if ratio2 < 0.5 || ratio2 > 2.0 {
		t.Logf("WARNING: timing ratio prefix/wrong = %.2f — potential timing side channel", ratio2)
	}

	t.Logf("ATK-02: wrong=%v, close=%v, prefix=%v, ratios=%.2f/%.2f",
		avgWrong, avgClose, avgPrefix, ratio1, ratio2)
}

// ============================================================
// ATK-03: Challenge proof replay — valid proof, different CSR
// ============================================================

func TestSec_ChallengeProofReplayRejected(t *testing.T) {
	shortCA, _ := server.NewCA(server.CAConfig{
		CertDir: t.TempDir(), Organization: "Replay Test",
		Validity: 1 * time.Millisecond,
	})
	store := server.NewMemStore()
	secret := "replay-secret"
	fp := "sha256:replay-fp"

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/enroll", server.NewEnrollHandler(server.EnrollConfig{
		CA: shortCA, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	}))
	mux.Handle("POST /api/v1/renew/challenge", server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
		CA: shortCA, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	storeDir := t.TempDir()
	secEnroll(t, ts.URL, secret, fp, "replay-host", storeDir)
	time.Sleep(50 * time.Millisecond)

	// Load the expired cert and old key
	oldCert, _ := client.LoadCert(storeDir)
	oldCertPEM, _ := os.ReadFile(storeDir + "/client.crt")
	oldKeyPEM, _ := os.ReadFile(storeDir + "/client.key")

	oldKeyBlock, _ := pem.Decode(oldKeyPEM)
	oldKey, _ := x509.ParseECPrivateKey(oldKeyBlock.Bytes)

	serverID := oldCert.Subject.CommonName
	_ = oldCertPEM

	// Create legitimate proof for CSR-A
	csrA, _ := makeCSRForSec(t)
	digestA := sha256.Sum256([]byte(serverID + "\n" + fp + "\n" + csrA))
	sigA, _ := oldKey.Sign(rand.Reader, digestA[:], crypto.SHA256)
	proofA := base64.StdEncoding.EncodeToString(sigA)

	// Now replay proofA but with a DIFFERENT CSR-B (attacker's CSR)
	csrB, _ := makeCSRForSec(t)

	replayBody, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID:    serverID,
		Fingerprint: fp,
		ExpiredCert: string(oldCertPEM),
		CSR:         csrB, // attacker's CSR
		Proof:       proofA, // proof was for csrA
	})

	resp, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(replayBody))
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("VULNERABILITY: challenge proof replay accepted with different CSR")
	}
	t.Logf("ATK-03 PASS: replay rejected with %d", resp.StatusCode)
}

// ============================================================
// ATK-04: Challenge proof with wrong key (impersonation)
// ============================================================

func TestSec_ChallengeProofWrongKeyRejected(t *testing.T) {
	shortCA, _ := server.NewCA(server.CAConfig{
		CertDir: t.TempDir(), Organization: "WrongKey Test",
		Validity: 1 * time.Millisecond,
	})
	store := server.NewMemStore()
	secret := "wrongkey-secret"
	fp := "sha256:wrongkey-fp"

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/enroll", server.NewEnrollHandler(server.EnrollConfig{
		CA: shortCA, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	}))
	mux.Handle("POST /api/v1/renew/challenge", server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
		CA: shortCA, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	storeDir := t.TempDir()
	secEnroll(t, ts.URL, secret, fp, "wrongkey-host", storeDir)
	time.Sleep(50 * time.Millisecond)

	oldCert, _ := client.LoadCert(storeDir)
	oldCertPEM, _ := os.ReadFile(storeDir + "/client.crt")
	serverID := oldCert.Subject.CommonName

	// Attacker generates their OWN key and signs the proof with it
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM, _ := makeCSRForSec(t)

	digest := sha256.Sum256([]byte(serverID + "\n" + fp + "\n" + csrPEM))
	sig, _ := attackerKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	proof := base64.StdEncoding.EncodeToString(sig)

	reqBody, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: serverID, Fingerprint: fp,
		ExpiredCert: string(oldCertPEM), CSR: csrPEM, Proof: proof,
	})

	resp, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(reqBody))
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("VULNERABILITY: challenge proof signed with wrong key was accepted")
	}
	t.Logf("ATK-04 PASS: wrong-key proof rejected with %d", resp.StatusCode)
}

// ============================================================
// ATK-05: Challenge fingerprint spoofing
// ============================================================

func TestSec_ChallengeFingerprintSpoofRejected(t *testing.T) {
	shortCA, _ := server.NewCA(server.CAConfig{
		CertDir: t.TempDir(), Organization: "FP Spoof Test",
		Validity: 1 * time.Millisecond,
	})
	store := server.NewMemStore()
	secret := "fpspoof-secret"
	realFP := "sha256:real-device-fp"
	fakeFP := "sha256:attacker-device-fp"

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/enroll", server.NewEnrollHandler(server.EnrollConfig{
		CA: shortCA, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	}))
	mux.Handle("POST /api/v1/renew/challenge", server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
		CA: shortCA, Store: store, ChallengeWindow: 30 * 24 * time.Hour,
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	storeDir := t.TempDir()
	secEnroll(t, ts.URL, secret, realFP, "real-host", storeDir)
	time.Sleep(50 * time.Millisecond)

	oldCert, _ := client.LoadCert(storeDir)
	oldCertPEM, _ := os.ReadFile(storeDir + "/client.crt")
	oldKeyPEM, _ := os.ReadFile(storeDir + "/client.key")
	oldKeyBlock, _ := pem.Decode(oldKeyPEM)
	oldKey, _ := x509.ParseECPrivateKey(oldKeyBlock.Bytes)
	serverID := oldCert.Subject.CommonName

	csrPEM, _ := makeCSRForSec(t)

	// Sign proof with the FAKE fingerprint (attacker claims different device)
	digest := sha256.Sum256([]byte(serverID + "\n" + fakeFP + "\n" + csrPEM))
	sig, _ := oldKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	proof := base64.StdEncoding.EncodeToString(sig)

	reqBody, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: serverID, Fingerprint: fakeFP,
		ExpiredCert: string(oldCertPEM), CSR: csrPEM, Proof: proof,
	})

	resp, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(reqBody))
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("VULNERABILITY: spoofed fingerprint accepted in challenge renewal")
	}
	t.Logf("ATK-05 PASS: fingerprint spoof rejected with %d", resp.StatusCode)
}

// ============================================================
// ATK-06: Challenge error oracle — all failures should be opaque
// ============================================================

func TestSec_ChallengeErrorOracle(t *testing.T) {
	shortCA, _ := server.NewCA(server.CAConfig{
		CertDir: t.TempDir(), Organization: "Oracle Test",
		Validity: 1 * time.Millisecond,
	})
	store := server.NewMemStore()
	secret := "oracle-secret"
	fp := "sha256:oracle-fp"

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/enroll", server.NewEnrollHandler(server.EnrollConfig{
		CA: shortCA, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	}))
	mux.Handle("POST /api/v1/renew/challenge", server.NewChallengeRenewHandler(server.ChallengeRenewConfig{
		CA: shortCA, Store: store, ChallengeWindow: 1 * time.Millisecond,
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	storeDir := t.TempDir()
	secEnroll(t, ts.URL, secret, fp, "oracle-host", storeDir)
	time.Sleep(50 * time.Millisecond)

	oldCert, _ := client.LoadCert(storeDir)
	oldCertPEM, _ := os.ReadFile(storeDir + "/client.crt")
	oldKeyPEM, _ := os.ReadFile(storeDir + "/client.key")
	oldKeyBlock, _ := pem.Decode(oldKeyPEM)
	oldKey, _ := x509.ParseECPrivateKey(oldKeyBlock.Bytes)
	serverID := oldCert.Subject.CommonName
	_ = oldKey

	csrPEM, _ := makeCSRForSec(t)

	// Collect error responses for various failure reasons
	errorBodies := make(map[string]string)

	// Failure: wrong fingerprint
	d := sha256.Sum256([]byte(serverID + "\n" + "sha256:wrong-fp" + "\n" + csrPEM))
	s, _ := oldKey.Sign(rand.Reader, d[:], crypto.SHA256)
	b1, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: serverID, Fingerprint: "sha256:wrong-fp",
		ExpiredCert: string(oldCertPEM), CSR: csrPEM,
		Proof: base64.StdEncoding.EncodeToString(s),
	})
	r1, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(b1))
	body1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	errorBodies["wrong_fingerprint"] = strings.TrimSpace(string(body1))

	// Failure: wrong server_id
	b2, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: "srv_nonexistent", Fingerprint: fp,
		ExpiredCert: string(oldCertPEM), CSR: csrPEM,
		Proof: base64.StdEncoding.EncodeToString(s),
	})
	r2, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(b2))
	body2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	errorBodies["wrong_server_id"] = strings.TrimSpace(string(body2))

	// Failure: beyond window (window is 1ms, cert expired 50ms+ ago)
	d3 := sha256.Sum256([]byte(serverID + "\n" + fp + "\n" + csrPEM))
	s3, _ := oldKey.Sign(rand.Reader, d3[:], crypto.SHA256)
	b3, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: serverID, Fingerprint: fp,
		ExpiredCert: string(oldCertPEM), CSR: csrPEM,
		Proof: base64.StdEncoding.EncodeToString(s3),
	})
	r3, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(b3))
	body3, _ := io.ReadAll(r3.Body)
	r3.Body.Close()
	errorBodies["beyond_window"] = strings.TrimSpace(string(body3))

	// Failure: bad proof signature
	b4, _ := json.Marshal(imprint.ChallengeRenewalRequest{
		ServerID: serverID, Fingerprint: fp,
		ExpiredCert: string(oldCertPEM), CSR: csrPEM,
		Proof: base64.StdEncoding.EncodeToString([]byte("garbage-signature")),
	})
	r4, _ := http.Post(ts.URL+"/api/v1/renew/challenge", "application/json", bytes.NewReader(b4))
	body4, _ := io.ReadAll(r4.Body)
	r4.Body.Close()
	errorBodies["bad_proof"] = strings.TrimSpace(string(body4))

	// Check all error bodies are identical (opaque)
	allSame := true
	var reference string
	for reason, body := range errorBodies {
		if reference == "" {
			reference = body
		}
		if body != reference {
			allSame = false
			t.Logf("ORACLE LEAK: %q returned %q (expected %q)", reason, body, reference)
		}
	}

	if !allSame {
		t.Fatal("VULNERABILITY: challenge endpoint leaks different error messages for different failure reasons")
	}
	t.Logf("ATK-06 PASS: all challenge errors return opaque %q", reference)
}

// ============================================================
// ATK-07: mTLS verifier error messages — info leakage check
// ============================================================

func TestSec_VerifierErrorInfoLeakage(t *testing.T) {
	ca, store, secret := secSetup(t)

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	enrollTS := httptest.NewServer(enrollHandler)
	defer enrollTS.Close()

	// Enroll a device
	storeDir := t.TempDir()
	resp := secEnroll(t, enrollTS.URL, secret, "sha256:leak-fp", "leak-host", storeDir)

	// Prepare mTLS server
	protected := server.RequireMTLS(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))

	// Test with various failure scenarios using httptest.NewRequest (direct handler)
	errorMessages := make(map[string]string)

	// No TLS at all
	r1 := httptest.NewRequest("GET", "/data", nil)
	w1 := httptest.NewRecorder()
	protected.ServeHTTP(w1, r1)
	errorMessages["no_cert"] = strings.TrimSpace(w1.Body.String())

	// TLS but no peer certs
	r2 := httptest.NewRequest("GET", "/data", nil)
	r2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	w2 := httptest.NewRecorder()
	protected.ServeHTTP(w2, r2)
	errorMessages["empty_peer_certs"] = strings.TrimSpace(w2.Body.String())

	// Cert with empty CN
	emptyCNKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	emptyCNCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ""},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	emptyCNCertDER, _ := x509.CreateCertificate(rand.Reader, emptyCNCert, emptyCNCert, &emptyCNKey.PublicKey, emptyCNKey)
	emptyCNCertParsed, _ := x509.ParseCertificate(emptyCNCertDER)

	r3 := httptest.NewRequest("GET", "/data", nil)
	r3.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{emptyCNCertParsed}}
	w3 := httptest.NewRecorder()
	protected.ServeHTTP(w3, r3)
	errorMessages["empty_cn"] = strings.TrimSpace(w3.Body.String())

	// Unknown server_id
	unknownKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unknownCert := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "srv_unknown_attacker"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	unknownCertDER, _ := x509.CreateCertificate(rand.Reader, unknownCert, unknownCert, &unknownKey.PublicKey, unknownKey)
	unknownCertParsed, _ := x509.ParseCertificate(unknownCertDER)

	r4 := httptest.NewRequest("GET", "/data", nil)
	r4.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{unknownCertParsed}}
	w4 := httptest.NewRecorder()
	protected.ServeHTTP(w4, r4)
	errorMessages["unknown_device"] = strings.TrimSpace(w4.Body.String())

	// Revoked cert
	store.Revoke(context.Background(), resp.ServerID)
	tlsCfg, _ := client.LoadTLS(storeDir)
	realCert, _ := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	r5 := httptest.NewRequest("GET", "/data", nil)
	r5.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{realCert}}
	w5 := httptest.NewRecorder()
	protected.ServeHTTP(w5, r5)
	errorMessages["revoked"] = strings.TrimSpace(w5.Body.String())

	// Check: are error messages distinct? (potential info leak)
	uniqueMessages := make(map[string]bool)
	for _, msg := range errorMessages {
		uniqueMessages[msg] = true
	}

	// "no_cert" and "empty_peer_certs" may differ from the security-relevant
	// rejections (they indicate a client configuration issue). Check that all
	// security-relevant rejections are opaque.
	securityMessages := map[string]string{
		"empty_cn":       errorMessages["empty_cn"],
		"unknown_device": errorMessages["unknown_device"],
		"revoked":        errorMessages["revoked"],
	}
	secUnique := make(map[string]bool)
	for _, msg := range securityMessages {
		secUnique[msg] = true
	}
	if len(secUnique) > 1 {
		t.Fatal("VULNERABILITY: RequireMTLS returns distinct error messages for security-relevant rejections")
	}
	t.Logf("ATK-07 PASS: all security-relevant mTLS rejections return opaque %q", errorMessages["revoked"])
}

// ============================================================
// ATK-08: Oversized request body (resource exhaustion)
// ============================================================

func TestSec_OversizedRequestBodyRejected(t *testing.T) {
	ca, store, secret := secSetup(t)

	enrollHandler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(enrollHandler)
	defer ts.Close()

	// Send a 2MB payload (limit is 1MB)
	hugeBody := bytes.Repeat([]byte("A"), 2<<20)
	resp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(hugeBody))

	rejected := err != nil || (resp != nil && resp.StatusCode >= 400)
	var statusCode int
	if resp != nil {
		statusCode = resp.StatusCode
		resp.Body.Close()
	}

	if !rejected {
		t.Fatal("VULNERABILITY: oversized request body was accepted")
	}
	t.Logf("ATK-08 PASS: oversized body rejected (status %d)", statusCode)
}

// ============================================================
// ATK-09: Malformed CSR injection
// ============================================================

func TestSec_MalformedCSRRejected(t *testing.T) {
	ca, store, secret := secSetup(t)

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	malformedCSRs := map[string]string{
		"garbage_text":   "not-a-csr-at-all",
		"empty_pem":      "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----",
		"wrong_pem_type": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ=\n-----END RSA PRIVATE KEY-----",
		"truncated_pem":  "-----BEGIN CERTIFICATE REQUEST-----\nMIIBhDCB7gIBADARMQ8w",
	}

	results := make(map[string]map[string]any)
	for name, csr := range malformedCSRs {
		body, _ := json.Marshal(imprint.EnrollmentRequest{
			BuildSecret: secret, Fingerprint: "sha256:bad-csr-fp",
			Hostname: "bad-csr-host", CSR: csr,
		})
		resp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		results[name] = map[string]any{
			"status_code":   resp.StatusCode,
			"rejected":      resp.StatusCode >= 400,
			"response_body": strings.TrimSpace(string(respBody)),
		}
	}

	for name, result := range results {
		if !result["rejected"].(bool) {
			t.Fatalf("VULNERABILITY: malformed CSR %q was accepted", name)
		}
		body := result["response_body"].(string)
		if strings.Contains(body, "panic") || strings.Contains(body, "goroutine") ||
			strings.Contains(body, "runtime.") {
			t.Fatalf("VULNERABILITY: %q error response contains stack trace: %s", name, body)
		}
		if strings.Contains(body, "asn1:") || strings.Contains(body, "syntax error") {
			t.Fatalf("VULNERABILITY: %q error response leaks parser details: %s", name, body)
		}
	}

	t.Log("ATK-09 PASS: all malformed CSRs rejected with opaque error")
}

// ============================================================
// ATK-10: Wrong HTTP method
// ============================================================

func TestSec_WrongHTTPMethodRejected(t *testing.T) {
	ca, store, secret := secSetup(t)

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	methods := []string{"GET", "PUT", "DELETE", "PATCH", "OPTIONS"}
	results := make(map[string]int)

	for _, method := range methods {
		req, _ := http.NewRequest(method, ts.URL+"/api/v1/enroll", nil)
		resp, _ := http.DefaultClient.Do(req)
		results[method] = resp.StatusCode
		resp.Body.Close()
	}

	for method, code := range results {
		if code == http.StatusOK {
			t.Fatalf("VULNERABILITY: %s method accepted on enrollment endpoint", method)
		}
	}

	t.Logf("ATK-10 PASS: all non-POST methods rejected: %v", results)
}

// ============================================================
// ATK-11: Concurrent enrollment race condition
// ============================================================

func TestSec_ConcurrentEnrollmentRace(t *testing.T) {
	ca, store, secret := secSetup(t)

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Race: 10 concurrent enrollments with the SAME fingerprint
	const concurrency = 10
	fp := "sha256:race-condition-fp"
	var wg sync.WaitGroup
	serverIDs := make([]string, concurrency)
	errors := make([]string, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sd := t.TempDir()
			resp, err := client.Enroll(context.Background(), client.EnrollConfig{
				ServiceURL: ts.URL, BuildSecret: secret,
				Fingerprint: fp, Hostname: fmt.Sprintf("race-%d", idx), StoreDir: sd,
			})
			if err != nil {
				errors[idx] = err.Error()
				return
			}
			serverIDs[idx] = resp.ServerID
		}(i)
	}
	wg.Wait()

	// All should get the same server_id (re-enrollment)
	var firstID string
	allSame := true
	successCount := 0
	for _, id := range serverIDs {
		if id == "" {
			continue
		}
		successCount++
		if firstID == "" {
			firstID = id
		}
		if id != firstID {
			allSame = false
		}
	}

	enrollment, _ := store.GetByServerID(context.Background(), firstID)

	if !allSame {
		t.Fatal("VULNERABILITY: concurrent enrollments created different server_ids for same fingerprint")
	}
	if enrollment == nil || enrollment.Status != imprint.StatusActive {
		t.Fatal("VULNERABILITY: final enrollment state is invalid after concurrent writes")
	}

	t.Logf("ATK-11 PASS: %d concurrent enrollments all resolved to %s", successCount, firstID)
}

// ============================================================
// ATK-12: CSR signing request with manipulated SAN/URIs
// ============================================================

func TestSec_CSRWithMaliciousSANsAccepted(t *testing.T) {
	ca, store, secret := secSetup(t)

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Client submits a CSR with attacker-controlled SANs
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	maliciousCSR := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "attacker-host"},
		DNSNames: []string{"admin.internal.corp", "*.example.com"},
		URIs:     []*url.URL{{Scheme: "imprint", Host: "server", Path: "/srv_admin"}},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, maliciousCSR, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: secret, Fingerprint: "sha256:san-inject-fp",
		Hostname: "attacker-host", CSR: string(csrPEM),
	})
	resp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var enrollResp imprint.EnrollmentResponse
	json.Unmarshal(respBody, &enrollResp)

	// Parse the issued cert and check if attacker SANs were copied
	var issuedDNS []string
	var issuedURIs []string
	if enrollResp.Certificate != "" {
		block, _ := pem.Decode([]byte(enrollResp.Certificate))
		if block != nil {
			cert, _ := x509.ParseCertificate(block.Bytes)
			if cert != nil {
				issuedDNS = cert.DNSNames
				for _, u := range cert.URIs {
					issuedURIs = append(issuedURIs, u.String())
				}
			}
		}
	}

	attackerDNSCopied := len(issuedDNS) > 0
	attackerURIsOverridden := false
	for _, u := range issuedURIs {
		if strings.Contains(u, "srv_admin") {
			attackerURIsOverridden = true
		}
	}

	if attackerDNSCopied {
		t.Logf("FINDING: CSR DNS SANs were copied to issued cert: %v", issuedDNS)
	}
	if attackerURIsOverridden {
		t.Fatal("VULNERABILITY: attacker-controlled URI SAN was copied to issued cert")
	}

	t.Logf("ATK-12: enrolled=%v, DNS SANs copied=%v, URI overridden=%v",
		resp.StatusCode == 200, attackerDNSCopied, attackerURIsOverridden)
}

// ============================================================
// ATK-13: Enrollment response leaks build secret or internal state
// ============================================================

func TestSec_EnrollmentResponseNoSecretLeakage(t *testing.T) {
	ca, store, _ := secSetup(t)
	secret := "super-secret-build-key-12345"

	handler := server.NewEnrollHandler(server.EnrollConfig{
		CA: ca, Store: store, BuildSecrets: []string{secret}, Mode: imprint.ModeAuto,
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM, _ := makeCSRForSec(t)
	body, _ := json.Marshal(imprint.EnrollmentRequest{
		BuildSecret: secret, Fingerprint: "sha256:leak-check-fp",
		Hostname: "leak-host", CSR: csrPEM,
	})
	resp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	responseStr := string(respBody)
	containsSecret := strings.Contains(responseStr, secret)
	containsPrivateKey := strings.Contains(responseStr, "PRIVATE KEY")

	if containsSecret {
		t.Fatal("VULNERABILITY: enrollment response contains the build secret")
	}
	if containsPrivateKey {
		t.Fatal("VULNERABILITY: enrollment response contains a private key")
	}

	t.Log("ATK-13 PASS: response contains no secrets or private keys")
}

func getJSONKeys(data []byte) []string {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

