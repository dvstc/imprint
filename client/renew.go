package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dvstc/imprint"
)

// RenewConfig configures certificate renewal requests.
type RenewConfig struct {
	ServiceURL      string        // base URL of the service
	StoreDir        string        // directory containing enrollment state
	ChallengeWindow time.Duration // max age of expired cert for Tier 2; 0 = 30 days
	HTTPClient      *http.Client  // optional; defaults to a client with 30s timeout
}

func (c RenewConfig) challengeWindow() time.Duration {
	if c.ChallengeWindow > 0 {
		return c.ChallengeWindow
	}
	return DefaultRenewalThreshold
}

// Renew performs Tier 1 mTLS certificate renewal. The client must have a valid
// (not-yet-expired) certificate. A new keypair and CSR are generated, and the
// request is authenticated via the existing mTLS credentials.
func Renew(ctx context.Context, cfg RenewConfig) (*imprint.EnrollmentResponse, error) {
	meta, err := LoadMeta(cfg.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("load enrollment meta: %w", err)
	}

	key, csrPEM, err := generateKeypairAndCSR(meta.ServerID)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := LoadTLS(cfg.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("load mTLS config: %w", err)
	}

	reqBody := imprint.RenewalRequest{CSR: string(csrPEM)}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.ServiceURL+"/api/v1/renew", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	base := defaultHTTPClient(cfg.HTTPClient)
	base.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	resp, err := base.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("renewal request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renewal failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var renewResp imprint.EnrollmentResponse
	if err := json.Unmarshal(respBody, &renewResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := SaveEnrollment(
		cfg.StoreDir, keyPEM,
		[]byte(renewResp.Certificate),
		[]byte(renewResp.CACertificate),
		renewResp.ServerID, meta.Fingerprint,
	); err != nil {
		return nil, fmt.Errorf("save renewed enrollment: %w", err)
	}

	return &renewResp, nil
}

// ChallengeRenew performs Tier 2 challenge-based renewal for expired certificates.
// The client proves identity by signing a digest with the old private key.
// The fingerprint parameter should be the device's current hardware fingerprint.
func ChallengeRenew(ctx context.Context, cfg RenewConfig, fingerprint string) (*imprint.EnrollmentResponse, error) {
	oldCert, err := LoadCert(cfg.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("load expired cert: %w", err)
	}
	serverID := oldCert.Subject.CommonName

	oldCertPEM, err := os.ReadFile(filepath.Join(cfg.StoreDir, clientCertFile))
	if err != nil {
		return nil, fmt.Errorf("read expired cert PEM: %w", err)
	}

	oldKeyPEM, err := os.ReadFile(filepath.Join(cfg.StoreDir, clientKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read old private key: %w", err)
	}
	signer, err := parsePrivateKey(oldKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse old private key: %w", err)
	}

	newKey, csrPEM, err := generateKeypairAndCSR(serverID)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(serverID + "\n" + fingerprint + "\n" + string(csrPEM)))
	var opts crypto.SignerOpts
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		opts = crypto.SHA256
	case ed25519.PublicKey:
		opts = crypto.Hash(0)
	default:
		return nil, fmt.Errorf("unsupported key type for proof signing: %T", signer.Public())
	}
	sigBytes, err := signer.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		return nil, fmt.Errorf("sign proof: %w", err)
	}
	proof := base64.StdEncoding.EncodeToString(sigBytes)

	reqBody := imprint.ChallengeRenewalRequest{
		ServerID:    serverID,
		Fingerprint: fingerprint,
		ExpiredCert: string(oldCertPEM),
		CSR:         string(csrPEM),
		Proof:       proof,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.ServiceURL+"/api/v1/renew/challenge", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient(cfg.HTTPClient).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("challenge renewal request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("challenge renewal failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var renewResp imprint.EnrollmentResponse
	if err := json.Unmarshal(respBody, &renewResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	newKeyDER, err := x509.MarshalECPrivateKey(newKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newKeyDER})

	if err := SaveEnrollment(
		cfg.StoreDir, newKeyPEM,
		[]byte(renewResp.Certificate),
		[]byte(renewResp.CACertificate),
		renewResp.ServerID, fingerprint,
	); err != nil {
		return nil, fmt.Errorf("save renewed enrollment: %w", err)
	}

	return &renewResp, nil
}

// RenewOrReenroll implements the three-tier renewal fallback:
//  1. If no cert on disk: re-enroll (Tier 3)
//  2. If cert valid but nearing expiry: mTLS renew (Tier 1)
//  3. If cert expired within challenge window: challenge renew (Tier 2)
//  4. If cert expired beyond window or Tier 2 fails: re-enroll (Tier 3)
//
// Returns the action taken: "renewed", "challenge_renewed", "reenrolled", or "none".
func RenewOrReenroll(ctx context.Context, renewCfg RenewConfig, enrollCfg EnrollConfig, threshold time.Duration) (string, error) {
	if threshold == 0 {
		threshold = DefaultRenewalThreshold
	}

	if !IsEnrolled(renewCfg.StoreDir) {
		if _, err := Enroll(ctx, enrollCfg); err != nil {
			return "", fmt.Errorf("enroll: %w", err)
		}
		return "reenrolled", nil
	}

	cert, err := LoadCert(renewCfg.StoreDir)
	if err != nil {
		if _, err := Enroll(ctx, enrollCfg); err != nil {
			return "", fmt.Errorf("enroll after cert parse failure: %w", err)
		}
		return "reenrolled", nil
	}

	now := time.Now()
	expired := now.After(cert.NotAfter)
	nearingExpiry := !expired && time.Until(cert.NotAfter) < threshold

	if !expired && !nearingExpiry {
		return "none", nil
	}

	// Tier 1: mTLS renewal (only if cert is still valid)
	if !expired {
		if _, err := Renew(ctx, renewCfg); err == nil {
			return "renewed", nil
		}
	}

	// Tier 2: challenge renewal (only if within challenge window)
	window := renewCfg.challengeWindow()
	if expired && time.Since(cert.NotAfter) <= window {
		if _, err := ChallengeRenew(ctx, renewCfg, enrollCfg.Fingerprint); err == nil {
			return "challenge_renewed", nil
		}
	}

	// Tier 3: re-enrollment
	if _, err := Enroll(ctx, enrollCfg); err != nil {
		return "", fmt.Errorf("re-enroll: %w", err)
	}
	return "reenrolled", nil
}

func generateKeypairAndCSR(cn string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return key, csrPEM, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("not valid PEM")
	}

	// Try EC first (current key type)
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8 (supports EC, Ed25519, RSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("parsed key does not implement crypto.Signer")
	}

	return nil, fmt.Errorf("unsupported private key format")
}
