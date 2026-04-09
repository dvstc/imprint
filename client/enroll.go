package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/dvstc/imprint"
)

const defaultHTTPTimeout = 30 * time.Second

func defaultHTTPClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// EnrollConfig configures a client enrollment request.
type EnrollConfig struct {
	ServiceURL  string       // base URL of the enrollment service (e.g. "https://updates.example.com")
	BuildSecret string       // compiled-in build secret
	Fingerprint string       // hardware fingerprint ("sha256:...")
	Hostname    string
	OS          string       // defaults to runtime.GOOS if empty
	Arch        string       // defaults to runtime.GOARCH if empty
	StoreDir    string       // directory to persist enrollment state
	HTTPClient  *http.Client // optional; defaults to a client with 30s timeout
}

// Enroll performs the enrollment handshake with the service.
// It generates an ECDSA keypair, creates a CSR, POSTs to the enrollment
// endpoint, and persists the returned certificate + CA cert to StoreDir.
func Enroll(ctx context.Context, cfg EnrollConfig) (*imprint.EnrollmentResponse, error) {
	if cfg.OS == "" {
		cfg.OS = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}

	// Generate keypair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cfg.Hostname,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Build request
	reqBody := imprint.EnrollmentRequest{
		BuildSecret: cfg.BuildSecret,
		Fingerprint: cfg.Fingerprint,
		Hostname:    cfg.Hostname,
		OS:          cfg.OS,
		Arch:        cfg.Arch,
		CSR:         string(csrPEM),
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// POST to enrollment endpoint
	url := cfg.ServiceURL + "/api/v1/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient(cfg.HTTPClient).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var enrollResp imprint.EnrollmentResponse
	if err := json.Unmarshal(respBody, &enrollResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Persist to disk
	if cfg.StoreDir != "" {
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		if err := SaveEnrollment(
			cfg.StoreDir,
			keyPEM,
			[]byte(enrollResp.Certificate),
			[]byte(enrollResp.CACertificate),
			enrollResp.ServerID,
			cfg.Fingerprint,
		); err != nil {
			return nil, fmt.Errorf("save enrollment: %w", err)
		}
	}

	return &enrollResp, nil
}
