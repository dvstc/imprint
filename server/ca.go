package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caCertFilename = "ca.crt"
	caKeyFilename  = "ca.key"
	defaultValidity = 365 * 24 * time.Hour // 1 year
)

// CAConfig controls CA initialization.
type CAConfig struct {
	CertDir      string        // directory to store/load CA cert and key
	Organization string        // organization name in the CA certificate subject
	Validity     time.Duration // client certificate validity; 0 = default (1 year)
}

// CA manages an internal certificate authority for signing client enrollment CSRs.
type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	validity time.Duration

	mu     sync.Mutex
	serial *big.Int // monotonically increasing serial number
}

// NewCA loads an existing CA from CertDir or generates a new one if none exists.
func NewCA(cfg CAConfig) (*CA, error) {
	if cfg.CertDir == "" {
		return nil, fmt.Errorf("imprint/server: CAConfig.CertDir is required")
	}
	if cfg.Organization == "" {
		cfg.Organization = "Imprint CA"
	}
	validity := cfg.Validity
	if validity == 0 {
		validity = defaultValidity
	}

	certPath := filepath.Join(cfg.CertDir, caCertFilename)
	keyPath := filepath.Join(cfg.CertDir, caKeyFilename)

	// Try to load existing CA
	if fileExists(certPath) && fileExists(keyPath) {
		return loadCA(certPath, keyPath, validity)
	}

	// Generate new CA
	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}
	return generateCA(certPath, keyPath, cfg.Organization, validity)
}

func loadCA(certPath, keyPath string, validity time.Duration) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	keyRaw, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{
		cert:     cert,
		key:      keyRaw,
		certPEM:  certPEM,
		validity: validity,
		serial:   big.NewInt(time.Now().UnixNano()),
	}, nil
}

func generateCA(certPath, keyPath, org string, validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   org,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour), // 20 year CA
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse new CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	return &CA{
		cert:     cert,
		key:      key,
		certPEM:  certPEM,
		validity: validity,
		serial:   big.NewInt(time.Now().UnixNano()),
	}, nil
}

// SignCSR signs a PKCS#10 CSR and returns a PEM-encoded client certificate.
// The certificate CN is set to the given serverID, and a SAN URI of
// imprint://server/<serverID> is added.
func (ca *CA) SignCSR(csr *x509.CertificateRequest, serverID string) (certPEM []byte, serialHex string, err error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("invalid CSR signature: %w", err)
	}

	serial := ca.nextSerial()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   serverID,
			Organization: ca.cert.Subject.Organization,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(ca.validity),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		URIs: []*url.URL{
			{Scheme: "imprint", Host: "server", Path: "/" + serverID},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, "", fmt.Errorf("sign certificate: %w", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return encoded, fmt.Sprintf("%x", serial), nil
}

// CACertPEM returns the PEM-encoded CA certificate.
func (ca *CA) CACertPEM() []byte {
	return ca.certPEM
}

// CertPool returns an x509.CertPool containing the CA certificate,
// suitable for use in tls.Config.ClientCAs.
func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// ServerTLSConfig returns a tls.Config that verifies client certificates
// signed by this CA. ClientAuth is set to VerifyClientCertIfGiven so that
// unauthenticated routes (enrollment, health) still work.
func (ca *CA) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:  ca.CertPool(),
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
}

func (ca *CA) nextSerial() *big.Int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.serial.Add(ca.serial, big.NewInt(1))
	return new(big.Int).Set(ca.serial)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
