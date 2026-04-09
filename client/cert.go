package client

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultRenewalThreshold is the default duration before certificate expiry
// at which NeedsRenewal returns true (30 days).
const DefaultRenewalThreshold = 30 * 24 * time.Hour

// LoadCert parses the client certificate from the store directory.
func LoadCert(dir string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(dir, clientCertFile))
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("client cert: not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client cert: %w", err)
	}
	return cert, nil
}

// CertExpiry returns the NotAfter time of the client certificate.
func CertExpiry(dir string) (time.Time, error) {
	cert, err := LoadCert(dir)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// NeedsRenewal returns true if the certificate is valid but will expire
// within the given threshold duration.
func NeedsRenewal(dir string, threshold time.Duration) (bool, error) {
	cert, err := LoadCert(dir)
	if err != nil {
		return false, err
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return false, nil
	}
	return time.Until(cert.NotAfter) < threshold, nil
}

// IsExpired returns true if the client certificate's NotAfter is in the past.
func IsExpired(dir string) (bool, error) {
	cert, err := LoadCert(dir)
	if err != nil {
		return false, err
	}
	return time.Now().After(cert.NotAfter), nil
}
