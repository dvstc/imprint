package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// LoadTLS reads the enrollment credentials from dir and returns a *tls.Config
// configured for mTLS. The certificate is loaded once at call time.
// Use this for short-lived processes. For long-running services with
// AutoRenewer, use ReloadableTLS instead.
func LoadTLS(dir string) (*tls.Config, error) {
	certPath := filepath.Join(dir, clientCertFile)
	keyPath := filepath.Join(dir, clientKeyFile)
	caPath := filepath.Join(dir, caCertFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ReloadableTLS returns a *tls.Config that reloads the client certificate
// from disk on every new TLS connection. This allows renewed certificates
// to be picked up automatically without restarting the process.
// Use this with AutoRenewer for long-running services.
//
// Note: the CA certificate (RootCAs) is loaded once at call time and is not
// reloaded on subsequent connections. This is acceptable because CA certificates
// have a long validity period (20 years by default). If CA rotation support is
// needed in the future, the caller should recreate the TLS config.
func ReloadableTLS(dir string) (*tls.Config, error) {
	if !IsEnrolled(dir) {
		return nil, fmt.Errorf("not enrolled: no certificates in %s", dir)
	}

	caPath := filepath.Join(dir, caCertFile)
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	certPath := filepath.Join(dir, clientCertFile)
	keyPath := filepath.Join(dir, clientKeyFile)

	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}
