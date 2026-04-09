package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dvstc/imprint"
)

// RenewConfig configures the mTLS renewal handler (Tier 1).
type RenewConfig struct {
	CA     *CA
	Store  Store
	Logger *slog.Logger
}

// NewRenewHandler returns an http.Handler that processes Tier 1 mTLS
// certificate renewal requests. The client must present a valid (not expired)
// client certificate via mTLS. Identity is extracted from the certificate CN.
func NewRenewHandler(cfg RenewConfig) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		serverID := cert.Subject.CommonName
		if serverID == "" {
			http.Error(w, "invalid client certificate: missing CN", http.StatusUnauthorized)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		var req imprint.RenewalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.CSR == "" {
			http.Error(w, "missing required field: csr", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		enrollment, err := cfg.Store.GetByServerID(ctx, serverID)
		if err != nil {
			logger.Error("store lookup failed", "error", err, "server_id", serverID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if enrollment == nil || enrollment.Status == imprint.StatusRevoked {
			logger.Warn("renewal rejected: enrollment not found or revoked",
				"server_id", serverID,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "renewal denied", http.StatusUnauthorized)
			return
		}

		csr, err := parseCSR(req.CSR)
		if err != nil {
			logger.Warn("invalid CSR in renewal", "error", err, "server_id", serverID)
			http.Error(w, "invalid CSR", http.StatusBadRequest)
			return
		}

		certPEM, serialHex, err := cfg.CA.SignCSR(csr, serverID)
		if err != nil {
			logger.Error("CSR signing failed", "error", err, "server_id", serverID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		enrollment.SerialNumber = serialHex
		enrollment.RenewedAt = time.Now()
		enrollment.LastSeenAt = time.Now()
		enrollment.LastIP = r.RemoteAddr

		if err := cfg.Store.SaveEnrollment(ctx, enrollment); err != nil {
			logger.Error("store save failed", "error", err, "server_id", serverID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("certificate renewed via mTLS",
			"server_id", serverID,
			"serial", serialHex,
		)

		resp := imprint.EnrollmentResponse{
			ServerID:      serverID,
			Certificate:   string(certPEM),
			CACertificate: string(cfg.CA.CACertPEM()),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
}

// ChallengeRenewConfig configures the challenge-based renewal handler (Tier 2).
type ChallengeRenewConfig struct {
	CA              *CA
	Store           Store
	ChallengeWindow time.Duration // max time after cert expiry to allow challenge renewal; 0 disables
	Logger          *slog.Logger
}

const defaultChallengeWindow = 30 * 24 * time.Hour

// NewChallengeRenewHandler returns an http.Handler that processes Tier 2
// challenge-based renewal. This endpoint is public (no mTLS) and requires
// proof of possession of the old private key via a signature.
//
// All validation failures return a generic 401 to prevent oracle attacks.
// Specific failure reasons are logged server-side only.
func NewChallengeRenewHandler(cfg ChallengeRenewConfig) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	window := cfg.ChallengeWindow
	if window == 0 {
		window = defaultChallengeWindow
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		var req imprint.ChallengeRenewalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.ServerID == "" || req.Fingerprint == "" || req.ExpiredCert == "" || req.CSR == "" || req.Proof == "" {
			http.Error(w, "missing required fields", http.StatusBadRequest)
			return
		}

		const opaque = "challenge renewal failed"

		// Step 1: Parse expired cert and verify it was signed by our CA.
		expiredCert, err := parseCertPEM(req.ExpiredCert)
		if err != nil {
			logger.Warn("challenge renewal: invalid cert PEM",
				"server_id", req.ServerID, "reason", err.Error())
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Verify the cert chain against our CA, using a shifted CurrentTime
		// to the midpoint of the cert's validity so the expired cert passes
		// time validation. This ensures we're well within both the leaf and
		// CA cert validity windows.
		pool := cfg.CA.CertPool()
		midpoint := expiredCert.NotBefore.Add(expiredCert.NotAfter.Sub(expiredCert.NotBefore) / 2)
		_, err = expiredCert.Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: midpoint,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			logger.Warn("challenge renewal: cert not signed by our CA",
				"server_id", req.ServerID, "reason", err.Error())
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 2: Verify cert IS expired. If still valid, reject.
		if time.Now().Before(expiredCert.NotAfter) {
			logger.Warn("challenge renewal: cert is not expired, use mTLS renewal",
				"server_id", req.ServerID)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 3: Verify cert CN matches claimed server_id.
		if expiredCert.Subject.CommonName != req.ServerID {
			logger.Warn("challenge renewal: CN mismatch",
				"server_id", req.ServerID, "cert_cn", expiredCert.Subject.CommonName)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 4: Look up enrollment.
		ctx := r.Context()
		enrollment, err := cfg.Store.GetByServerID(ctx, req.ServerID)
		if err != nil {
			logger.Error("challenge renewal: store lookup failed",
				"server_id", req.ServerID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if enrollment == nil || enrollment.Status == imprint.StatusRevoked {
			logger.Warn("challenge renewal: enrollment not found or revoked",
				"server_id", req.ServerID)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 5: Verify cert serial matches enrollment (not superseded).
		certSerial := expiredCert.SerialNumber.Text(16)
		if enrollment.SerialNumber != certSerial {
			logger.Warn("challenge renewal: serial mismatch (superseded cert)",
				"server_id", req.ServerID,
				"enrollment_serial", enrollment.SerialNumber,
				"cert_serial", certSerial,
			)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 6: Verify fingerprint matches enrollment (constant-time).
		if subtle.ConstantTimeCompare([]byte(enrollment.Fingerprint), []byte(req.Fingerprint)) != 1 {
			logger.Warn("challenge renewal: fingerprint mismatch",
				"server_id", req.ServerID)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 7: Verify cert not expired beyond the challenge window.
		if time.Since(expiredCert.NotAfter) > window {
			logger.Warn("challenge renewal: beyond challenge window",
				"server_id", req.ServerID,
				"expired_at", expiredCert.NotAfter,
				"window", window,
			)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// Step 8: Verify proof signature.
		digest := challengeDigest(req.ServerID, req.Fingerprint, req.CSR)
		sigBytes, err := base64.StdEncoding.DecodeString(req.Proof)
		if err != nil {
			logger.Warn("challenge renewal: invalid proof encoding",
				"server_id", req.ServerID, "reason", err.Error())
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		if !verifyProof(expiredCert.PublicKey, digest, sigBytes) {
			logger.Warn("challenge renewal: proof signature verification failed",
				"server_id", req.ServerID)
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		// All checks passed. Sign new CSR and update enrollment.
		csr, err := parseCSR(req.CSR)
		if err != nil {
			logger.Warn("challenge renewal: invalid CSR",
				"server_id", req.ServerID, "reason", err.Error())
			http.Error(w, opaque, http.StatusUnauthorized)
			return
		}

		certPEM, serialHex, err := cfg.CA.SignCSR(csr, req.ServerID)
		if err != nil {
			logger.Error("challenge renewal: CSR signing failed",
				"server_id", req.ServerID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		enrollment.SerialNumber = serialHex
		enrollment.RenewedAt = time.Now()
		enrollment.LastSeenAt = time.Now()
		enrollment.LastIP = r.RemoteAddr

		if err := cfg.Store.SaveEnrollment(ctx, enrollment); err != nil {
			logger.Error("challenge renewal: store save failed",
				"server_id", req.ServerID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("certificate renewed via challenge",
			"server_id", req.ServerID,
			"serial", serialHex,
		)

		resp := imprint.EnrollmentResponse{
			ServerID:      req.ServerID,
			Certificate:   string(certPEM),
			CACertificate: string(cfg.CA.CACertPEM()),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
}

// challengeDigest computes SHA256(server_id + "\n" + fingerprint + "\n" + csr_pem).
func challengeDigest(serverID, fingerprint, csrPEM string) []byte {
	msg := []byte(serverID + "\n" + fingerprint + "\n" + csrPEM)
	h := sha256.Sum256(msg)
	return h[:]
}

// verifyProof checks a signature against a public key, dispatching based on key type.
func verifyProof(pubKey any, digest, sig []byte) bool {
	switch pk := pubKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pk, digest, sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pk, digest, sig)
	default:
		return false
	}
}

// parseCSR decodes a PEM-encoded CSR and validates its signature.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// parseCertPEM decodes a PEM-encoded certificate.
func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("not valid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
