package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dvstc/imprint"
)

// EnrollConfig configures the enrollment handler.
type EnrollConfig struct {
	CA           *CA
	Store        Store
	BuildSecrets []string           // allowlist of valid build secrets
	Mode         imprint.EnrollMode // ModeAuto, ModeToken, ModeApproval
	Logger       *slog.Logger
}

// NewEnrollHandler returns an http.Handler that processes device enrollment requests.
func NewEnrollHandler(cfg EnrollConfig) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		var req imprint.EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.BuildSecret == "" || req.Fingerprint == "" || req.CSR == "" {
			http.Error(w, "missing required fields: build_secret, fingerprint, csr", http.StatusBadRequest)
			return
		}

		if !validateBuildSecret(req.BuildSecret, cfg.BuildSecrets) {
			logger.Warn("enrollment rejected: invalid build secret",
				"fingerprint", req.Fingerprint,
				"hostname", req.Hostname,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch cfg.Mode {
		case imprint.ModeAuto:
			// proceed
		case imprint.ModeToken:
			http.Error(w, "token enrollment not yet implemented", http.StatusNotImplemented)
			return
		case imprint.ModeApproval:
			http.Error(w, "approval enrollment not yet implemented", http.StatusNotImplemented)
			return
		}

		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			http.Error(w, "invalid CSR", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			logger.Warn("invalid CSR", "error", err, "fingerprint", req.Fingerprint)
			http.Error(w, "invalid CSR", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		candidate := &imprint.Enrollment{
			ServerID:    generateServerID(),
			Fingerprint: req.Fingerprint,
			Hostname:    req.Hostname,
			OS:          req.OS,
			Arch:        req.Arch,
			EnrolledAt:  time.Now(),
			LastSeenAt:  time.Now(),
			LastIP:      r.RemoteAddr,
			Status:      imprint.StatusActive,
		}

		enrolled, created, err := cfg.Store.EnrollDevice(ctx, req.Fingerprint, candidate)
		if err != nil {
			logger.Error("store enroll failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		serverID := enrolled.ServerID
		if !created {
			logger.Info("re-enrollment for existing device",
				"server_id", serverID,
				"fingerprint", req.Fingerprint,
			)
		}

		certPEM, serialHex, err := cfg.CA.SignCSR(csr, serverID)
		if err != nil {
			logger.Error("CSR signing failed", "error", err)
			if created {
				_ = cfg.Store.Delete(ctx, serverID)
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		enrollment := &imprint.Enrollment{
			ServerID:     serverID,
			Fingerprint:  req.Fingerprint,
			Hostname:     req.Hostname,
			OS:           req.OS,
			Arch:         req.Arch,
			SerialNumber: serialHex,
			EnrolledAt:   time.Now(),
			LastSeenAt:   time.Now(),
			LastIP:       r.RemoteAddr,
			Status:       imprint.StatusActive,
		}

		if err := cfg.Store.SaveEnrollment(ctx, enrollment); err != nil {
			logger.Error("store save failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device enrolled",
			"server_id", serverID,
			"fingerprint", req.Fingerprint,
			"hostname", req.Hostname,
			"os", req.OS,
			"arch", req.Arch,
		)

		resp := imprint.EnrollmentResponse{
			ServerID:      serverID,
			Certificate:   string(certPEM),
			CACertificate: string(cfg.CA.CACertPEM()),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})
}

func validateBuildSecret(provided string, allowed []string) bool {
	providedHash := sha256.Sum256([]byte(provided))
	match := 0
	for _, s := range allowed {
		allowedHash := sha256.Sum256([]byte(s))
		match |= subtle.ConstantTimeCompare(providedHash[:], allowedHash[:])
	}
	return match == 1
}

func generateServerID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("srv_%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("srv_%08x%04x%04x%04x%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
