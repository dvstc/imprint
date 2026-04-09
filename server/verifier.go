package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/dvstc/imprint"
)

type contextKey int

const serverIdentityKey contextKey = iota

// RequireMTLS returns middleware that enforces a valid client certificate
// on every request. The enrollment must exist, be active, and the certificate
// serial must match the enrollment record (preventing use of superseded certs
// after renewal). The enrollment is injected into the request context.
func RequireMTLS(store Store, next http.Handler) http.Handler {
	return RequireMTLSWithLogger(store, next, nil)
}

// RequireMTLSWithLogger is like RequireMTLS but accepts a custom logger.
func RequireMTLSWithLogger(store Store, next http.Handler, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		serverID := cert.Subject.CommonName
		if serverID == "" {
			logger.Warn("invalid client certificate: missing CN", "remote_addr", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		serialHex := cert.SerialNumber.Text(16)

		enrollment, err := store.GetByServerID(r.Context(), serverID)
		if err != nil {
			logger.Error("enrollment lookup failed", "error", err, "server_id", serverID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if enrollment == nil {
			logger.Warn("unknown device: no enrollment for server_id",
				"server_id", serverID,
				"serial", serialHex,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if enrollment.Status == imprint.StatusRevoked {
			logger.Warn("revoked certificate used",
				"server_id", serverID,
				"serial", serialHex,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if enrollment.SerialNumber != serialHex {
			logger.Warn("superseded certificate used",
				"server_id", serverID,
				"cert_serial", serialHex,
				"enrollment_serial", enrollment.SerialNumber,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Update last-seen tracking (best-effort)
		_ = store.UpdateLastSeen(r.Context(), serverID, r.RemoteAddr)

		w.Header().Set("X-Imprint-Cert-Expires", cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"))

		ctx := context.WithValue(r.Context(), serverIdentityKey, enrollment)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ServerIdentity extracts the enrollment record from the request context.
// Returns nil if the request was not authenticated via mTLS.
func ServerIdentity(ctx context.Context) *imprint.Enrollment {
	v, _ := ctx.Value(serverIdentityKey).(*imprint.Enrollment)
	return v
}
