package imprint

import "time"

// EnrollmentRequest is sent by a device to enroll with a service.
// The build secret proves the software is genuine; the fingerprint
// uniquely identifies the machine; the CSR lets the service issue
// a client certificate without ever seeing the device's private key.
type EnrollmentRequest struct {
	BuildSecret string `json:"build_secret"`
	Fingerprint string `json:"fingerprint"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CSR         string `json:"csr"` // PEM-encoded PKCS#10 certificate signing request
}

// EnrollmentResponse is returned by the service after a successful enrollment.
// The certificate is signed by the service's internal CA and can be used
// for mTLS on all subsequent requests.
type EnrollmentResponse struct {
	ServerID      string `json:"server_id"`
	Certificate   string `json:"certificate"`    // PEM-encoded signed client certificate
	CACertificate string `json:"ca_certificate"` // PEM-encoded CA certificate
}

// RenewalRequest is sent by a device with a valid (not-yet-expired) certificate
// to obtain a fresh certificate via mTLS (Tier 1 renewal).
type RenewalRequest struct {
	CSR string `json:"csr"` // PEM-encoded PKCS#10 certificate signing request
}

// ChallengeRenewalRequest is sent by a device with an expired certificate
// to prove its identity via signature proof and obtain a fresh certificate
// (Tier 2 renewal). The proof is computed over SHA256(server_id + "\n" +
// fingerprint + "\n" + csr), signed with the old private key.
type ChallengeRenewalRequest struct {
	ServerID    string `json:"server_id"`
	Fingerprint string `json:"fingerprint"`
	ExpiredCert string `json:"expired_cert"` // PEM-encoded expired client certificate
	CSR         string `json:"csr"`          // PEM-encoded new CSR
	Proof       string `json:"proof"`        // base64-encoded signature over SHA256 digest
}

// Enrollment represents a registered device in the enrollment store.
type Enrollment struct {
	ServerID     string    `json:"server_id"`
	Fingerprint  string    `json:"fingerprint"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	SerialNumber string    `json:"serial_number"`          // certificate serial (hex), for revocation
	EnrolledAt   time.Time `json:"enrolled_at"`
	RenewedAt    time.Time `json:"renewed_at,omitempty"`   // zero value = never renewed
	LastSeenAt   time.Time `json:"last_seen_at"`
	LastIP       string    `json:"last_ip"`
	Status       string    `json:"status"`                 // "active", "revoked", "pending"
}

// Enrollment status constants.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
	StatusPending = "pending"
)

// EnrollMode controls how the server handles new enrollment requests.
type EnrollMode int

const (
	ModeAuto     EnrollMode = iota // any valid build secret is immediately enrolled
	ModeToken                      // requires a pre-generated enrollment token (future)
	ModeApproval                   // enrollment is queued for admin approval (future)
)
