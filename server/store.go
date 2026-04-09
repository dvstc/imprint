package server

import (
	"context"

	"github.com/dvstc/imprint"
)

// ListFilter controls which enrollments are returned by List.
type ListFilter struct {
	Status string // if non-empty, only return enrollments with this status
	Limit  int    // max results; 0 means no limit
	Offset int    // for pagination
}

// Store persists enrollment records. Consumers provide their own
// implementation (SQLite, Postgres, etc.). An in-memory implementation
// is provided for testing.
type Store interface {
	// SaveEnrollment persists an enrollment record, inserting or updating by ServerID.
	SaveEnrollment(ctx context.Context, e *imprint.Enrollment) error
	// GetByFingerprint returns the enrollment matching the given fingerprint, or nil if none exists.
	GetByFingerprint(ctx context.Context, fingerprint string) (*imprint.Enrollment, error)
	// GetByServerID returns the enrollment matching the given server ID, or nil if none exists.
	GetByServerID(ctx context.Context, serverID string) (*imprint.Enrollment, error)

	// EnrollDevice atomically looks up an existing enrollment by fingerprint,
	// or persists newEnrollment if none exists. Returns the enrollment and
	// whether it was newly created. Implementations must ensure that concurrent
	// calls with the same fingerprint never create duplicate records.
	EnrollDevice(ctx context.Context, fingerprint string, newEnrollment *imprint.Enrollment) (enrolled *imprint.Enrollment, created bool, err error)
	// List returns enrollments matching the given filter criteria.
	List(ctx context.Context, filter ListFilter) ([]*imprint.Enrollment, error)
	// Revoke marks the enrollment for the given server ID as revoked.
	Revoke(ctx context.Context, serverID string) error

	// IsRevoked checks whether a certificate serial number belongs to a revoked
	// enrollment. Note: RequireMTLS does not call this method (it checks enrollment
	// status and serial match directly via GetByServerID). This method remains
	// available for direct consumer use.
	IsRevoked(ctx context.Context, serialNumber string) (bool, error)

	// UpdateLastSeen records the current time and remote IP for the given server ID.
	UpdateLastSeen(ctx context.Context, serverID string, ip string) error
	// Delete removes the enrollment record for the given server ID.
	Delete(ctx context.Context, serverID string) error
}
