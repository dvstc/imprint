package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dvstc/imprint"
)

// MemStore is an in-memory Store implementation for testing.
type MemStore struct {
	mu          sync.RWMutex
	enrollments map[string]*imprint.Enrollment // keyed by server_id
}

// NewMemStore creates a new in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		enrollments: make(map[string]*imprint.Enrollment),
	}
}

// SaveEnrollment stores a copy of the enrollment keyed by ServerID.
func (s *MemStore) SaveEnrollment(_ context.Context, e *imprint.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.enrollments[e.ServerID] = &cp
	return nil
}

// EnrollDevice atomically checks for an existing enrollment by fingerprint.
// If found, it returns the existing record. Otherwise it persists newEnrollment.
// The write lock is held across the entire check-and-save to prevent races.
func (s *MemStore) EnrollDevice(_ context.Context, fingerprint string, newEnrollment *imprint.Enrollment) (*imprint.Enrollment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.enrollments {
		if e.Fingerprint == fingerprint {
			cp := *e
			return &cp, false, nil
		}
	}
	cp := *newEnrollment
	s.enrollments[newEnrollment.ServerID] = &cp
	ret := *newEnrollment
	return &ret, true, nil
}

// GetByFingerprint returns the first enrollment matching the fingerprint, or nil.
func (s *MemStore) GetByFingerprint(_ context.Context, fingerprint string) (*imprint.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.enrollments {
		if e.Fingerprint == fingerprint {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

// GetByServerID returns the enrollment for the given server ID, or nil.
func (s *MemStore) GetByServerID(_ context.Context, serverID string) (*imprint.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.enrollments[serverID]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

func (s *MemStore) List(_ context.Context, filter ListFilter) ([]*imprint.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*imprint.Enrollment
	for _, e := range s.enrollments {
		if filter.Status != "" && e.Status != filter.Status {
			continue
		}
		cp := *e
		result = append(result, &cp)
	}

	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return nil, nil
		}
		result = result[filter.Offset:]
	}
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	return result, nil
}

// Revoke sets the enrollment status to revoked.
func (s *MemStore) Revoke(_ context.Context, serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrollments[serverID]
	if !ok {
		return fmt.Errorf("enrollment not found: %s", serverID)
	}
	e.Status = imprint.StatusRevoked
	return nil
}

// IsRevoked reports whether the given certificate serial belongs to a revoked enrollment.
func (s *MemStore) IsRevoked(_ context.Context, serialNumber string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.enrollments {
		if e.SerialNumber == serialNumber {
			return e.Status == imprint.StatusRevoked, nil
		}
	}
	return false, nil
}

// UpdateLastSeen records the current time and IP for the enrollment.
func (s *MemStore) UpdateLastSeen(_ context.Context, serverID string, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrollments[serverID]
	if !ok {
		return fmt.Errorf("enrollment not found: %s", serverID)
	}
	e.LastSeenAt = time.Now()
	e.LastIP = ip
	return nil
}

// Delete removes the enrollment record for the given server ID.
func (s *MemStore) Delete(_ context.Context, serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.enrollments[serverID]; !ok {
		return fmt.Errorf("enrollment not found: %s", serverID)
	}
	delete(s.enrollments, serverID)
	return nil
}
