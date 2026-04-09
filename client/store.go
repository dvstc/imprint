package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	clientKeyFile      = "client.key"
	clientCertFile     = "client.crt"
	caCertFile         = "ca.crt"
	enrollmentJSONFile = "enrollment.json"
)

// EnrollmentMeta is persisted alongside the certificates.
type EnrollmentMeta struct {
	ServerID    string `json:"server_id"`
	Fingerprint string `json:"fingerprint"`
}

// SaveEnrollment writes the client key, signed certificate, CA certificate,
// and enrollment metadata to the given directory. Files are written atomically
// (write to .tmp, then rename) to prevent corruption on crash.
func SaveEnrollment(dir string, keyPEM, certPEM, caCertPEM []byte, serverID, fingerprint string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{clientKeyFile, keyPEM, 0o600},
		{clientCertFile, certPEM, 0o644},
		{caCertFile, caCertPEM, 0o644},
	}

	for _, f := range files {
		if err := atomicWrite(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}

	meta := EnrollmentMeta{ServerID: serverID, Fingerprint: fingerprint}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, enrollmentJSONFile), metaJSON, 0o644)
}

// atomicWrite writes data to a temporary file in the same directory, then
// renames it into place. This ensures the target file is never partially written.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// IsEnrolled returns true if enrollment files exist in the directory.
func IsEnrolled(dir string) bool {
	for _, f := range []string{clientKeyFile, clientCertFile, caCertFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return false
		}
	}
	return true
}

// LoadMeta reads the enrollment metadata from disk.
func LoadMeta(dir string) (*EnrollmentMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, enrollmentJSONFile))
	if err != nil {
		return nil, err
	}
	var meta EnrollmentMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
