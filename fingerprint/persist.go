package fingerprint

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const identityFile = "imprint-identity"

// loadIdentity reads a previously persisted fingerprint from disk.
func loadIdentity(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		return "", err
	}
	fp := strings.TrimSpace(string(data))
	if fp == "" {
		return "", fmt.Errorf("identity file is empty")
	}
	return fp, nil
}

// saveIdentity writes a fingerprint to disk for future use.
// Uses write-tmp-then-rename to prevent corruption on crash.
func saveIdentity(dir string, fingerprint string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, identityFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fingerprint+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// generateAndPersist creates a random UUID, hashes it, persists the hash, and returns it.
func generateAndPersist(dir string) (string, error) {
	uuid, err := randomUUID()
	if err != nil {
		return "", err
	}

	h := sha256.Sum256([]byte(uuid))
	fp := fmt.Sprintf("sha256:%x", h[:])

	if err := saveIdentity(dir, fp); err != nil {
		return "", err
	}
	return fp, nil
}

// randomUUID generates a v4 UUID without external dependencies.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
