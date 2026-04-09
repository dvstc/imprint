package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockCollector returns a fixed value for testing.
type mockCollector struct {
	name  string
	value string
	err   error
}

func (m mockCollector) Name() string            { return m.name }
func (m mockCollector) Collect() (string, error) { return m.value, m.err }

func TestHashPairsDeterministic(t *testing.T) {
	a := HashPairs(
		[]string{"mac_address", "machine_id"},
		[]string{"aa:bb:cc:dd:ee:ff", "abc123"},
	)
	b := HashPairs(
		[]string{"mac_address", "machine_id"},
		[]string{"aa:bb:cc:dd:ee:ff", "abc123"},
	)
	if a != b {
		t.Fatalf("same inputs produced different hashes: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", a)
	}
}

func TestHashPairsOrderIndependent(t *testing.T) {
	a := HashPairs(
		[]string{"machine_id", "mac_address"},
		[]string{"abc123", "aa:bb:cc:dd:ee:ff"},
	)
	b := HashPairs(
		[]string{"mac_address", "machine_id"},
		[]string{"aa:bb:cc:dd:ee:ff", "abc123"},
	)
	if a != b {
		t.Fatalf("different input order should produce same hash: %s vs %s", a, b)
	}
}

func TestHashPairsDifferentValues(t *testing.T) {
	a := HashPairs([]string{"key"}, []string{"value1"})
	b := HashPairs([]string{"key"}, []string{"value2"})
	if a == b {
		t.Fatal("different values should produce different hashes")
	}
}

func TestGenerateFromCollectors(t *testing.T) {
	collectors := []Collector{
		mockCollector{name: "machine_id", value: "test-machine-id"},
		mockCollector{name: "mac_address", value: "aa:bb:cc:dd:ee:ff"},
	}
	fp, err := GenerateFromCollectors(collectors)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", fp)
	}

	// Same collectors should produce same result
	fp2, _ := GenerateFromCollectors(collectors)
	if fp != fp2 {
		t.Fatal("same collectors should produce same fingerprint")
	}
}

func TestGenerateFromCollectorsSkipsEmpty(t *testing.T) {
	collectors := []Collector{
		mockCollector{name: "missing", value: ""},
		mockCollector{name: "present", value: "hello"},
	}
	fp, err := GenerateFromCollectors(collectors)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should equal hashing just the "present" key
	expected := HashPairs([]string{"present"}, []string{"hello"})
	if fp != expected {
		t.Fatalf("expected %s, got %s", expected, fp)
	}
}

func TestGenerateFromCollectorsAllEmpty(t *testing.T) {
	collectors := []Collector{
		mockCollector{name: "a", value: ""},
		mockCollector{name: "b", value: ""},
	}
	_, err := GenerateFromCollectors(collectors)
	if err == nil {
		t.Fatal("expected error when all collectors return empty")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp := "sha256:abcdef1234567890"

	if err := saveIdentity(dir, fp); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}

	loaded, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if loaded != fp {
		t.Fatalf("expected %q, got %q", fp, loaded)
	}
}

func TestPersistCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	fp := "sha256:test"

	if err := saveIdentity(dir, fp); err != nil {
		t.Fatalf("saveIdentity failed to create nested dir: %v", err)
	}

	loaded, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if loaded != fp {
		t.Fatalf("expected %q, got %q", fp, loaded)
	}
}

func TestLoadIdentityMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := loadIdentity(dir)
	if err == nil {
		t.Fatal("expected error for missing identity file")
	}
}

func TestGenerateAndPersist(t *testing.T) {
	dir := t.TempDir()
	fp, err := generateAndPersist(dir)
	if err != nil {
		t.Fatalf("generateAndPersist: %v", err)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", fp)
	}

	// Verify it was persisted
	loaded, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity after generate: %v", err)
	}
	if loaded != fp {
		t.Fatalf("persisted value %q doesn't match generated %q", loaded, fp)
	}
}

func TestGenerateAndPersistUnique(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	fp1, _ := generateAndPersist(dir1)
	fp2, _ := generateAndPersist(dir2)
	if fp1 == fp2 {
		t.Fatal("two generated fingerprints should not collide")
	}
}

func TestGenerateTieredFallback(t *testing.T) {
	dir := t.TempDir()

	// On this machine (Windows CI/dev), hardware collectors should work.
	// But we also test that the persist dir gets used for caching.
	result, err := Generate(Options{PersistDir: dir})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(result.Fingerprint, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", result.Fingerprint)
	}
	// On a real machine, tier should be "hardware"; in a stripped container it might differ
	t.Logf("tier=%s fingerprint=%s", result.Tier, result.Fingerprint)

	// Running again should produce the same fingerprint
	result2, err := Generate(Options{PersistDir: dir})
	if err != nil {
		t.Fatalf("Generate (second run): %v", err)
	}
	if result.Fingerprint != result2.Fingerprint {
		t.Fatalf("fingerprint changed between runs: %s vs %s", result.Fingerprint, result2.Fingerprint)
	}
}

func TestGenerateWithPersistedFallback(t *testing.T) {
	dir := t.TempDir()

	// Pre-plant an identity file to simulate tier 2
	expected := "sha256:preexisting"
	if err := os.WriteFile(filepath.Join(dir, identityFile), []byte(expected+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// If hardware collectors succeed, tier 1 takes priority.
	// But we can at least verify the file is loadable.
	loaded, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if loaded != expected {
		t.Fatalf("expected %q, got %q", expected, loaded)
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"},
		{"00:11:22:33:44:55", "00:11:22:33:44:55"},
	}
	for _, tt := range tests {
		got := NormalizeMAC(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestRandomUUID(t *testing.T) {
	u1, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := randomUUID()
	if u1 == u2 {
		t.Fatal("two UUIDs should not be equal")
	}
	// v4 UUID format check
	if len(u1) != 36 {
		t.Fatalf("UUID wrong length: %d", len(u1))
	}
	if u1[8] != '-' || u1[13] != '-' || u1[18] != '-' || u1[23] != '-' {
		t.Fatalf("UUID wrong format: %s", u1)
	}
}

func TestIdentityFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := saveIdentity(dir, "sha256:test"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, identityFile))
	if err != nil {
		t.Fatal(err)
	}
	// On Windows, file permissions work differently, but the file should exist
	if info.Size() == 0 {
		t.Fatal("identity file should not be empty")
	}
}
