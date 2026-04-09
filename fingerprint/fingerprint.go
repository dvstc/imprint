package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// Tier describes how the fingerprint was derived.
const (
	TierHardware  = "hardware"
	TierPersisted = "persisted"
	TierGenerated = "generated"
)

// Options configures fingerprint generation.
type Options struct {
	// PersistDir is the directory used to store/load a persisted identity file.
	// Required for container environments where hardware attributes are unavailable.
	// If empty, tier-2 (persisted) and tier-3 (generated) fallbacks are disabled.
	PersistDir string
}

// Result holds a generated fingerprint and metadata about how it was derived.
type Result struct {
	Fingerprint string // "sha256:<hex>"
	Tier        string // TierHardware, TierPersisted, or TierGenerated
}

// Collector gathers a named machine attribute. If the attribute is unavailable
// the collector returns an empty value and a nil error; a non-nil error means
// something unexpected happened.
type Collector interface {
	// Name returns the attribute key used in the fingerprint hash (e.g. "machine_id").
	Name() string
	// Collect returns the attribute value, or empty string if unavailable.
	Collect() (string, error)
}

// Generate produces a stable, unique fingerprint for the current machine.
//
// It follows a tiered strategy:
//   - Tier 1 (hardware): collect platform-specific attributes (machine-id, MAC, etc.)
//     and hash them. Used on bare metal and VMs.
//   - Tier 2 (persisted): if hardware attributes are insufficient, look for an
//     existing identity file on disk. Used for containers with persistent volumes.
//   - Tier 3 (generated): if nothing else is available, generate a random UUID,
//     persist it, and hash it. First-boot fallback for any environment.
func Generate(opts Options) (*Result, error) {
	// Tier 1: hardware collectors
	collectors := platformCollectors()
	pairs := collectAll(collectors)

	if len(pairs) > 0 {
		fp := hashPairs(pairs)
		// Cache the hardware fingerprint so restarts are fast
		if opts.PersistDir != "" {
			_ = saveIdentity(opts.PersistDir, fp)
		}
		return &Result{Fingerprint: fp, Tier: TierHardware}, nil
	}

	// Tier 2: persisted identity
	if opts.PersistDir != "" {
		if fp, err := loadIdentity(opts.PersistDir); err == nil && fp != "" {
			return &Result{Fingerprint: fp, Tier: TierPersisted}, nil
		}
	}

	// Tier 3: generate and persist
	if opts.PersistDir != "" {
		fp, err := generateAndPersist(opts.PersistDir)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: failed to generate identity: %w", err)
		}
		return &Result{Fingerprint: fp, Tier: TierGenerated}, nil
	}

	return nil, fmt.Errorf("fingerprint: no hardware attributes available and no PersistDir configured")
}

// collectAll runs every collector and returns the key=value pairs for those
// that returned a non-empty value.
func collectAll(collectors []Collector) []kv {
	var pairs []kv
	for _, c := range collectors {
		val, err := c.Collect()
		if err != nil || val == "" {
			continue
		}
		pairs = append(pairs, kv{Key: c.Name(), Value: val})
	}
	return pairs
}

type kv struct {
	Key   string
	Value string
}

// hashPairs sorts key-value pairs alphabetically by key and hashes them using
// the canonical format: "key=value\n" per pair, UTF-8 encoded.
func hashPairs(pairs []kv) string {
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key < pairs[j].Key
	})

	h := sha256.New()
	for _, p := range pairs {
		fmt.Fprintf(h, "%s=%s\n", p.Key, p.Value)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// GenerateFromCollectors is exported for testing: it runs the given collectors
// through the same hashing logic as the hardware tier.
func GenerateFromCollectors(collectors []Collector) (string, error) {
	pairs := collectAll(collectors)
	if len(pairs) == 0 {
		return "", fmt.Errorf("fingerprint: no attributes collected")
	}
	return hashPairs(pairs), nil
}

// HashPairs is exported for cross-language verification tests.
func HashPairs(keys []string, values []string) string {
	if len(keys) != len(values) {
		return ""
	}
	pairs := make([]kv, len(keys))
	for i := range keys {
		pairs[i] = kv{Key: keys[i], Value: values[i]}
	}
	return hashPairs(pairs)
}

// NormalizeMAC formats a MAC address to lowercase colon-separated hex.
func NormalizeMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}
