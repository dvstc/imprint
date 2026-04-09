//go:build linux

package fingerprint

import (
	"os"
	"strings"
)

// fileCollector reads a value from a file (e.g. /etc/machine-id).
type fileCollector struct {
	name string
	path string
}

func (f fileCollector) Name() string { return f.name }

func (f fileCollector) Collect() (string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return "", nil // attribute unavailable, not an error
	}
	return strings.ToLower(strings.TrimSpace(string(data))), nil
}

func platformCollectors() []Collector {
	return []Collector{
		fileCollector{name: "machine_id", path: "/etc/machine-id"},
		fileCollector{name: "product_uuid", path: "/sys/class/dmi/id/product_uuid"},
		macCollector{},
	}
}
