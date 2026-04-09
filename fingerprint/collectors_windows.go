//go:build windows

package fingerprint

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// registryCollector reads a string value from the Windows registry.
type registryCollector struct {
	name    string
	keyPath string
	value   string
}

func (r registryCollector) Name() string { return r.name }

func (r registryCollector) Collect() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, r.keyPath, registry.READ)
	if err != nil {
		return "", nil
	}
	defer key.Close()

	val, _, err := key.GetStringValue(r.value)
	if err != nil {
		return "", nil
	}
	return strings.ToLower(strings.TrimSpace(val)), nil
}

func platformCollectors() []Collector {
	return []Collector{
		registryCollector{
			name:    "machine_guid",
			keyPath: `SOFTWARE\Microsoft\Cryptography`,
			value:   "MachineGuid",
		},
		macCollector{},
	}
}
