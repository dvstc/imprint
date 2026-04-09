//go:build darwin

package fingerprint

import (
	"os/exec"
	"strings"
)

// ioregCollector reads the IOPlatformUUID from IOKit on macOS.
type ioregCollector struct{}

func (ioregCollector) Name() string { return "platform_uuid" }

func (ioregCollector) Collect() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				uuid := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				return strings.ToLower(strings.TrimSpace(uuid)), nil
			}
		}
	}
	return "", nil
}

func platformCollectors() []Collector {
	return []Collector{
		ioregCollector{},
		macCollector{},
	}
}
