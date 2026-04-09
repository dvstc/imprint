package fingerprint

import (
	"net"
	"sort"
	"strings"
)

// macCollector reads the primary NIC's hardware (MAC) address.
// "Primary NIC" is defined as the first non-loopback, non-virtual interface
// with a hardware address, sorted alphabetically by interface name.
type macCollector struct{}

func (macCollector) Name() string { return "mac_address" }

func (macCollector) Collect() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if isVirtualMAC(mac) {
			continue
		}
		return NormalizeMAC(mac), nil
	}
	return "", nil
}

// isVirtualMAC checks for common virtual/container MAC prefixes.
func isVirtualMAC(mac string) bool {
	lower := strings.ToLower(mac)
	virtualPrefixes := []string{
		"00:00:00", // null
		"02:42:",   // Docker default
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
