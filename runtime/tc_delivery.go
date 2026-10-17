//go:build with_ebpf && (linux || android)

package runtime

import (
	"fmt"
	"os"
	"strings"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
)

func nextTCVethNames() (string, string, error) {
	for range 1024 {
		sequence := tcVethSequence.Add(1)
		suffix := fmt.Sprintf("%04x%04x", uint32(os.Getpid())&0xffff, sequence&0xffff)
		redirectName := "sbt" + suffix
		deliveryName := "sbd" + suffix
		if len(redirectName) > 15 || len(deliveryName) > 15 {
			return "", "", E.New("TC eBPF delivery link name exceeds Linux limit")
		}
		_, redirectErr := netlink.LinkByName(redirectName)
		_, deliveryErr := netlink.LinkByName(deliveryName)
		if tcLinkNotFound(redirectErr) && tcLinkNotFound(deliveryErr) {
			return redirectName, deliveryName, nil
		}
		if redirectErr != nil && !tcLinkNotFound(redirectErr) {
			return "", "", redirectErr
		}
		if deliveryErr != nil && !tcLinkNotFound(deliveryErr) {
			return "", "", deliveryErr
		}
	}
	return "", "", E.New("unable to allocate TC eBPF delivery link name")
}

// These settings are applied only inside the caller-owned private namespace.
// Namespace destruction owns their lifetime; no host-global restore list exists.
func tcInterfaceSysctlPath(interfaceName, setting string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/" + setting
}

func setTCSysctl(path, value string) (bool, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(current)) == value {
		return false, nil
	}
	if err = os.WriteFile(path, []byte(value), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func (d *tcDeliveryLink) IsClosed() bool {
	return d == nil || d.filter == nil && d.returnFilter == nil && d.redirect == nil && d.delivery == nil
}

func (d *tcDeliveryLink) Close() error {
	if d == nil {
		return nil
	}
	return d.closeIsolated()
}
