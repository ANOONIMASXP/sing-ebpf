//go:build with_ebpf && linux && ebpf_integration

package core

import "testing"

// These are strict object-load tests: absence of a compatibility-path helper is
// a failure, not a skip. Attach/traffic tests remain separate evidence.
func TestCompatibilityObjectsIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load compatibility-oriented data planes")
	for _, tcp := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			plan := kernelProbePlan{localCgroup: true, sharedPacketRewrite: true, enableTCP: tcp, enableUDP: !tcp, enableIPv6: ipv6}
			if _, err := loadCgroupProbeObject(plan); err != nil {
				t.Fatalf("cgroup tcp=%v ipv6=%v: %v", tcp, ipv6, err)
			}
			if _, err := loadSharedNetworkProbeObject(plan); err != nil {
				t.Fatalf("packet_rewrite tcp=%v ipv6=%v: %v", tcp, ipv6, err)
			}
		}
	}
}
