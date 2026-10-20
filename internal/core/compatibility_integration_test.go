//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"os"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// These are strict object-load tests: absence of a compatibility-path helper is
// a failure, not a skip. Attach/traffic tests remain separate evidence.
func TestCompatibilityObjectsIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load compatibility-oriented data planes")
	testCompatibilityObjects(t)
}

func testCompatibilityObjects(t *testing.T) {
	t.Helper()
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

// This is a pinned stable-kernel contract, not a runtime version gate. This
// 4.19 patch level backports UDP recvmsg hooks, but still lacks sk_assign.
func TestLegacy419CapabilitiesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify the pinned stable 4.19 compatibility boundary")
	if os.Getenv("SING_EBPF_KERNEL_PROFILE") != "legacy419" {
		t.Skip("only the pinned stable 4.19 guest asserts missing capabilities")
	}
	testCompatibilityObjects(t)
	if err := features.HaveProgramHelper(CiliumEBPF.SchedCLS, asm.FnSkAssign); !errors.Is(err, CiliumEBPF.ErrNotSupported) {
		t.Fatalf("expected unsupported sk_assign, got %v", err)
	}
	if _, err := loadTCProbeObject(kernelProbePlan{sharedSocketAssign: true, enableTCP: true, enableUDP: true}); err == nil {
		t.Fatal("upstream 4.19 unexpectedly loaded socket assignment")
	}
}
