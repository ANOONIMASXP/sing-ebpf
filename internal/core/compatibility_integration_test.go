//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"os"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

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

// This is a pinned upstream-kernel negative contract, not a runtime version
// gate. Vendor kernels may backport either capability and are probed normally.
func TestLegacy419CapabilitiesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify the upstream 4.19 compatibility boundary")
	if os.Getenv("SING_EBPF_KERNEL_PROFILE") != "legacy419" {
		t.Skip("only the pinned upstream 4.19 guest asserts missing capabilities")
	}
	for _, ipv6 := range []bool{false, true} {
		if _, err := loadCgroupProbeObject(kernelProbePlan{localCgroup: true, enableTCP: true, enableIPv6: ipv6}); err != nil {
			t.Fatalf("cgroup TCP ipv6=%v: %v", ipv6, err)
		}
		for _, tcp := range []bool{false, true} {
			if _, err := loadSharedNetworkProbeObject(kernelProbePlan{sharedPacketRewrite: true, enableTCP: tcp, enableUDP: !tcp, enableIPv6: ipv6}); err != nil {
				t.Fatalf("packet_rewrite tcp=%v ipv6=%v: %v", tcp, ipv6, err)
			}
		}
		if _, err := loadCgroupProbeObject(kernelProbePlan{localCgroup: true, enableUDP: true, enableIPv6: ipv6}); err == nil {
			t.Fatal("upstream 4.19 unexpectedly loaded the cgroup UDP reply path")
		}
	}
	for _, attach := range []CiliumEBPF.AttachType{CiliumEBPF.AttachCGroupUDP4Recvmsg, CiliumEBPF.AttachCGroupUDP6Recvmsg} {
		program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
			Type: CiliumEBPF.CGroupSockAddr, AttachType: attach, License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
		})
		if err == nil {
			_ = program.Close()
			t.Fatalf("unexpected recvmsg attach capability: %v", attach)
		}
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, CiliumEBPF.ErrNotSupported) {
			t.Fatalf("unexpected recvmsg failure: %v", err)
		}
	}
	if err := features.HaveProgramHelper(CiliumEBPF.SchedCLS, asm.FnSkAssign); !errors.Is(err, CiliumEBPF.ErrNotSupported) {
		t.Fatalf("expected unsupported sk_assign, got %v", err)
	}
	if _, err := loadTCProbeObject(kernelProbePlan{sharedSocketAssign: true, enableTCP: true, enableUDP: true}); err == nil {
		t.Fatal("upstream 4.19 unexpectedly loaded socket assignment")
	}
}
