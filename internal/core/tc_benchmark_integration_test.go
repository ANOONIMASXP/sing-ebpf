//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"net/netip"
	"os"
	"testing"
)

func BenchmarkTCSharedSteadyFlow(b *testing.B) {
	if os.Getenv("SING_EBPF_INTEGRATION") != "1" {
		b.Skip("set SING_EBPF_INTEGRATION=1")
	}
	backend, err := PrepareTC(TCConfig{ListenerPort: 65530, DeliveryInterface: 1,
		EnableShared: true, EnableIPv4: true, EnableTCP: true, AssignmentCapacity: 64})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()
	if err = backend.Enable(); err != nil {
		b.Fatal(err)
	}
	packet := testIPv4TCPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.1"), 50000, 443)
	// PROG_TEST_RUN repeats the output frame; keep the benchmark MAC stable.
	var mac MACAddress
	copy(mac[:], packet[:6])
	if err = backend.SetDeliveryInterface(1, mac); err != nil {
		b.Fatal(err)
	}
	program := backend.runtime.programs[tcProgramSharedIngressEthernet]
	action, duration, err := program.Benchmark(packet, b.N, b.ResetTimer)
	if err != nil || action != testTCActRedirect {
		b.Fatalf("benchmark action=%d err=%v", action, err)
	}
	b.ReportMetric(float64(duration.Nanoseconds()), "kernel-ns/op")
}
