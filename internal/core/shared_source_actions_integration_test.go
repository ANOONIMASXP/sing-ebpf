//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestSharedPacketRewriteSourceActionsIntegration(t *testing.T) {
	testSharedSourceActions(t, false)
}

func TestTCSharedSourceActionsIntegration(t *testing.T) {
	testSharedSourceActions(t, true)
}

func testSharedSourceActions(t *testing.T, assignment bool) {
	t.Helper()
	requireEBPFIntegration(t, "verify explicit shared source defaults and precedence")
	for _, ipv6 := range []bool{false, true} {
		for _, defaultAction := range []Decision{DecisionPass, DecisionIntercept} {
			for _, rules := range []bool{false, true} {
				t.Run(fmt.Sprintf("ipv6=%v/default=%d/rules=%v", ipv6, defaultAction, rules), func(t *testing.T) {
					include, exclude := "192.0.2.0/24", "192.0.2.128/25"
					selected, blocked, unmatched, destination := "192.0.2.1", "192.0.2.129", "198.51.100.1", "203.0.113.1"
					if ipv6 {
						include, exclude = "2001:db8:1::/64", "2001:db8:1::8000/113"
						selected, blocked, unmatched, destination = "2001:db8:1::1", "2001:db8:1::8001", "2001:db8:2::1", "2001:db8:3::1"
					}
					scope := ActionScope{Default: defaultAction}
					if rules {
						scope.SourceCIDR = []CIDRDecision{{netip.MustParsePrefix(include), DecisionIntercept}, {netip.MustParsePrefix(exclude), DecisionPass}}
						scope.SourceMAC = []MACDecision{{MACAddress{2, 0, 0, 0, 0, 1}, DecisionIntercept}, {MACAddress{2, 0, 0, 0, 0, 3}, DecisionPass}}
					}
					policy, err := CompileActionPolicy(ActionPolicy{Shared: scope})
					if err != nil {
						t.Fatal(err)
					}
					var program *CiliumEBPF.Program
					if assignment {
						backend, err := PrepareTC(TCConfig{ListenerPort: 65531, DeliveryInterface: 1, EnableShared: true, EnableIPv4: true, EnableSharedIPv6: ipv6, EnableTCP: true, EnableUDP: true, Policy: policy})
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = backend.Close() })
						if _, err = backend.UpdateSharedDestinationDecisions(nil); err != nil {
							t.Fatal(err)
						}
						if err = backend.Enable(); err != nil {
							t.Fatal(err)
						}
						program = backend.runtime.programs[tcProgramSharedIngressEthernet]
					} else {
						config := SharedPacketRewriteConfig{ListenerPort: 65531, EnableTCP: true, EnableUDP: true, RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), Policy: policy, MapCapacity: SharedPacketRewriteMapCapacity{Proxy: 64, Bypass: 64}, UDPTimeout: time.Minute}
						if ipv6 {
							config.RedirectIPv6 = netip.MustParsePrefix("fd00:1234::/64")
						}
						backend, err := PrepareSharedPacketRewrite(config)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = backend.Close() })
						if _, err = backend.UpdateDestinationDecisions(nil); err != nil {
							t.Fatal(err)
						}
						if err = backend.Enable(); err != nil {
							t.Fatal(err)
						}
						program = backend.runtime.programs[sharedNetworkProgramIngress]
					}
					for index, test := range []struct {
						name, source string
						mac          byte
						match        bool
					}{
						{"default", unmatched, 2, defaultAction == DecisionIntercept},
						{"CIDR intercept", selected, 2, true},
						{"MAC intercept", unmatched, 1, true},
						{"CIDR pass beats MAC intercept", blocked, 1, false},
						{"MAC pass beats CIDR intercept", selected, 3, false},
					} {
						for _, udp := range []bool{false, true} {
							src, dst := netip.MustParseAddr(test.source), netip.MustParseAddr(destination)
							port := uint16(51000 + index)
							var packet []byte
							if udp {
								packet = checksumTestUDPPacket(src, dst, port, 8443, false)
							} else if ipv6 {
								packet = testIPv6TCPPacket(src, dst, port, 8443, nil)
							} else {
								packet = testIPv4TCPPacket(src, dst, port, 8443)
							}
							copy(packet[6:12], []byte{2, 0, 0, 0, 0, test.mac})
							want := test.match
							if !rules {
								want = defaultAction == DecisionIntercept
							}
							action, output := runTCProgram(t, program, packet)
							if !want && (action != testTCActUnspec || !bytes.Equal(packet, output)) {
								t.Fatalf("%s udp=%v: pass intercepted (action=%d)", test.name, udp, action)
							}
							if want && assignment && action != testTCActRedirect {
								t.Fatalf("%s udp=%v: not assigned (action=%d)", test.name, udp, action)
							}
							if want && !assignment && bytes.Equal(packet, output) {
								t.Fatalf("%s udp=%v: not rewritten", test.name, udp)
							}
						}
					}
				})
			}
		}
	}
}
