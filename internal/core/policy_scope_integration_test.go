//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"bytes"
	"net/netip"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestScopedPrefixSetsAndPortStagesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify scoped destination and staged port actions")
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{Default: DecisionIntercept, DestinationCIDR: []CIDRDecision{
			{Prefix: netip.MustParsePrefix("198.18.0.0/16"), Action: DecisionIntercept},
		}},
		Shared: ActionScope{
			Default:    DecisionIntercept,
			SourceCIDR: []CIDRDecision{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: DecisionPass}},
			DestinationCIDR: []CIDRDecision{
				{Prefix: netip.MustParsePrefix("198.19.0.0/16"), Action: DecisionIntercept},
				{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: DecisionIntercept},
				{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: DecisionPass},
			},
			DestinationPort: []PortDecision{
				{Protocol: ProtocolTCP, Port: 8443, Action: DecisionIntercept},
				{Protocol: ProtocolTCP, Port: 5353, Action: DecisionIntercept, AfterSelectors: true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tc, err := PrepareTC(TCConfig{ListenerPort: 65531, EnableShared: true, EnableIPv4: true, EnableTCP: true, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	if err = tc.Enable(); err != nil {
		t.Fatal(err)
	}
	rewrite, err := PrepareSharedPacketRewrite(newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rewrite.Close() })
	if err = rewrite.Enable(); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []struct {
		name    string
		program *CiliumEBPF.Program
		rewrite bool
	}{
		{"socket_assign", tc.runtime.programs[tcProgramSharedIngressEthernet], false},
		{"packet_rewrite", rewrite.runtime.programs[sharedNetworkProgramIngress], true},
	} {
		t.Run(backend.name, func(t *testing.T) {
			for index, test := range []struct {
				name, source, destination string
				port                      uint16
				selected                  bool
			}{
				{"local set must not leak", "192.0.2.1", "198.18.0.1", 443, false},
				{"first shared prefix overrides selector", "192.0.2.1", "198.19.0.1", 443, true},
				{"second shared prefix overrides selector", "192.0.2.1", "203.0.113.1", 443, true},
				{"priority port overrides selector", "192.0.2.1", "198.51.100.1", 8443, true},
				{"selected port respects selector", "192.0.2.1", "198.51.100.1", 5353, false},
				{"selected port overrides CIDR", "203.0.114.1", "198.51.100.1", 5353, true},
				{"port 53 has no implicit meaning", "203.0.114.1", "198.51.100.1", 53, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					packet := testIPv4TCPPacket(netip.MustParseAddr(test.source), netip.MustParseAddr(test.destination), uint16(50000+index), test.port)
					action, output := runTCProgram(t, backend.program, packet)
					if !test.selected {
						if action != testTCActUnspec || !bytes.Equal(packet, output) {
							t.Fatalf("pass packet intercepted: %d", action)
						}
					} else if backend.rewrite {
						if bytes.Equal(packet, output) {
							t.Fatal("selected packet was not rewritten")
						}
					} else if action != testTCActShot {
						t.Fatalf("selected packet did not reach assignment: %d", action)
					}
				})
			}
		})
	}
}
