//go:build with_ebpf && (linux || android)

package core

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestDecisionValues(t *testing.T) {
	if !DecisionPass.Valid() || !DecisionIntercept.Valid() {
		t.Fatal("supported eBPF decisions must be valid")
	}
	if Decision(2).Valid() {
		t.Fatal("unknown eBPF decision was accepted")
	}
}

func TestSharedDefaultIsExplicit(t *testing.T) {
	for _, withSelectors := range []bool{false, true} {
		var compiled [2]CompiledPolicy
		for _, action := range []Decision{DecisionPass, DecisionIntercept} {
			scope := ActionScope{Default: action}
			if withSelectors {
				scope.SourceCIDR = []CIDRDecision{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: DecisionIntercept}}
				scope.SourceMAC = []MACDecision{{Address: MACAddress{2, 0, 0, 0, 0, 1}, Action: DecisionPass}}
			}
			var err error
			compiled[action], err = CompileActionPolicy(ActionPolicy{Shared: scope})
			if err != nil {
				t.Fatal(err)
			}
			if compiled[action].sharedDefaultBypass != (action == DecisionPass) {
				t.Fatal("shared default lost")
			}
		}
		if reflect.DeepEqual(compiled[0], compiled[1]) {
			t.Fatal("different shared defaults compiled identically")
		}
	}
}

func TestUIDPassOverridesOverlappingIntercept(t *testing.T) {
	rules := []UIDDecision{
		{Start: 1000, End: 2000, Action: DecisionIntercept},
		{Start: 1500, End: 1600, Action: DecisionPass},
		{Start: ^uint32(0) - 1, End: ^uint32(0), Action: DecisionIntercept},
		{Start: ^uint32(0), End: ^uint32(0), Action: DecisionPass},
	}
	for _, defaultAction := range []Decision{DecisionPass, DecisionIntercept} {
		entries, defaultBypass, err := compileUIDActionPolicy(rules, defaultAction)
		if err != nil {
			t.Fatal(err)
		}
		for _, uid := range []uint32{0, 999, 1000, 1499, 1500, 1550, 1600, 1601, 2000, 2001, ^uint32(0) - 1, ^uint32(0)} {
			want := defaultAction
			for _, rule := range rules {
				if uid >= rule.Start && uid <= rule.End && rule.Action == DecisionIntercept {
					want = DecisionIntercept
				}
			}
			for _, rule := range rules {
				if uid >= rule.Start && uid <= rule.End && rule.Action == DecisionPass {
					want = DecisionPass
				}
			}
			bypass := defaultBypass
			for _, entry := range entries {
				mask := ^uint32(0) << (32 - entry.PrefixLength)
				if uid&mask == binary.BigEndian.Uint32(entry.UID[:])&mask {
					bypass = !defaultBypass
					break
				}
			}
			if bypass != (want == DecisionPass) {
				t.Fatalf("default=%v uid=%d bypass=%v want=%v", defaultAction, uid, bypass, want)
			}
		}
	}
}

func TestCompileActionPolicyUsesFinalActions(t *testing.T) {
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{
			Default: DecisionIntercept,
			UID:     []UIDDecision{{Start: 10000, End: 10010, Action: DecisionPass}},
			DestinationCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.168.0.0/16"),
				Action: DecisionPass,
			}},
		},
		Shared: ActionScope{
			Default: DecisionIntercept,
			SourceCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.0.2.0/24"),
				Action: DecisionIntercept,
			}},
			SourceMAC: []MACDecision{{
				Address: MACAddress{2, 0, 0, 0, 0, 1},
				Action:  DecisionPass,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.uidEntries) == 0 || policy.uidDefaultBypass {
		t.Fatalf("UID pass action was not compiled into the local decision: entries=%d defaultBypass=%v", len(policy.uidEntries), policy.uidDefaultBypass)
	}
	if len(policy.localInitialBypass.ipv4) != 1 || !policy.localInitialBypass.ipv4[0].Addr().Is4() {
		t.Fatalf("destination pass action was not compiled into the local bypass map: %+v", policy.localInitialBypass)
	}
	if len(policy.includeSource.ipv4) != 1 || len(policy.excludeSourceMAC) != 1 {
		t.Fatalf("shared source actions were not compiled: include=%+v exclude_mac=%+v", policy.includeSource, policy.excludeSourceMAC)
	}
}

func TestCompileActionPolicyPortStages(t *testing.T) {
	for _, port := range []uint16{53, 443, 5353} {
		for _, action := range []Decision{DecisionPass, DecisionIntercept} {
			for _, after := range []bool{false, true} {
				scope := ActionScope{Default: DecisionPass, DestinationPort: []PortDecision{{Protocol: ProtocolUDP, Port: port, Action: action, AfterSelectors: after}}}
				policy, err := CompileActionPolicy(ActionPolicy{Local: scope, Shared: scope})
				if err != nil {
					t.Fatal(err)
				}
				want := uint8(action) + 1
				if after {
					want |= portActionAfterSelectors
				}
				if len(policy.localBypassPortEntries) != 1 || policy.localBypassPortEntries[0].action != want || policy.sharedBypassPortEntries[0].action != want {
					t.Fatalf("port stage lost: %+v", policy)
				}
			}
		}
	}
	policy, err := CompileActionPolicy(ActionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.localBypassPortEntries)+len(policy.sharedBypassPortEntries) != 0 {
		t.Fatal("library inferred a port policy")
	}
}

func TestCompileActionPolicyIndependentPrefixSets(t *testing.T) {
	local := []CIDRDecision{
		{Prefix: netip.MustParsePrefix("100.64.0.0/10"), Action: DecisionIntercept},
		{Prefix: netip.MustParsePrefix("198.18.0.0/15"), Action: DecisionIntercept},
		{Prefix: netip.MustParsePrefix("fd00::/8"), Action: DecisionIntercept},
	}
	shared := []CIDRDecision{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Action: DecisionIntercept}}
	policy, err := CompileActionPolicy(ActionPolicy{Local: ActionScope{DestinationCIDR: local}, Shared: ActionScope{DestinationCIDR: shared}})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.localForce.ipv4) != 2 || len(policy.localForce.ipv6) != 1 || len(policy.sharedForce.ipv4) != 1 || len(policy.sharedForce.ipv6) != 0 {
		t.Fatalf("scope leak: %+v", policy)
	}
	if policy.sharedForce.ipv4[0] != shared[0].Prefix {
		t.Fatal("local prefixes leaked into shared")
	}
}
