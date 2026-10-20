//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// Decision is the only policy result understood by sing-ebpf. The library
// does not interpret why a rule was selected (for example DNS, FakeIP,
// routing, or a sing-box rule-set); the caller supplies the final action.
type Decision uint8

const (
	DecisionPass Decision = iota
	DecisionIntercept
)

// Valid reports whether d is one of the two supported data-plane actions.
func (d Decision) Valid() bool {
	return d == DecisionPass || d == DecisionIntercept
}

// CIDRDecision is a CIDR match with an already compiled final action.
type CIDRDecision struct {
	Prefix netip.Prefix
	Action Decision
	// EchoReply limits ICMP echo reply to the intercept destination prefixes
	// that set it, for example a FakeIP range intercepted beside a VPN range
	// whose hosts are real. When no intercept decision of a scope and address
	// family sets it, ICMP echo reply answers every intercept prefix of that
	// family. It is valid only on intercept destination decisions.
	EchoReply bool
}

// PortDecision is a protocol/port match with an already compiled final
// action. Protocol uses the IANA IP protocol number (6 for TCP, 17 for UDP).
type PortDecision struct {
	Protocol uint8
	Port     uint16
	Action   Decision
	// AfterSelectors applies this action only after UID/source selection.
	// Otherwise it precedes selectors. Safety and mandatory destination
	// interception retain precedence in either case.
	AfterSelectors bool
}

// UIDDecision is a UID range match with an already compiled final action.
type UIDDecision struct {
	Start  uint32
	End    uint32
	Action Decision
}

// MACDecision is a source MAC match with an already compiled final action.
type MACDecision struct {
	Address MACAddress
	Action  Decision
}

// ActionScope contains only match primitives and their final actions. It does
// not encode include/exclude, DNS, FakeIP, or rule-set semantics.
type ActionScope struct {
	// Default applies when no UID (local) or source CIDR/MAC (shared)
	// decision matches. Matching pass decisions take precedence over intercept
	// decisions; an intercept match in either source dimension selects a packet.
	// Destination interception and priority port actions precede this stage.
	Default         Decision
	UID             []UIDDecision
	SourceCIDR      []CIDRDecision
	SourceMAC       []MACDecision
	DestinationCIDR []CIDRDecision
	DestinationPort []PortDecision
}

// ActionPolicy is the policy input for the action-only API. The caller owns
// configuration semantics and supplies the final action for every rule.
type ActionPolicy struct {
	Local  ActionScope
	Shared ActionScope
}

func compileDestinationPassDecisions(decisions []CIDRDecision) (dualStackCIDRPrefixes, error) {
	prefixes := make([]netip.Prefix, 0, len(decisions))
	for _, decision := range decisions {
		if !decision.Prefix.IsValid() || !decision.Action.Valid() {
			return dualStackCIDRPrefixes{}, E.New("invalid eBPF destination decision")
		}
		if decision.Action != DecisionPass {
			return dualStackCIDRPrefixes{}, E.New("destination decision updates require pass actions")
		}
		prefixes = append(prefixes, decision.Prefix)
	}
	ipv4, ipv6, err := compileCIDRPrefixes(prefixes)
	return dualStackCIDRPrefixes{ipv4: ipv4, ipv6: ipv6}, err
}
