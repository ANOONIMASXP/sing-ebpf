//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// CompiledPolicy is an immutable policy snapshot shared by all eBPF data
// planes created for one consumer. The force-intercept prefixes are opaque
// application-supplied destination prefixes: the library neither assigns
// their meaning nor resolves addresses within them.
type CompiledPolicy struct {
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	localDNSMode            DNSMode
	sharedDNSMode           DNSMode
	sharedBypassPrivate     bool
	forceIntercept          forceInterceptPolicy
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
	localInitialBypass      dualStackCIDRPrefixes
	sharedInitialBypass     dualStackCIDRPrefixes
}

// CompileActionPolicy translates the caller's final pass/intercept rules into
// the internal map layout. The translation intentionally contains no
// sing-box concepts: a pass action becomes a bypass map entry and an
// intercept action becomes an include/force entry where the selected data
// plane supports it.
func CompileActionPolicy(config ActionPolicy) (CompiledPolicy, error) {
	if err := validateActionScope(config.Local, "local"); err != nil {
		return CompiledPolicy{}, err
	}
	if err := validateActionScope(config.Shared, "shared"); err != nil {
		return CompiledPolicy{}, err
	}
	var force forceInterceptBuilder
	local, localBypass, err := compileActionScope(config.Local, "local", &force)
	if err != nil {
		return CompiledPolicy{}, err
	}
	shared, sharedBypass, err := compileActionScope(config.Shared, "shared", &force)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceIntercept, err := force.build()
	if err != nil {
		return CompiledPolicy{}, err
	}
	return CompiledPolicy{
		uidEntries:              local.uidEntries,
		uidDefaultBypass:        local.uidDefaultBypass,
		localDNSMode:            actionDNSMode(config.Local),
		includeSource:           shared.includeSource,
		excludeSource:           shared.excludeSource,
		includeSourceMAC:        shared.includeSourceMAC,
		excludeSourceMAC:        shared.excludeSourceMAC,
		localBypassPortEntries:  local.localBypassPortEntries,
		sharedBypassPortEntries: shared.sharedBypassPortEntries,
		forceIntercept:          forceIntercept,
		localInitialBypass:      localBypass,
		sharedInitialBypass:     sharedBypass,
		sharedDNSMode:           actionDNSMode(config.Shared),
		sharedBypassPrivate:     false,
	}, nil
}

type compiledActionScope struct {
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
}

func actionDNSMode(scope ActionScope) DNSMode {
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionIntercept {
			return DNSModeHijack
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionPass {
			return DNSModeOff
		}
	}
	return DNSModeRespectPolicy
}

func validateActionScope(scope ActionScope, name string) error {
	if !scope.Default.Valid() {
		return E.New("invalid ", name, " eBPF default decision: ", scope.Default)
	}
	for _, rule := range scope.UID {
		if rule.Start > rule.End || !rule.Action.Valid() {
			return E.New("invalid ", name, " UID decision")
		}
	}
	for _, rule := range scope.SourceCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() || rule.EchoReply {
			return E.New("invalid ", name, " source CIDR decision")
		}
	}
	for _, rule := range scope.DestinationCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() || rule.EchoReply && rule.Action != DecisionIntercept {
			return E.New("invalid ", name, " destination CIDR decision")
		}
	}
	for _, rule := range scope.SourceMAC {
		if !rule.Action.Valid() {
			return E.New("invalid ", name, " source MAC decision")
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 0 || !rule.Action.Valid() {
			return E.New("invalid ", name, " destination port decision")
		}
	}
	return nil
}

func compileActionScope(scope ActionScope, name string, force *forceInterceptBuilder) (compiledActionScope, dualStackCIDRPrefixes, error) {
	result := compiledActionScope{}
	var err error
	var bypass dualStackCIDRPrefixes
	result.uidEntries, result.uidDefaultBypass, err = compileUIDActionPolicy(scope.UID, scope.Default)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, E.Cause(err, name, " UID policy")
	}
	var sourceInclude, sourceExclude []netip.Prefix
	for _, rule := range scope.SourceCIDR {
		if rule.Action == DecisionPass {
			sourceExclude = append(sourceExclude, rule.Prefix)
		} else {
			sourceInclude = append(sourceInclude, rule.Prefix)
		}
	}
	result.includeSource.ipv4, result.includeSource.ipv6, err = compileCIDRPrefixes(sourceInclude)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, E.Cause(err, name, " include source CIDR policy")
	}
	result.excludeSource.ipv4, result.excludeSource.ipv6, err = compileCIDRPrefixes(sourceExclude)
	if err != nil {
		return compiledActionScope{}, dualStackCIDRPrefixes{}, E.Cause(err, name, " exclude source CIDR policy")
	}
	for _, rule := range scope.SourceMAC {
		if rule.Action == DecisionPass {
			result.excludeSourceMAC = append(result.excludeSourceMAC, rule.Address)
		} else {
			result.includeSourceMAC = append(result.includeSourceMAC, rule.Address)
		}
	}
	for _, rule := range scope.DestinationCIDR {
		prefix := rule.Prefix.Masked()
		if rule.Action == DecisionPass {
			if prefix.Addr().Is4() {
				bypass.ipv4 = append(bypass.ipv4, prefix)
			} else {
				bypass.ipv6 = append(bypass.ipv6, prefix)
			}
			continue
		}
		if err = force.add(rule); err != nil {
			return compiledActionScope{}, dualStackCIDRPrefixes{}, E.Cause(err, name, " destination CIDR policy")
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Action != DecisionPass {
			// DNS hijack is a control-plane mode, not a normal destination-port
			// exception. It intentionally remains global even when a UID policy
			// makes ordinary traffic default to pass, so include_package can be
			// combined with dns_mode=hijack without silently degrading hijack.
			if scope.Default == DecisionPass && !isDNSHijackPort(rule) {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, E.New(name, " cannot override a pass default with port intercept")
			}
			continue
		}
		entry := tcPortKey{Protocol: rule.Protocol, Port: rule.Port}
		if name == "shared" {
			result.sharedBypassPortEntries = append(result.sharedBypassPortEntries, entry)
		} else {
			result.localBypassPortEntries = append(result.localBypassPortEntries, entry)
		}
	}
	return result, bypass, nil
}

func isDNSHijackPort(rule PortDecision) bool {
	return rule.Action == DecisionIntercept && rule.Port == 53 &&
		(rule.Protocol == ProtocolTCP || rule.Protocol == ProtocolUDP)
}
