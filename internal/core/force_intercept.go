//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"slices"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ForceInterceptPrefixesPerFamily is the number of force-intercept prefixes
// a compiled policy can carry per address family, merged from the intercept
// destination decisions of both scopes. Each interception data plane keeps
// that many slots (SB_EBPF_FORCE_INTERCEPT_SLOTS).
const ForceInterceptPrefixesPerFamily = 2

const forceInterceptSlots = ForceInterceptPrefixesPerFamily

// forceInterceptSlot mirrors struct sb_ebpf_force_intercept_slot.
type forceInterceptSlot struct {
	IPv4Prefix [4]byte
	IPv4Mask   [4]byte
	IPv6Prefix [16]byte
	IPv6Mask   [16]byte
}

// forceInterceptPolicy holds the destination prefixes every interception
// data plane intercepts ahead of its pass decisions, and the prefix of each
// address family that ICMP echo reply answers. An unused slot holds the zero
// prefix.
type forceInterceptPolicy struct {
	ipv4          [forceInterceptSlots]netip.Prefix
	ipv6          [forceInterceptSlots]netip.Prefix
	echoReplyIPv4 netip.Prefix
	echoReplyIPv6 netip.Prefix
}

func (p forceInterceptPolicy) controlSlots() [forceInterceptSlots]forceInterceptSlot {
	var slots [forceInterceptSlots]forceInterceptSlot
	for index := range slots {
		if prefix := p.ipv4[index]; prefix.IsValid() {
			slots[index].IPv4Prefix = prefix.Addr().As4()
			slots[index].IPv4Mask = prefixMask4(prefix.Bits())
		}
		if prefix := p.ipv6[index]; prefix.IsValid() {
			slots[index].IPv6Prefix = prefix.Addr().As16()
			slots[index].IPv6Mask = prefixMask16(prefix.Bits())
		}
	}
	return slots
}

func (p forceInterceptPolicy) enabledIPv4() [forceInterceptSlots]bool {
	var enabled [forceInterceptSlots]bool
	for index, prefix := range p.ipv4 {
		enabled[index] = prefix.IsValid()
	}
	return enabled
}

func (p forceInterceptPolicy) enabledIPv6() [forceInterceptSlots]bool {
	var enabled [forceInterceptSlots]bool
	for index, prefix := range p.ipv6 {
		enabled[index] = prefix.IsValid()
	}
	return enabled
}

// forceInterceptFamily collects the intercept destination prefixes of one
// address family from every scope.
type forceInterceptFamily struct {
	prefixes  []netip.Prefix
	echoReply netip.Prefix
}

func (f *forceInterceptFamily) add(prefix netip.Prefix, echoReply bool) error {
	if !slices.Contains(f.prefixes, prefix) {
		f.prefixes = append(f.prefixes, prefix)
	}
	if echoReply {
		if f.echoReply.IsValid() && f.echoReply != prefix {
			return E.New("multiple echo-reply intercept prefixes: ", f.echoReply, " and ", prefix)
		}
		f.echoReply = prefix
	}
	return nil
}

// slots assigns the collected prefixes to the data-plane slots, the
// echo-reply prefix first. A sole prefix that no decision selected for echo
// reply still answers it, as the single prefix did before echo reply could be
// selected.
func (f forceInterceptFamily) slots(family string) ([forceInterceptSlots]netip.Prefix, netip.Prefix, error) {
	var slots [forceInterceptSlots]netip.Prefix
	if len(f.prefixes) > forceInterceptSlots {
		prefixes := make([]string, 0, len(f.prefixes))
		for _, prefix := range f.prefixes {
			prefixes = append(prefixes, prefix.String())
		}
		return slots, netip.Prefix{}, E.New(family, " intercept prefixes [", strings.Join(prefixes, ", "),
			"] exceed the ", forceInterceptSlots, " force-intercept slots")
	}
	echoReply := f.echoReply
	if !echoReply.IsValid() && len(f.prefixes) == 1 {
		echoReply = f.prefixes[0]
	}
	index := 0
	if echoReply.IsValid() {
		slots[index] = echoReply
		index++
	}
	for _, prefix := range f.prefixes {
		if prefix != echoReply {
			slots[index] = prefix
			index++
		}
	}
	return slots, echoReply, nil
}

// forceInterceptBuilder merges the intercept destination decisions of the
// local and shared scopes. Every data plane holds one set of slots, so each
// prefix is intercepted on every path.
type forceInterceptBuilder struct {
	ipv4 forceInterceptFamily
	ipv6 forceInterceptFamily
}

func (b *forceInterceptBuilder) add(rule CIDRDecision) error {
	prefix := rule.Prefix.Masked()
	if prefix.Addr().Is4() {
		return b.ipv4.add(prefix, rule.EchoReply)
	}
	return b.ipv6.add(prefix, rule.EchoReply)
}

func (b forceInterceptBuilder) build() (forceInterceptPolicy, error) {
	var (
		policy forceInterceptPolicy
		err    error
	)
	policy.ipv4, policy.echoReplyIPv4, err = b.ipv4.slots("IPv4")
	if err != nil {
		return forceInterceptPolicy{}, err
	}
	policy.ipv6, policy.echoReplyIPv6, err = b.ipv6.slots("IPv6")
	if err != nil {
		return forceInterceptPolicy{}, err
	}
	return policy, nil
}
