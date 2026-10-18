//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"sync"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// ICMPEchoReplyBackend answers ICMP Echo Request packets destined to the
// configured force-intercept prefixes with a locally synthesized Echo Reply. It is a
// standalone backend, independent of TCBackend and SharedPacketRewriteBackend,
// because icmp_echo_reply.bpf.c is its own native object with its own control
// map (see that file's own comment for why it is not folded into either
// tc.bpf.c or shared_network.bpf.c) and because more than one caller needs
// to host it: TCBackend does, for local TC and shared socket_assign, and so
// does shared.data_plane: packet_rewrite, which has no TCBackend of its own
// at all. Prior to this type existing, only TCBackend could load this
// object, which meant a packet_rewrite-only inbound (no local interception,
// no socket_assign) had nothing to host the responder on even though the
// native object itself has always supported a "shared reply" path.
type ICMPEchoReplyBackend struct {
	access    sync.RWMutex
	runtime   *tcRuntime
	controlFD int
	closed    bool
}

const (
	icmpEchoReplyProgramLocalEthernet = iota
	icmpEchoReplyProgramLocalRawIP
	icmpEchoReplyProgramSharedEthernet
	icmpEchoReplyProgramSharedRawIP
	icmpEchoReplyProgramCount
)

const (
	icmpEchoReplyFlagEnabled            = 1 << 0
	icmpEchoReplyFlagIPv4               = 1 << 1
	icmpEchoReplyFlagLocalIPv6          = 1 << 2
	icmpEchoReplyFlagSharedIPv6         = 1 << 3
	icmpEchoReplyFlagForceInterceptIPv4 = 1 << 4
	icmpEchoReplyFlagForceInterceptIPv6 = 1 << 5
)

// These three mirror native/icmp_echo_reply.bpf.c's SB_ICMP_ECHO_REPLY_STAT_* indices
// and SB_ICMP_ECHO_REPLY_STAT_COUNT field for field; there is no generated
// binding for either side's constants, so this comment is the ABI contract
// between them. See that file's own comment on icmp_echo_reply_stats for why
// ordinary non-ICMP traffic on the same interface is never counted here at
// all: PassThrough only ever counts an ICMP/ICMPv6 Echo Request this object
// examined and declined to answer.
const (
	icmpEchoReplyStatReply          uint32 = 0
	icmpEchoReplyStatPassThrough    uint32 = 1
	icmpEchoReplyStatRewriteFailure uint32 = 2
	icmpEchoReplyStatCount                 = 3
)

// icmpEchoReplyControl mirrors struct sb_icmp_echo_reply_control in
// native/icmp_echo_reply.bpf.c field for field; the _Static_assert in that file
// is this struct's ABI contract.
type icmpEchoReplyControl struct {
	Flags uint32
}

// loadICMPEchoReplyResources loads the object's two maps and four programs. The
// maps are kept even though this object has no config-shaped sizing to do,
// because loadObjectMaps drops any map not named in its overrides — the
// overrides here exist to rename and place them, not to resize them.
func loadICMPEchoReplyResources(policy CompiledPolicy) (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := map[string]mapSpecOverride{
		"icmp_echo_reply_control": {name: "sb_icmp_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
		"icmp_echo_reply_stats":   {name: "sb_icmp_stat", mapType: CiliumEBPF.PerCPUArray, maxEntries: icmpEchoReplyStatCount},
	}
	addForceMapOverrides(mapOverrides, "icmp_local", "sb_icmp_lforce", policy.localForce)
	addForceMapOverrides(mapOverrides, "icmp_shared", "sb_icmp_sforce", policy.sharedForce)
	maps, err := loadObjectMaps(loadICMPEchoReply, mapOverrides)
	if err != nil {
		return nil, nil, err
	}
	selections := []programSelection{
		{section: "classifier/icmp_echo_reply_local_reply_ethernet", kernelProgramName: kernelProgramNameICMPLocalEthernet},
		{section: "classifier/icmp_echo_reply_local_reply_raw_ip", kernelProgramName: kernelProgramNameICMPLocalRawIP},
		{section: "classifier/icmp_echo_reply_shared_reply_ethernet", kernelProgramName: kernelProgramNameICMPSharedEthernet},
		{section: "classifier/icmp_echo_reply_shared_reply_raw_ip", kernelProgramName: kernelProgramNameICMPSharedRawIP},
	}
	programs, err := loadObjectPrograms(loadICMPEchoReply, maps, selections)
	if err != nil {
		return nil, nil, E.Errors(err, closeMaps(maps))
	}
	return maps, programs, nil
}

// PrepareICMPEchoReply loads a standalone responder with independent local and
// shared destination sets. Family flags mirror the selected caller scopes.
func PrepareICMPEchoReply(
	ipv4Enabled bool,
	localIPv6Enabled bool,
	sharedIPv6Enabled bool,
	policy CompiledPolicy,
) (*ICMPEchoReplyBackend, error) {
	policy = policy.echoReplyPolicy()
	if len(policy.localForce.ipv4)+len(policy.localForce.ipv6)+len(policy.sharedForce.ipv4)+len(policy.sharedForce.ipv6) == 0 {
		return nil, E.New("ICMP echo reply requires a configured force-intercept prefix")
	}
	maps, programs, err := loadICMPEchoReplyResources(policy)
	if err != nil {
		return nil, E.Cause(err, "load icmp_echo_reply eBPF resources")
	}
	if err = populateCompiledPolicyMaps(policyMapTargets{
		Scope:          "ICMP echo reply",
		LocalForceIPv4: maps["icmp_local_force4"], LocalForceIPv6: maps["icmp_local_force6"],
		SharedForceIPv4: maps["icmp_shared_force4"], SharedForceIPv6: maps["icmp_shared_force6"],
	}, policy); err != nil {
		return nil, E.Errors(err, closeObjectResources(programs, maps))
	}
	control := icmpEchoReplyControl{}
	if ipv4Enabled {
		control.Flags |= icmpEchoReplyFlagIPv4
	}
	if localIPv6Enabled {
		control.Flags |= icmpEchoReplyFlagLocalIPv6
	}
	if sharedIPv6Enabled {
		control.Flags |= icmpEchoReplyFlagSharedIPv6
	}
	control.Flags |= icmpEchoReplyFlagEnabled
	controlFD := maps["icmp_echo_reply_control"].FD()
	zero := uint32(0)
	if err = updateMap(controlFD, unsafe.Pointer(&zero), unsafe.Pointer(&control)); err != nil {
		closeErr := closeObjectResources(programs, maps)
		return nil, E.Errors(E.Cause(err, "populate icmp_echo_reply eBPF control"), closeErr)
	}
	return &ICMPEchoReplyBackend{
		runtime:   &tcRuntime{maps: maps, programs: programs},
		controlFD: controlFD,
	}, nil
}

func (b *ICMPEchoReplyBackend) program(index int) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed || index < 0 || index >= len(b.runtime.programs) {
		return nil
	}
	return b.runtime.programs[index]
}

func (b *ICMPEchoReplyBackend) programFD(index int) int {
	program := b.program(index)
	if program == nil {
		return -1
	}
	return program.FD()
}

func (b *ICMPEchoReplyBackend) LocalReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(icmpEchoReplyProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(icmpEchoReplyProgramLocalRawIP)
	default:
		return -1
	}
}

func (b *ICMPEchoReplyBackend) LocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(icmpEchoReplyProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.program(icmpEchoReplyProgramLocalRawIP)
	default:
		return nil
	}
}

func (b *ICMPEchoReplyBackend) SharedReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(icmpEchoReplyProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(icmpEchoReplyProgramSharedRawIP)
	default:
		return -1
	}
}

func (b *ICMPEchoReplyBackend) SharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(icmpEchoReplyProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.program(icmpEchoReplyProgramSharedRawIP)
	default:
		return nil
	}
}

// ReplyCount, PassThroughCount, and RewriteFailureCount read
// icmp_echo_reply_stats' three categories -- see that map's own doc comment in
// native/icmp_echo_reply.bpf.c. Each is a full PERCPU_ARRAY sum, computed fresh
// on every call; callers polling frequently should cache accordingly.
func (b *ICMPEchoReplyBackend) ReplyCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatReply)
}

func (b *ICMPEchoReplyBackend) PassThroughCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatPassThrough)
}

func (b *ICMPEchoReplyBackend) RewriteFailureCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatRewriteFailure)
}

func (b *ICMPEchoReplyBackend) stat(index uint32) (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed {
		return 0, errBackendClosed
	}
	statsMap := b.runtime.maps["icmp_echo_reply_stats"]
	if statsMap == nil {
		return 0, errBackendClosed
	}
	var perCPU []uint64
	if err := statsMap.Lookup(&index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range perCPU {
		total += value
	}
	return total, nil
}

// Close releases the object's maps and programs. Safe to call on a nil
// receiver or more than once.
func (b *ICMPEchoReplyBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return closeObjectResources(b.runtime.programs, b.runtime.maps)
}

// echoReplyPolicy returns the destination sets the responder answers, in the
// force-intercept fields it loads: per scope and address family, the
// intercept prefixes selected by CIDRDecision.EchoReply, or every intercept
// prefix of that family when none is selected.
func (p CompiledPolicy) echoReplyPolicy() CompiledPolicy {
	answered := func(force, echoReply []netip.Prefix) []netip.Prefix {
		if len(echoReply) > 0 {
			return echoReply
		}
		return force
	}
	return CompiledPolicy{
		localForce: dualStackCIDRPrefixes{
			ipv4: answered(p.localForce.ipv4, p.localEchoReply.ipv4),
			ipv6: answered(p.localForce.ipv6, p.localEchoReply.ipv6),
		},
		sharedForce: dualStackCIDRPrefixes{
			ipv4: answered(p.sharedForce.ipv4, p.sharedEchoReply.ipv4),
			ipv6: answered(p.sharedForce.ipv6, p.sharedEchoReply.ipv6),
		},
	}
}
