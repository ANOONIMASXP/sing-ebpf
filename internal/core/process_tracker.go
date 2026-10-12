//go:build with_ebpf && (linux || android)

package core

import (
	"runtime"
	"slices"
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	processSocketOwnerCapacity        = 16384
	compactProcessSocketOwnerCapacity = 8192
)

func processSocketOwnerMapCapacity(platform string) uint32 {
	if platform == "android" {
		return compactProcessSocketOwnerCapacity
	}
	return processSocketOwnerCapacity
}

const (
	socketMetadataPolicyBypass    = SocketMetadataPolicyBypass
	socketMetadataPolicyIntercept = SocketMetadataPolicyIntercept
)

type ProcessTrackerConfig struct {
	EnableTCP    bool
	EnableUDP    bool
	EnableIPv6   bool
	UIDDecisions []UIDDecision
	Default      Decision
	MetadataMap  *CiliumEBPF.Map
}

type ProcessSocketOwner struct {
	ProcessID uint32
	UserID    uint32
}

type processTrackerHook struct {
	hookName          string
	kernelProgramName string
	attachType        CiliumEBPF.AttachType
}

// ProcessTracker records the process performing connect or UDP sendmsg for a
// socket. Socket cookies let the TC data path carry that identity to userspace
// without searching every process file descriptor under procfs.
type ProcessTracker struct {
	access              sync.RWMutex
	owners              *CiliumEBPF.Map
	policyUID           *CiliumEBPF.Map
	metadata            *CiliumEBPF.Map
	policyDefaultBypass bool
	programs            []*CiliumEBPF.Program
	links               []cgroupProgramLink
	releaseCleanup      bool
	createHook          bool
}

// detectCgroup2Root is replaced in tests so AttachProcessTracker can attach
// to a dedicated test cgroup instead of the real cgroup v2 root.
var detectCgroup2Root = DetectCgroup2Root

func AttachProcessTracker(config ProcessTrackerConfig) (*ProcessTracker, error) {
	if !config.EnableTCP && !config.EnableUDP {
		return nil, E.New("process tracker has no enabled protocol")
	}
	memlockErr := raiseMemlockLimit()
	cgroupPath, err := detectCgroup2Root()
	if err != nil {
		return nil, E.Cause(err, "detect cgroup v2 root")
	}
	owners, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_proc_owner",
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: processSocketOwnerMapCapacity(runtime.GOOS),
	})
	if err != nil {
		return nil, E.Cause(explainBPFPermissionError(err, memlockErr), "create eBPF process owner map")
	}
	uidEntries, defaultBypass, err := compileUIDDecisions(config.UIDDecisions, config.Default)
	if err != nil {
		_ = owners.Close()
		return nil, err
	}
	tracker := &ProcessTracker{
		owners: owners,
	}
	if len(uidEntries) > 0 || defaultBypass {
		if err = checkLPMTriePolicyCompatibility("eBPF process UID policy", len(uidEntries)); err != nil {
			_ = owners.Close()
			return nil, err
		}
		uidPolicy, mapErr := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
			Name:       "sb_proc_uid",
			Type:       CiliumEBPF.LPMTrie,
			KeySize:    8,
			ValueSize:  1,
			MaxEntries: max(uint32(len(uidEntries)), 1),
			Flags:      bpfFlagNoPrealloc,
		})
		if mapErr != nil {
			_ = owners.Close()
			return nil, E.Cause(mapErr, "create eBPF process UID policy map")
		}
		if mapErr = populateUIDPolicyMap(uidPolicy, uidEntries); mapErr != nil {
			_ = uidPolicy.Close()
			_ = owners.Close()
			return nil, E.Cause(mapErr, "populate eBPF process UID policy map")
		}
		if config.MetadataMap == nil {
			_ = uidPolicy.Close()
			_ = owners.Close()
			return nil, E.New("eBPF socket metadata map is unavailable")
		}
		tracker.metadata = config.MetadataMap
		tracker.policyUID = uidPolicy
		tracker.policyDefaultBypass = defaultBypass
	}
	// Establish cleanup before any hook can publish an application cookie.
	// Appending it first also keeps cleanup attached until all writers detach.
	tracker.attachReleaseCleanup(cgroupPath)
	// Socket creation is the primary owner hook: its attach type never
	// shares a hook with the connect/sendmsg placeholders Android netd keeps
	// on the cgroup v2 root, so it stays attachable where the legacy hooks
	// below are refused. A create failure only matters when no legacy hook
	// attaches either.
	createErr := tracker.attachCreateHook(cgroupPath, config)
	for _, hook := range processTrackerHooks(config) {
		program, loadErr := newProcessTrackerProgram(hook, owners.FD(), tracker.policyUIDFD(), tracker.metadataFD(), tracker.policyDefaultBypass)
		if loadErr != nil {
			if createErr == nil {
				// The create hook already records every enabled protocol;
				// a failed legacy hook only loses the connect-time owner
				// correction for sockets created before the tracker ran.
				continue
			}
			return rollbackProcessTracker(tracker, E.Errors(createErr, loadErr))
		}
		tracker.programs = append(tracker.programs, program)
		// The tracker always uses the cgroup v2 root, which is also the
		// default interception cgroup. It must never leave a root hook in
		// single-program mode: that would make the kernel reject the
		// interception backend's own attachment, and the backend, unlike the
		// tracker, has no userspace fallback.
		programLink, attachErr := attachCgroupProgramShared(cgroupPath, program, hook.attachType)
		if attachErr != nil {
			if createErr == nil {
				continue
			}
			return rollbackProcessTracker(tracker, E.Errors(createErr, E.Cause(attachErr, "attach eBPF process tracker ", hook.hookName, " hook")))
		}
		tracker.links = append(tracker.links, programLink)
	}
	return tracker, nil
}

// attachCreateHook records process ownership at inet socket creation. A
// failure is recoverable: the caller keeps the tracker usable through the
// legacy connect/sendmsg hooks and only fails when those are refused too.
func (t *ProcessTracker) attachCreateHook(cgroupPath string, config ProcessTrackerConfig) error {
	program, err := newProcessTrackerCreateProgram(t.owners.FD(), t.policyUIDFD(), t.metadataFD(), t.policyDefaultBypass, config.EnableTCP, config.EnableIPv6)
	if err != nil {
		return err
	}
	t.programs = append(t.programs, program)
	// Same shared multi-program policy as the legacy hooks: never convert a
	// root hook into single-program mode for an optional component.
	programLink, err := attachCgroupProgramShared(cgroupPath, program, CiliumEBPF.AttachCGroupInetSockCreate)
	if err != nil {
		return E.Cause(err, "attach eBPF process tracker socket-create hook")
	}
	t.links = append(t.links, programLink)
	t.createHook = true
	return nil
}

// compileUIDDecisions converts final action decisions into the membership map
// used by the tracker. The map stores only actions different from Default;
// the kernel program treats a match as the inverse of the default action.
// This keeps sing-ebpf independent from sing-box's include/exclude semantics.
func compileUIDDecisions(decisions []UIDDecision, defaultDecision Decision) ([]uidLPMKey, bool, error) {
	if !defaultDecision.Valid() {
		return nil, false, E.New("invalid eBPF process tracker default action")
	}
	var ranges []UIDRange
	for _, decision := range decisions {
		if decision.Start > decision.End || !decision.Action.Valid() {
			return nil, false, E.New("invalid eBPF process tracker UID decision")
		}
		if decision.Action != defaultDecision {
			ranges = append(ranges, UIDRange{Start: decision.Start, End: decision.End})
		}
	}
	entries := compileUIDRanges(normalizeUIDRanges(ranges))
	if len(entries) > maxUIDPolicyEntries {
		return nil, false, E.New("UID policy compiles to too many eBPF map entries: ", len(entries), " > ", maxUIDPolicyEntries)
	}
	return entries, defaultDecision == DecisionPass, nil
}

// rollbackProcessTracker returns the tracker together with the startup error
// only when a legacy attachment could not be detached. The caller then owns
// that incomplete tracker and must retain it until Close succeeds.
func rollbackProcessTracker(tracker *ProcessTracker, startupErr error) (*ProcessTracker, error) {
	closeErr := tracker.Close()
	if closeErr != nil && !tracker.IsClosed() {
		return tracker, E.Errors(startupErr, E.Cause(closeErr, "rollback eBPF process tracker"))
	}
	return nil, E.Errors(startupErr, closeErr)
}

// attachReleaseCleanup removes both ownership and optional UID policy metadata
// as soon as the socket dies. The consumer's self-bypass release hook may cover
// only its own cgroup, while our writers observe sockets across the root cgroup.
// Both maps retain LRU fallback when sock_release cannot be loaded or attached.
func (t *ProcessTracker) attachReleaseCleanup(cgroupPath string) {
	program, err := newProcessTrackerReleaseProgram(t.owners.FD(), t.metadataFD())
	if err != nil {
		return
	}
	programLink, err := attachCgroupProgramShared(cgroupPath, program, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = program.Close()
		return
	}
	t.programs = append(t.programs, program)
	t.links = append(t.links, programLink)
	t.releaseCleanup = true
}

func (t *ProcessTracker) ReleaseCleanup() bool {
	return t != nil && t.releaseCleanup
}

// CreateHook reports whether the socket-create owner hook attached. The mode
// string it feeds distinguishes that path from the legacy connect/sendmsg
// hooks, which is how a device whose root hooks are held by netd placeholders
// shows up in logs.
func (t *ProcessTracker) CreateHook() bool {
	return t != nil && t.createHook
}

func processTrackerHooks(config ProcessTrackerConfig) []processTrackerHook {
	var hooks []processTrackerHook
	if config.EnableTCP {
		hooks = append(hooks, processTrackerHook{"connect4", kernelProgramNameProcessConnect4, CiliumEBPF.AttachCGroupInet4Connect})
		if config.EnableIPv6 {
			hooks = append(hooks, processTrackerHook{"connect6", kernelProgramNameProcessConnect6, CiliumEBPF.AttachCGroupInet6Connect})
		}
	}
	if config.EnableUDP {
		hooks = append(hooks, processTrackerHook{"sendmsg4", kernelProgramNameProcessSendmsg4, CiliumEBPF.AttachCGroupUDP4Sendmsg})
		if config.EnableIPv6 {
			hooks = append(hooks, processTrackerHook{"sendmsg6", kernelProgramNameProcessSendmsg6, CiliumEBPF.AttachCGroupUDP6Sendmsg})
		}
	}
	return hooks
}

func newProcessTrackerProgram(hook processTrackerHook, ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass bool) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         hook.kernelProgramName,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   hook.attachType,
		License:      "GPL",
		Instructions: processTrackerInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD, defaultBypass),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF process tracker ", hook.hookName, " hook")
	}
	return program, nil
}

func newProcessTrackerReleaseProgram(ownerMapFD, metadataMapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameProcessRelease,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
		License:      "GPL",
		Instructions: processTrackerReleaseInstructions(ownerMapFD, metadataMapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF process tracker socket-release hook")
	}
	return program, nil
}

func processTrackerReleaseInstructions(ownerMapFD, metadataMapFD int) asm.Instructions {
	return socketCookieDeleteInstructions(ownerMapFD, metadataMapFD)
}

// struct bpf_sock field offsets and values used by the socket-create prologue,
// from include/uapi/linux/bpf.h. The verifier allows reading family and
// protocol for BPF_CGROUP_INET_SOCK_CREATE and rewrites the loads onto
// skc_family/sk_protocol; inet_create assigns sk->sk_protocol before it runs
// BPF_CGROUP_RUN_PROG_INET_SOCK.
const (
	bpfSockFamilyOffset   = 4
	bpfSockProtocolOffset = 12
	bpfSockFamilyINET6    = 10 // AF_INET6
	bpfSockProtocolUDP    = 17 // IPPROTO_UDP
)

func newProcessTrackerCreateProgram(ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass, enableTCP, enableIPv6 bool) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(processTrackerCreateProgramSpec(ownerMapFD, policyUIDMapFD, metadataMapFD, defaultBypass, enableTCP, enableIPv6))
	if err != nil {
		return nil, E.Cause(err, "load eBPF process tracker socket-create hook")
	}
	return program, nil
}

// processTrackerCreateProgramSpec exists as a pure constructor so tests can
// assert the program type, attach type, and instruction layout without a
// kernel that can load BPF programs.
func processTrackerCreateProgramSpec(ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass, enableTCP, enableIPv6 bool) *CiliumEBPF.ProgramSpec {
	return &CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameProcessCreate,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: processTrackerCreateInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD, defaultBypass, enableTCP, enableIPv6),
	}
}

// processTrackerCreateInstructions prepends the family/protocol gates of the
// socket-create hook to the shared owner-recording body. The gates preserve
// the legacy hook selection: with TCP enabled every inet socket is recorded
// (the connect hook used to cover connected UDP too), with TCP disabled only
// SOCK_DGRAM/IPPROTO_UDP sockets are, and IPv6 sockets follow EnableIPv6.
// R1 keeps the context across the prologue so the body's cookie read still
// sees it.
func processTrackerCreateInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass, enableTCP, enableIPv6 bool) asm.Instructions {
	return append(processTrackerCreatePrologue(enableTCP, enableIPv6),
		processTrackerInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD, defaultBypass)...)
}

func processTrackerCreatePrologue(enableTCP, enableIPv6 bool) asm.Instructions {
	var instructions asm.Instructions
	if !enableIPv6 {
		instructions = append(instructions,
			asm.LoadMem(asm.R2, asm.R1, bpfSockFamilyOffset, asm.Word),
			asm.JEq.Imm(asm.R2, bpfSockFamilyINET6, "allow"),
		)
	}
	if !enableTCP {
		instructions = append(instructions,
			asm.LoadMem(asm.R2, asm.R1, bpfSockProtocolOffset, asm.Word),
			asm.JNE.Imm(asm.R2, bpfSockProtocolUDP, "allow"),
		)
	}
	return instructions
}

func processTrackerInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass bool) asm.Instructions {
	instructions := asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, ownerMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "update_owner"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.Word),
		asm.JNE.Reg(asm.R1, asm.R2, "update_owner"),
		asm.LoadMem(asm.R1, asm.R6, 4, asm.Word),
		asm.LoadMem(asm.R2, asm.RFP, -12, asm.Word),
		asm.JEq.Reg(asm.R1, asm.R2, "policy"),
		asm.LoadMapPtr(asm.R1, ownerMapFD).WithSymbol("update_owner"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Ja.Label("policy"),
	}
	if policyUIDMapFD < 0 || metadataMapFD < 0 {
		instructions = append(instructions,
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("policy"),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
			asm.Return(),
		)
		return instructions
	}
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, -24, 32, asm.Word).WithSymbol("policy"),
		asm.LoadMapPtr(asm.R1, metadataMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "metadata_empty"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.And.Imm(asm.R0, SocketMetadataSelfBypass),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.Ja.Label("lookup_policy_uid"),
		asm.StoreImm(asm.RFP, -28, 0, asm.Word).WithSymbol("metadata_empty"),
		asm.LoadMem(asm.R0, asm.RFP, -12, asm.Word).WithSymbol("lookup_policy_uid"),
		// UID trie keys are network-order, not unconditionally byte-swapped.
		// The classic END instruction also works before BPF ISA v4.
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, policyUIDMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "policy_unmatched"),
		asm.LoadMem(asm.R0, asm.RFP, -28, asm.Word),
		asm.Or.Imm(asm.R0, processTrackerPolicyMetadata(defaultBypass, true)),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.Ja.Label("policy_update"),
		asm.LoadMem(asm.R0, asm.RFP, -28, asm.Word).WithSymbol("policy_unmatched"),
		asm.Or.Imm(asm.R0, processTrackerPolicyMetadata(defaultBypass, false)),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, metadataMapFD).WithSymbol("policy_update"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -28),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return instructions
}

func processTrackerPolicyMetadata(defaultBypass bool, matched bool) int32 {
	if matched == defaultBypass {
		return socketMetadataPolicyIntercept
	}
	return socketMetadataPolicyBypass
}

func (t *ProcessTracker) policyUIDFD() int {
	if t == nil || t.policyUID == nil {
		return -1
	}
	return t.policyUID.FD()
}

func (t *ProcessTracker) metadataFD() int {
	if t == nil || t.metadata == nil {
		return -1
	}
	return t.metadata.FD()
}

func (t *ProcessTracker) LookupOwner(socketCookie uint64) (ProcessSocketOwner, error) {
	if t == nil || socketCookie == 0 {
		return ProcessSocketOwner{}, E.New("invalid eBPF process owner lookup")
	}
	t.access.RLock()
	defer t.access.RUnlock()
	if t.owners == nil {
		return ProcessSocketOwner{}, E.New("invalid eBPF process owner lookup")
	}
	var owner ProcessSocketOwner
	if err := t.owners.Lookup(&socketCookie, &owner); err != nil {
		return ProcessSocketOwner{}, err
	}
	return owner, nil
}

func (t *ProcessTracker) Close() error {
	if t == nil {
		return nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	var closeErr error
	linksClosed := true
	for index, programLink := range slices.Backward(t.links) {
		if programLink == nil {
			continue
		}
		linkErr := programLink.Close()
		closeErr = E.Errors(closeErr, linkErr)
		if cgroupProgramLinkCloseComplete(programLink, linkErr) {
			t.links[index] = nil
		} else {
			linksClosed = false
		}
	}
	if !linksClosed {
		return closeErr
	}
	for index, program := range slices.Backward(t.programs) {
		if program == nil {
			continue
		}
		closeErr = E.Errors(closeErr, program.Close())
		t.programs[index] = nil
	}
	if t.owners != nil {
		closeErr = E.Errors(closeErr, t.owners.Close())
		t.owners = nil
	}
	if t.policyUID != nil {
		closeErr = E.Errors(closeErr, t.policyUID.Close())
		t.policyUID = nil
	}
	return closeErr
}

func (t *ProcessTracker) IsClosed() bool {
	if t == nil {
		return true
	}
	t.access.RLock()
	defer t.access.RUnlock()
	return t.owners == nil && t.policyUID == nil && lenOpenCgroupProgramLinks(t.links) == 0
}

func lenOpenCgroupProgramLinks(links []cgroupProgramLink) int {
	var count int
	for _, programLink := range links {
		if programLink != nil {
			count++
		}
	}
	return count
}
