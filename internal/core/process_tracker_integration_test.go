//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// No self-bypass or cgroup interception release hook is present: application
// socket metadata must be reclaimed by the process tracker itself.
func TestProcessTrackerPolicySocketReleaseIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test process tracker metadata cleanup")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 170)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveCurrentProcessToCgroup(t, path, root)
	for _, policy := range []bool{false, true} {
		name := "owner_only"
		if policy {
			name = "uid_policy"
		}
		t.Run(name, func(t *testing.T) {
			owners, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 4, MaxEntries: 8})
			if err != nil {
				_ = owners.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = metadata.Close() })
			tracker := &ProcessTracker{owners: owners}
			t.Cleanup(func() { _ = tracker.Close() })
			if policy {
				tracker.policyUID, err = CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 1, Flags: bpfFlagNoPrealloc})
				if err != nil {
					t.Fatal(err)
				}
				uid := uint32(os.Getuid())
				if err = populateUIDPolicyMap(tracker.policyUID, compileUIDRanges([]UIDRange{{Start: uid, End: uid}})); err != nil {
					t.Fatal(err)
				}
				tracker.metadata = metadata
			}
			tracker.attachReleaseCleanup(path)
			if !tracker.ReleaseCleanup() {
				t.Fatal("process tracker socket-release hook did not attach")
			}
			for _, hook := range processTrackerHooks(ProcessTrackerConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true}) {
				program, err := newProcessTrackerProgram(hook, owners.FD(), tracker.policyUIDFD(), tracker.metadataFD(), false)
				if err != nil {
					t.Fatal(err)
				}
				tracker.programs = append(tracker.programs, program)
				link, err := attachCgroupProgram(path, program, hook.attachType)
				if err != nil {
					t.Fatal(err)
				}
				tracker.links = append(tracker.links, link)
			}
			for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
				for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
					// Churn beyond capacity; cleanup must not depend on eviction.
					for iteration := 0; iteration < 24; iteration++ {
						assertProcessTrackerSocketReleased(t, tracker, metadata, family, kind, iteration%2 == 0)
					}
				}
			}
		})
	}
}

func assertProcessTrackerSocketReleased(t *testing.T, tracker *ProcessTracker, metadata *CiliumEBPF.Map, family, kind int, removeOwner bool) {
	t.Helper()
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	var destination unix.Sockaddr = &unix.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}}
	if family == unix.AF_INET6 {
		destination = &unix.SockaddrInet6{Port: 1, Addr: [16]byte{15: 1}}
	}
	if kind == unix.SOCK_STREAM {
		err = unix.Connect(fd, destination)
	} else {
		err = unix.Sendto(fd, []byte{1}, 0, destination)
	}
	if err != nil && !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatal(err)
	}
	var owner ProcessSocketOwner
	if err = tracker.owners.Lookup(&cookie, &owner); err != nil {
		t.Fatalf("socket was not tracked (family=%d kind=%d): %v", family, kind, err)
	}
	if tracker.metadata != nil {
		var value uint32
		if err = metadata.Lookup(&cookie, &value); err != nil || value != SocketMetadataPolicyBypass {
			t.Fatalf("policy metadata = %d, want bypass: %v", value, err)
		}
	}
	if removeOwner {
		// Owner LRU eviction must not prevent metadata cleanup.
		if err = tracker.owners.Delete(&cookie); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	deadline := time.Now().Add(time.Second)
	for {
		var value uint32
		ownerErr := tracker.owners.Lookup(&cookie, &owner)
		metadataErr := metadata.Lookup(&cookie, &value)
		if errors.Is(ownerErr, CiliumEBPF.ErrKeyNotExist) && errors.Is(metadataErr, CiliumEBPF.ErrKeyNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed socket retained (family=%d kind=%d): owner=%v metadata=%v value=%d", family, kind, ownerErr, metadataErr, value)
		}
		time.Sleep(time.Millisecond)
	}
}

// replaceDetectCgroup2Root points AttachProcessTracker at a dedicated test
// cgroup instead of the real cgroup v2 root.
func replaceDetectCgroup2Root(t *testing.T, path string) {
	t.Helper()
	original := detectCgroup2Root
	detectCgroup2Root = func() (string, error) { return path, nil }
	t.Cleanup(func() { detectCgroup2Root = original })
}

// attachExclusiveCreateTestProgram reproduces netd-style unflagged
// BPF_PROG_ATTACH on the socket-create hook. The ID stays attached after the
// program FD is closed, and the hook is left in single-program mode.
func attachExclusiveCreateTestProgram(t *testing.T, cgroupFile *os.File) CiliumEBPF.ProgramID {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "foreign_create",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup sock programs are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer program.Close()
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  CiliumEBPF.AttachCGroupInetSockCreate,
	}); err != nil {
		t.Fatal(err)
	}
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	t.Cleanup(func() {
		if leftover, openErr := CiliumEBPF.NewProgramFromID(id); openErr == nil {
			_ = rawDetachProgram(int(cgroupFile.Fd()), leftover, CiliumEBPF.AttachCGroupInetSockCreate)
			_ = leftover.Close()
		}
	})
	return id
}

func hookProgramNames(t *testing.T, cgroupFile *os.File, attachType CiliumEBPF.AttachType) []string {
	t.Helper()
	ids, err := queryCgroupProgramIDs(int(cgroupFile.Fd()), attachType)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, id := range ids {
		program, err := CiliumEBPF.NewProgramFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		info, err := program.Info()
		_ = program.Close()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, info.Name)
	}
	return names
}

func requireCreateHookMulti(t *testing.T, cgroupFile *os.File, context string) {
	t.Helper()
	flags, err := queryCgroupHookFlags(int(cgroupFile.Fd()), CiliumEBPF.AttachCGroupInetSockCreate)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.BPF_F_ALLOW_MULTI == 0 {
		t.Fatalf("%s: create hook flags = %#x, want multi-program mode", context, flags)
	}
}

func fullTrackerConfig() ProcessTrackerConfig {
	// The zero value of Decision is DecisionPass, which would activate the
	// UID policy marking and require a self-bypass metadata map; these tests
	// exercise owner recording only.
	return ProcessTrackerConfig{
		EnableTCP:  true,
		EnableUDP:  true,
		EnableIPv6: true,
		Default:    DecisionIntercept,
	}
}

// Android 15+ netd holds the connect hooks in single-program mode. The
// socket-create hook must attach anyway so owner recording works, and the
// refused legacy connect hook must not fail the tracker.
func TestProcessTrackerCreateHookWithNetdOccupiedConnectIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 99)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	replaceDetectCgroup2Root(t, path)

	tracker, err := AttachProcessTracker(fullTrackerConfig())
	if err != nil {
		t.Fatalf("attach with netd holding connect4: %v", err)
	}
	t.Cleanup(func() { _ = tracker.Close() })

	if !tracker.CreateHook() {
		t.Fatal("socket-create hook did not attach while netd holds connect4")
	}
	// netd keeps its exclusive owner: the tracker must not have touched it.
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{netdID}, "after tracker attach")
	// The create hook stays in multi-program mode so the interception
	// backend and a later tracker remain attachable.
	requireCreateHookMulti(t, cgroupFile, "after tracker attach")
	if names := hookProgramNames(t, cgroupFile, CiliumEBPF.AttachCGroupInetSockCreate); !slices.Contains(names, kernelProgramNameProcessCreate) {
		t.Fatalf("create hook programs = %v, want %q among them", names, kernelProgramNameProcessCreate)
	}
	// The legacy hooks that stayed free supplement the create hook.
	if names := hookProgramNames(t, cgroupFile, CiliumEBPF.AttachCGroupUDP4Sendmsg); !slices.Contains(names, kernelProgramNameProcessSendmsg4) {
		t.Fatalf("sendmsg4 programs = %v, want %q among them", names, kernelProgramNameProcessSendmsg4)
	}
}

// When something else already occupies the socket-create hook, the legacy
// connect/sendmsg hooks still carry the tracker: no error and no create hook.
func TestProcessTrackerFallsBackToLegacyHooksIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 101)
	attachExclusiveCreateTestProgram(t, cgroupFile)
	replaceDetectCgroup2Root(t, path)

	tracker, err := AttachProcessTracker(fullTrackerConfig())
	if err != nil {
		t.Fatalf("attach with an occupied socket-create hook: %v", err)
	}
	t.Cleanup(func() { _ = tracker.Close() })

	if tracker.CreateHook() {
		t.Fatal("tracker reports the socket-create hook although a foreign program owns it")
	}
	if owners := hookProgramNames(t, cgroupFile, CiliumEBPF.AttachCGroupInetSockCreate); !slices.Equal(owners, []string{"foreign_create"}) {
		t.Fatalf("create hook programs = %v, want the foreign owner alone", owners)
	}
	if names := hookProgramNames(t, cgroupFile, CiliumEBPF.AttachCGroupUDP4Sendmsg); !slices.Contains(names, kernelProgramNameProcessSendmsg4) {
		t.Fatalf("sendmsg4 programs = %v, want %q among them", names, kernelProgramNameProcessSendmsg4)
	}
}

// Without the create hook the legacy failure semantics stay as they were
// before it existed: a refused connect hook fails the whole tracker.
func TestProcessTrackerFailsWhenCreateAndLegacyHooksOccupiedIntegration(t *testing.T) {
	path, cgroupFile := dedicatedHookOwnerCgroup(t, 102)
	attachExclusiveCreateTestProgram(t, cgroupFile)
	placeholder := newHookOwnerTestProgram(t, "connect4_inet4_")
	t.Cleanup(func() { _ = placeholder.Close() })
	netdID := attachLikeNetd(t, cgroupFile, placeholder)
	replaceDetectCgroup2Root(t, path)

	tracker, err := AttachProcessTracker(fullTrackerConfig())
	if err == nil {
		_ = tracker.Close()
		t.Fatal("attach succeeded although the create and connect hooks are occupied")
	}
	if !strings.Contains(err.Error(), "socket-create hook") {
		t.Fatalf("attach error = %v, want the socket-create failure included", err)
	}
	if tracker != nil && !tracker.IsClosed() {
		t.Fatal("failed attach returned an open tracker")
	}
	// netd keeps its exclusive connect4 owner after the rollback.
	requireConnect4Owners(t, cgroupFile, []CiliumEBPF.ProgramID{netdID}, "after rollback")
}
