//go:build with_ebpf && (linux || android)

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestProcessSocketOwnerABI(t *testing.T) {
	if size := unsafe.Sizeof(ProcessSocketOwner{}); size != 8 {
		t.Fatalf("unexpected process owner size: %d", size)
	}
}

func TestProcessTrackerCloseRetainsFailedLegacyAttachment(t *testing.T) {
	programLink := &retryableTestCgroupProgramLink{failures: 1}
	tracker := &ProcessTracker{links: []cgroupProgramLink{programLink}}
	if err := tracker.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if tracker.IsClosed() {
		t.Fatal("process tracker discarded a failed legacy attachment")
	}
	if err := tracker.Close(); err != nil {
		t.Fatalf("retry process tracker close: %v", err)
	}
	if !tracker.IsClosed() {
		t.Fatal("process tracker remained open after cleanup retry")
	}
}

func TestProcessTrackerHooks(t *testing.T) {
	if hooks := processTrackerHooks(ProcessTrackerConfig{}); len(hooks) != 0 {
		t.Fatalf("unexpected hooks for disabled protocols: %+v", hooks)
	}
	base := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true})
	if len(base) != 1 || base[0].attachType != CiliumEBPF.AttachCGroupInet4Connect {
		t.Fatalf("unexpected base process tracker hooks: %+v", base)
	}
	dualStackUDP := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true})
	if len(dualStackUDP) != 4 ||
		dualStackUDP[1].attachType != CiliumEBPF.AttachCGroupInet6Connect ||
		dualStackUDP[2].attachType != CiliumEBPF.AttachCGroupUDP4Sendmsg ||
		dualStackUDP[3].attachType != CiliumEBPF.AttachCGroupUDP6Sendmsg {
		t.Fatalf("unexpected dual-stack UDP process tracker hooks: %+v", dualStackUDP)
	}
	if dualStackUDP[0].kernelProgramName != kernelProgramNameProcessConnect4 ||
		dualStackUDP[1].kernelProgramName != kernelProgramNameProcessConnect6 ||
		dualStackUDP[2].kernelProgramName != kernelProgramNameProcessSendmsg4 ||
		dualStackUDP[3].kernelProgramName != kernelProgramNameProcessSendmsg6 {
		t.Fatalf("unexpected process tracker kernel program names: %+v", dualStackUDP)
	}
}

func TestProcessTrackerInstructions(t *testing.T) {
	instructions := processTrackerInstructions(1, -1, -1, false)
	if len(instructions) == 0 {
		t.Fatal("empty process tracker instructions")
	}
	if err := instructions.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
}

func TestProcessTrackerUIDUsesClassicNetworkByteOrder(t *testing.T) {
	instructions := processTrackerInstructions(1, 2, 3, false)
	var conversions int
	for _, instruction := range instructions {
		if instruction.OpCode == asm.BSwap(asm.R0, asm.Word).OpCode {
			t.Fatal("UID policy requires an ISA v4 unconditional swap")
		}
		if instruction.OpCode == asm.HostTo(asm.BE, asm.R0, asm.Word).OpCode && instruction.Constant == 32 {
			conversions++
		}
	}
	if conversions != 1 {
		t.Fatalf("UID network-order conversions = %d, want 1", conversions)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if err := instructions.Marshal(new(bytes.Buffer), order); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcessTrackerReleaseInstructions(t *testing.T) {
	for _, test := range []struct {
		name       string
		metadataFD int
		deletes    int
	}{
		{"owner_only", -1, 1},
		{"with_policy_metadata", 2, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			instructions := processTrackerReleaseInstructions(1, test.metadataFD)
			var cookies, deletes int
			for _, instruction := range instructions {
				if !instruction.IsBuiltinCall() {
					continue
				}
				switch asm.BuiltinFunc(instruction.Constant) {
				case asm.FnGetSocketCookie:
					cookies++
				case asm.FnMapDeleteElem:
					deletes++
				}
			}
			if cookies != 1 || deletes != test.deletes {
				t.Fatalf("release calls: cookies=%d deletes=%d, want 1/%d", cookies, deletes, test.deletes)
			}
			for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
				if err := instructions.Marshal(new(bytes.Buffer), order); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestProcessTrackerReleaseCleanupMode(t *testing.T) {
	if (*ProcessTracker)(nil).ReleaseCleanup() {
		t.Fatal("nil process tracker reports socket-release cleanup")
	}
	tracker := &ProcessTracker{releaseCleanup: true}
	if !tracker.ReleaseCleanup() {
		t.Fatal("process tracker did not report socket-release cleanup")
	}
}

func TestProcessTrackerPolicyMetadata(t *testing.T) {
	tests := []struct {
		name          string
		defaultBypass bool
		matched       bool
		expected      int32
	}{
		{"include match", true, true, socketMetadataPolicyIntercept},
		{"include miss", true, false, socketMetadataPolicyBypass},
		{"exclude match", false, true, socketMetadataPolicyBypass},
		{"exclude miss", false, false, socketMetadataPolicyIntercept},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := processTrackerPolicyMetadata(test.defaultBypass, test.matched); actual != test.expected {
				t.Fatalf("unexpected metadata: got=%d expected=%d", actual, test.expected)
			}
		})
	}
}

func TestCompileUIDDecisions(t *testing.T) {
	entries, defaultBypass, err := compileUIDDecisions([]UIDDecision{
		{Start: 1000, End: 1999, Action: DecisionIntercept},
	}, DecisionPass)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultBypass || len(entries) == 0 {
		t.Fatalf("include-style decisions compiled as defaultBypass=%v entries=%d", defaultBypass, len(entries))
	}
	entries, defaultBypass, err = compileUIDDecisions([]UIDDecision{
		{Start: 1000, End: 1999, Action: DecisionPass},
	}, DecisionIntercept)
	if err != nil {
		t.Fatal(err)
	}
	if defaultBypass || len(entries) == 0 {
		t.Fatalf("exclude-style decisions compiled as defaultBypass=%v entries=%d", defaultBypass, len(entries))
	}
	if _, _, err = compileUIDDecisions([]UIDDecision{{Start: 2, End: 1, Action: DecisionPass}}, DecisionIntercept); err == nil {
		t.Fatal("accepted an inverted UID range")
	}
}

func TestProcessTrackerCreateProgramSpec(t *testing.T) {
	spec := processTrackerCreateProgramSpec(1, -1, -1, false, true, true)
	if spec.Name != kernelProgramNameProcessCreate {
		t.Fatalf("program name = %q, want %q", spec.Name, kernelProgramNameProcessCreate)
	}
	if spec.Type != CiliumEBPF.CGroupSock {
		t.Fatalf("program type = %v, want CGroupSock", spec.Type)
	}
	if spec.AttachType != CiliumEBPF.AttachCGroupInetSockCreate {
		t.Fatalf("attach type = %v, want AttachCGroupInetSockCreate", spec.AttachType)
	}
	if spec.License != "GPL" {
		t.Fatalf("license = %q, want GPL", spec.License)
	}
	if len(spec.Instructions) == 0 {
		t.Fatal("socket-create program has no instructions")
	}
}

type processTrackerCreateGate struct {
	offset int16
	imm    int64
}

func TestProcessTrackerCreatePrologue(t *testing.T) {
	tests := []struct {
		name       string
		enableTCP  bool
		enableIPv6 bool
		gates      []processTrackerCreateGate
	}{
		{"every protocol", true, true, nil},
		{"ipv4 only", true, false, []processTrackerCreateGate{{bpfSockFamilyOffset, bpfSockFamilyINET6}}},
		{"udp only", false, true, []processTrackerCreateGate{{bpfSockProtocolOffset, bpfSockProtocolUDP}}},
		{"udp over ipv4 only", false, false, []processTrackerCreateGate{
			{bpfSockFamilyOffset, bpfSockFamilyINET6},
			{bpfSockProtocolOffset, bpfSockProtocolUDP},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prologue := processTrackerCreatePrologue(test.enableTCP, test.enableIPv6)
			if len(prologue) != 2*len(test.gates) {
				t.Fatalf("prologue has %d instructions, want %d", len(prologue), 2*len(test.gates))
			}
			for index, gate := range test.gates {
				load := prologue[2*index]
				jump := prologue[2*index+1]
				if load.Offset != gate.offset {
					t.Fatalf("gate %d reads offset %d, want %d", index, load.Offset, gate.offset)
				}
				if jump.Offset != -1 || jump.Constant != gate.imm || jump.Reference() != "allow" {
					t.Fatalf("gate %d jump: offset=%d imm=%d reference=%q, want imm=%d reference=allow",
						index, jump.Offset, jump.Constant, jump.Reference(), gate.imm)
				}
			}
		})
	}
}

func TestProcessTrackerCreateInstructions(t *testing.T) {
	baseBytes := marshalTrackerInstructions(t, processTrackerInstructions(1, -1, -1, false))
	tests := []struct {
		name       string
		enableTCP  bool
		enableIPv6 bool
		extraBytes int
	}{
		{"every protocol", true, true, 0},
		{"ipv4 only", true, false, 16},
		{"udp only", false, true, 16},
		{"udp over ipv4 only", false, false, 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			created := marshalTrackerInstructions(t,
				processTrackerCreateInstructions(1, -1, -1, false, test.enableTCP, test.enableIPv6))
			if len(created) != len(baseBytes)+test.extraBytes {
				t.Fatalf("create instructions encode %d bytes, want %d", len(created), len(baseBytes)+test.extraBytes)
			}
			if test.extraBytes == 0 && !bytes.Equal(created, baseBytes) {
				t.Fatal("create instructions differ from the legacy body when no gate applies")
			}
		})
	}
	// The UID policy variant defines its own "allow" label and must marshal
	// with the prologue referencing it.
	marshalTrackerInstructions(t, processTrackerCreateInstructions(1, 2, 3, true, false, false))
}

func marshalTrackerInstructions(t *testing.T, instructions asm.Instructions) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := instructions.Marshal(&buffer, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestProcessTrackerCreateHookDefault(t *testing.T) {
	if (*ProcessTracker)(nil).CreateHook() {
		t.Fatal("nil process tracker reports the socket-create hook")
	}
	if (&ProcessTracker{}).CreateHook() {
		t.Fatal("detached process tracker reports the socket-create hook")
	}
}
