//go:build with_ebpf && (linux || android)

package runtime

import (
	"testing"

	"github.com/sagernet/netlink"
)

// TestTCSlotFilterIdentities covers what lets several runtimes share an
// interface: slot 0 keeps the single-instance identities, and no two slots,
// generations or roles share a filter name or handle on one parent.
func TestTCSlotFilterIdentities(t *testing.T) {
	for role := range tcFilterRoleCount {
		if got := tcSlotFilter(0, 0, role); got != tcLegacyFilterIdentities[role] {
			t.Errorf("slot 0 role %d = %+v, want the single-instance identity %+v", role, got, tcLegacyFilterIdentities[role])
		}
	}
	names := make(map[string]bool)
	handles := map[uint32]map[uint16]string{
		netlink.HANDLE_MIN_INGRESS: {tcDeliveryFilterHandle: "delivery"},
		netlink.HANDLE_MIN_EGRESS:  {},
	}
	for slot := range 16 {
		for generation := range tcFilterGenerations {
			for role := range tcFilterRoleCount {
				identity := tcSlotFilter(slot, generation, role)
				if _, used := names[identity.name]; used {
					t.Fatalf("slot %d generation %d role %d reuses name %q", slot, generation, role, identity.name)
				}
				names[identity.name] = true
				if previous, used := handles[identity.parent][identity.handle]; used {
					t.Fatalf("%s reuses handle %#x of %s", identity.name, identity.handle, previous)
				}
				handles[identity.parent][identity.handle] = identity.name
				if slot != 0 || generation != 0 {
					// Single-instance builds gave make-before-break filters handles
					// up to 0x6348; a slot handle must stay out of that range.
					if identity.handle <= 0x6348 {
						t.Fatalf("%s handle %#x overlaps handles of single-instance builds", identity.name, identity.handle)
					}
				}
				for other := range 16 {
					if got := tcSlotOwnsFilter(other, identity.name); got != (other == slot) {
						t.Fatalf("slot %d owns %q = %v", other, identity.name, got)
					}
				}
			}
		}
	}
	for _, name := range []string{"sbi1", "sbofff", "sbc2a"} {
		if !tcSlotOwnsFilter(0, name) || tcSlotOwnsFilter(1, name) {
			t.Errorf("a single-instance replacement filter %q is not owned by slot 0 alone", name)
		}
	}
	for _, name := range []string{"sbx1", "sbi", "sbi12345", "sbig", "cilium"} {
		if tcSlotOwnsFilter(0, name) {
			t.Errorf("slot 0 claims the unrelated filter %q", name)
		}
	}
}

// TestSharedTCInterfaceLockOutlivesEveryHolder covers a make-before-break
// replacement and the attachment it replaced holding one interface slot: the
// slot stays held until the last of them closes.
func TestSharedTCInterfaceLockOutlivesEveryHolder(t *testing.T) {
	slot, err := acquireTCInterfaceLock("shared", testTCInterfaceLockIndex+0x50)
	if err != nil {
		t.Fatal(err)
	}
	previous := newSharedTCInterfaceLock(slot)
	replacement := previous.share()
	if err = previous.Close(); err != nil {
		t.Fatal(err)
	}
	if err = previous.Close(); err != nil {
		t.Fatalf("a second close of one holder: %v", err)
	}
	if !tcLockHeld(t, testTCInterfaceLockIndex+0x50) {
		t.Fatal("the slot was released while the replacement still holds it")
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if tcLockHeld(t, testTCInterfaceLockIndex+0x50) {
		t.Fatal("the slot outlived its last holder")
	}
}

// TestReplacementGenerationAvoidsRetainedAttachments covers a replacement made
// while an earlier attachment of the same slot could not detach: it must not
// reuse that attachment's filter names and handles.
func TestReplacementGenerationAvoidsRetainedAttachments(t *testing.T) {
	retained := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 2, generation: 0,
		ingressFilter: &netlink.BpfFilter{}}
	otherSlot := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 3, generation: 2,
		ingressFilter: &netlink.BpfFilter{}}
	dataPlane := &sharedRewriteDataPlane{retiredAttachments: []*sharedRewriteAttachment{retained, otherSlot}}
	previous := &sharedRewriteAttachment{interfaceName: "wlan0", interfaceIndex: 7, slot: 2, generation: 1}
	generation, err := dataPlane.replacementGenerationLocked(previous)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 2 {
		t.Fatalf("replacement generation = %d, want 2 (0 is retained, 1 is being replaced)", generation)
	}
	for used := range tcFilterGenerations {
		dataPlane.retiredAttachments = append(dataPlane.retiredAttachments, &sharedRewriteAttachment{
			interfaceIndex: 7, slot: 2, generation: used, ingressFilter: &netlink.BpfFilter{},
		})
	}
	if _, err = dataPlane.replacementGenerationLocked(previous); err == nil {
		t.Fatal("a generation was handed out although every one is held")
	}
}
