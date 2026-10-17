//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"strings"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

// deliveryPairLeftBehind names the delivery veth ends still present, using the
// prefixes nextTCVethNames allocates from.
func deliveryPairLeftBehind(t *testing.T) []string {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("list the links in the namespace: %v", err)
	}
	var leftBehind []string
	for _, device := range links {
		name := device.Attrs().Name
		if strings.HasPrefix(name, "sbt") || strings.HasPrefix(name, "sbd") {
			leftBehind = append(leftBehind, name)
		}
	}
	return leftBehind
}

// TestCreateTCDeliveryLinkRemovesThePairWhenTheLookupFails covers the step
// between creating the delivery veth and having a handle on it.
//
// LinkAdd has already put the pair in the kernel by then. If the lookup that
// follows fails, the cleanup is the only thing that can remove it, and it can
// only remove what the delivery link holds — so the pair has to belong to the
// delivery link from the moment it exists rather than from the moment the
// lookup returns.
//
// The lookup is substituted; everything else is the real thing in a private
// network namespace.
func TestCreateTCDeliveryLinkRemovesThePairWhenTheLookupFails(t *testing.T) {
	enterTestNetworkNamespace(t)
	n, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("a fresh namespace already carries delivery links %v", leftBehind)
	}
	dataPlane := &tcDataPlane{
		backend:   &commonEBPF.TCBackend{},
		namespace: n,
		priority:  defaultTCPriority,
		hooks: &tcDataPlaneHooks{
			// Not a "not found" error: the pair was just created, so a lookup
			// failing here is the kernel refusing to answer, not the link
			// being absent.
			linkByName: func(string) (netlink.Link, error) { return nil, unix.ENOBUFS },
		},
	}

	delivery, err := dataPlane.createIsolatedTCDeliveryLink()
	if err == nil {
		t.Fatalf("a failed lookup was reported as success: %+v", delivery)
	}
	if !strings.Contains(err.Error(), "find TC eBPF redirect link") {
		t.Fatalf("error = %v, want the redirect lookup failure", err)
	}
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("the delivery pair %v was left behind with nothing owning it", leftBehind)
	}
}

// TestCreateTCDeliveryLinkRemovesThePairWhenAttachingFails covers the same
// property at return-filter attachment. An empty backend has no return program,
// so attaching fails before namespace configuration and must still remove veth.
func TestCreateTCDeliveryLinkRemovesThePairWhenAttachingFails(t *testing.T) {
	enterTestNetworkNamespace(t)
	n, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	dataPlane := &tcDataPlane{namespace: n, backend: &commonEBPF.TCBackend{}, priority: defaultTCPriority}

	delivery, err := dataPlane.createIsolatedTCDeliveryLink()
	if err == nil {
		t.Fatalf("attaching with no program loaded was reported as success: %+v", delivery)
	}
	if !strings.Contains(err.Error(), "TC eBPF program is unavailable") {
		t.Fatalf("error = %v, want the filter attach to be what failed", err)
	}
	if leftBehind := deliveryPairLeftBehind(t); len(leftBehind) != 0 {
		t.Fatalf("the delivery pair %v was left behind with nothing owning it", leftBehind)
	}
}
