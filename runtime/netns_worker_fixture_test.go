//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"os"
	goRuntime "runtime"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func setLoopbackUp(t *testing.T) {
	t.Helper()
	if err := setLinkUpByName("lo"); err != nil {
		t.Fatalf("bring up lo: %v", err)
	}
}

func setLinkUpByName(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func addTestAddress(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	address, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrAdd(link, address); err != nil {
		t.Fatalf("add %s to %s: %v", cidr, link.Attrs().Name, err)
	}
}

// testNetworkNamespaceWorker runs functions on an OS thread that lives in its
// own network namespace. The thread is never unlocked, so it exits with the
// worker instead of returning to the scheduler in the wrong namespace.
type testNetworkNamespaceWorker struct {
	namespace *os.File
	requests  chan func()
}

func startTestNetworkNamespaceWorker(t *testing.T) *testNetworkNamespaceWorker {
	t.Helper()
	worker := &testNetworkNamespaceWorker{requests: make(chan func())}
	ready := make(chan error, 1)
	go func() {
		goRuntime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- err
			return
		}
		namespace, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			ready <- err
			return
		}
		worker.namespace = namespace
		ready <- nil
		for request := range worker.requests {
			request()
		}
	}()
	if err := <-ready; err != nil {
		t.Skipf("cannot create a client network namespace: %v", err)
	}
	t.Cleanup(func() {
		close(worker.requests)
		_ = worker.namespace.Close()
	})
	return worker
}

func (w *testNetworkNamespaceWorker) run(t *testing.T, request func() error) {
	t.Helper()
	done := make(chan error, 1)
	w.requests <- func() { done <- request() }
	if err := <-done; err != nil {
		t.Fatalf("client namespace: %v", err)
	}
}
