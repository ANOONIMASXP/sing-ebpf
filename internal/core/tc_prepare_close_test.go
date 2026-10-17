//go:build with_ebpf && (linux || android)

package core

import (
	"os"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// openFDCount includes every real BPF descriptor owned by this process.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open file descriptors: %v", err)
	}
	return len(entries)
}

func TestPrepareTCCleansUpWhenExternalSelfMapIsClosed(t *testing.T) {
	before := openFDCount(t)
	external, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 4, MaxEntries: 1024,
	})
	if err != nil {
		t.Skipf("cannot create the external map: %v", err)
	}
	// Close through the owner so its finalizer cannot later close an unrelated
	// descriptor that happens to reuse the same number.
	if err = external.Close(); err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 12345, EnableLocal: true, EnableIPv4: true, EnableTCP: true,
		SelfBypassMap: external,
	})
	if err == nil {
		_ = backend.Close()
		t.Fatal("closed external self-bypass map was accepted")
	}
	if after := openFDCount(t); after > before {
		t.Fatalf("failed PrepareTC leaked descriptors: before=%d after=%d", before, after)
	}
}
