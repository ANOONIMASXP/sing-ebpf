//go:build with_ebpf && (linux || android) && ebpf_integration

package core

import (
	"errors"
	"runtime"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestMapBatchIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test BPF map batch operations")
	for _, test := range []struct {
		name          string
		forceFallback bool
	}{
		{name: "kernel"},
		{name: "fallback", forceFallback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const maxEntries = 8
			mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
				Type:       CiliumEBPF.Hash,
				KeySize:    uint32(unsafe.Sizeof(uint32(0))),
				ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
				MaxEntries: maxEntries,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mapInstance.Close() })
			mapFD := mapInstance.FD()

			keys := []uint32{1, 2, 3, 4}
			values := []uint64{10, 20, 30, 40}
			var updateSupport mapBatchSupport
			var deleteSupport mapBatchSupport
			if test.forceFallback {
				updateSupport.mode.Store(mapBatchUnsupported)
				deleteSupport.mode.Store(mapBatchUnsupported)
			}
			processed, err := updateMapBatch(
				mapInstance,
				keys,
				values,
				0,
				&updateSupport,
			)
			runtime.KeepAlive(keys)
			runtime.KeepAlive(values)
			if err != nil || processed != uint32(len(keys)) {
				t.Fatalf("batch update: processed=%d err=%v", processed, err)
			}
			for index, key := range keys {
				var value uint64
				if err = lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
					t.Fatal(err)
				}
				if value != values[index] {
					t.Fatalf("unexpected value for key %d: %d", key, value)
				}
			}
			entries, err := countMapEntries(mapFD, unsafe.Sizeof(keys[0]), maxEntries)
			if err != nil {
				t.Fatal(err)
			}
			if entries != uint32(len(keys)) {
				t.Fatalf("unexpected map entry count: %d", entries)
			}
			processed, err = deleteMapBatch(
				mapInstance,
				keys,
				&deleteSupport,
			)
			runtime.KeepAlive(keys)
			if err != nil || processed != uint32(len(keys)) {
				t.Fatalf("batch delete: processed=%d err=%v", processed, err)
			}
			for _, key := range keys {
				var value uint64
				if err = lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); !errors.Is(err, unix.ENOENT) {
					t.Fatalf("deleted key %d remains: %v", key, err)
				}
			}
			entries, err = countMapEntries(mapFD, unsafe.Sizeof(keys[0]), maxEntries)
			if err != nil {
				t.Fatal(err)
			}
			if entries != 0 {
				t.Fatalf("unexpected map entry count after delete: %d", entries)
			}
		})
	}
}

func TestLRUFallbackBoundedIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test bounded LRU fallback")
	const maxEntries = 8
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mapInstance.Close() })
	for key := uint64(0); key < 256; key++ {
		value := key + 1
		if err = updateMap(mapInstance.FD(), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			t.Fatalf("update LRU fallback at key %d: %v", key, err)
		}
	}
	entries, err := countMapEntries(mapInstance.FD(), unsafe.Sizeof(uint64(0)), maxEntries)
	if err != nil {
		t.Fatal(err)
	}
	if entries != maxEntries {
		t.Fatalf("unexpected bounded LRU entry count: %d", entries)
	}
}

func TestMapScanBudgetIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test resumable map scans")
	for _, fallback := range []bool{false, true} {
		m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 512})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		for key := uint32(0); key < 300; key++ {
			if err = m.Put(key, key); err != nil {
				t.Fatal(err)
			}
		}
		var scratch mapScanScratch[uint32, uint32]
		if fallback {
			scratch.lookupSupport.mode.Store(mapBatchUnsupported)
		}
		visited := make(map[uint32]bool)
		complete := false
		for pass := 0; pass < 40; pass++ {
			result, err := scratch.scan(m, 512, 32, func(key, value uint32) {
				if key != value {
					t.Fatal("corrupt value")
				}
				visited[key] = true
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Scanned > 32 {
				t.Fatalf("budget exceeded: %+v", result)
			}
			if result.Complete {
				if result.Entries != 300 || len(visited) != 300 {
					t.Fatalf("incomplete scan: %+v, visited=%d", result, len(visited))
				}
				complete = true
				break
			}
		}
		if !complete {
			t.Fatal("scan never completed")
		}
	}
}
