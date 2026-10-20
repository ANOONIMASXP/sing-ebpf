//go:build with_ebpf && linux && ebpf_integration

package core

import (
	CiliumEBPF "github.com/cilium/ebpf"
	"testing"
)

func TestRuntimeInspectionUsesOwnerIDs(t *testing.T) {
	requireEBPFIntegration(t, "inspect owner-specific resources")
	create := func() *CiliumEBPF.Map {
		m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Name: "sb_owner_test", Type: CiliumEBPF.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 8})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	owned, foreign := create(), create()
	if err := owned.Put(uint32(1), uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := foreign.Put(uint32(2), uint32(2)); err != nil {
		t.Fatal(err)
	}
	var resources RuntimeResources
	resources.add(nil, map[string]*CiliumEBPF.Map{"owned": owned})
	state := InspectRuntimeResources(resources, resources)
	if len(state.MapOccupancy.Maps) != 1 || state.MapOccupancy.Maps[0].Entries != 1 || state.MapOccupancy.Maps[0].ID != resources.Maps[0] {
		t.Fatalf("duplicate or foreign resource included: %+v", state)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	state = InspectRuntimeResources(resources)
	if len(state.MapOccupancy.Maps) != 1 || state.MapOccupancy.Maps[0].Pressure != "unavailable" || state.MapOccupancy.Status != "unknown" {
		t.Fatalf("closed owner reported healthy: %+v", state)
	}
}
