//go:build with_ebpf && linux && ebpf_integration

package core

import "testing"

func TestTCPListenerDirectFallbackIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify listener fallback before program exposure")
	for _, isolated := range []bool{false, true} {
		policy, err := CompileActionPolicy(ActionPolicy{EnableTCP: true, EnableUDP: true,
			Local: ActionScope{Default: DecisionIntercept}, Shared: ActionScope{Default: DecisionIntercept}})
		if err != nil {
			t.Fatal(err)
		}
		backend, err := PrepareTC(TCConfig{Isolated: isolated, ListenerPort: 65530, EnableLocal: true,
			EnableShared: true, EnableIPv4: true, EnableTCP: true, EnableUDP: true, Policy: policy, AssignmentCapacity: 32})
		if err != nil {
			t.Fatal(err)
		}
		old := backend.runtime.programs[tcProgramDeliveryIngress]
		backend.access.Lock()
		err = backend.useDirectTCPListenersLocked()
		backend.access.Unlock()
		if err != nil {
			backend.Close()
			t.Fatal(err)
		}
		if backend.TCPListenerLookupMode() != "direct" || old.FD() != -1 || backend.DeliveryIngressProgramFD() < 0 {
			t.Fatal("fallback did not replace/close the old delivery program")
		}
		backend.access.Lock()
		err = backend.useDirectTCPListenersLocked()
		backend.access.Unlock()
		if err == nil {
			t.Fatal("fallback replaced an exposed program")
		}
		if err = backend.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTCIsolatedVerifierIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load tuple-preserving namespace TC programs")
	for _, legacy := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, process := range []bool{false, true} {
				policy, err := CompileActionPolicy(ActionPolicy{EnableTCP: tcp, EnableUDP: true,
					Local: ActionScope{Default: DecisionIntercept}, Shared: ActionScope{Default: DecisionIntercept}})
				if err != nil {
					t.Fatal(err)
				}
				backend, err := prepareTC(TCConfig{Isolated: true, ListenerPort: 65530, EnableLocal: true, EnableShared: true,
					EnableIPv4: true, EnableLocalIPv6: true, EnableSharedIPv6: true, EnableTCP: tcp, EnableUDP: true,
					Policy: policy, TrackProcess: process, AssignmentCapacity: 32}, legacy)
				if err != nil {
					t.Fatalf("legacy=%v tcp=%v process=%v: %+v", legacy, tcp, process, err)
				}
				if backend.DeliveryIngressProgramFD() < 0 || backend.IsolatedReturnProgramFD() < 0 {
					t.Fatal("missing isolation programs")
				}
				if err = backend.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
