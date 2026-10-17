#!/usr/bin/env bash
set -euo pipefail

# vmtest boots a minimal guest without a network manager. Real socket tests
# require the same loopback setup that ordinary Linux distributions provide.
ip link set dev lo up
export SING_EBPF_INTEGRATION=1
export PATH="$PWD/.kernel-tests/bin:$PATH"

# These controlled guests must execute selected positive and negative
# contracts. A skipped test or empty selection is not compatibility evidence.
run_required() {
  "$1" -test.v -test.run "$2" | tee .kernel-tests/required.log
  if grep -Eq '^[[:space:]]*--- SKIP:' .kernel-tests/required.log ||
      ! grep -q '^--- PASS:' .kernel-tests/required.log; then
    echo 'required kernel tests were skipped or did not execute' >&2
    return 1
  fi
}

case "$(uname -r)" in
  4.19.*)
    export SING_EBPF_KERNEL_PROFILE=legacy419
    run_required .kernel-tests/core.test '^(TestLegacy419CapabilitiesIntegration|TestSharedPacketRewrite.*Integration|TestMapScanBudgetIntegration)$'
    run_required .kernel-tests/runtime.test '^(TestCompatibilityCgroupTCPRoundTrip|TestSharedRewriteRoundTripIntegration|TestSharedRewriteUDPChecksumDeliveryIntegration)$'
    ;;
  5.4.*)
    run_required .kernel-tests/core.test '^(TestCompatibilityObjectsIntegration|TestCgroupProgramMatrixIntegration|TestCgroupUDPFlowCacheDoesNotOverrideUIDBypass|TestCgroupUDPRecoverySweep.*|TestSharedPacketRewrite.*Integration|TestMapScanBudgetIntegration|TestRuntimeInspectionUsesOwnerIDs)$'
    run_required .kernel-tests/runtime.test '^(TestCompatibilityCgroup(TCP|UDP)RoundTrip|TestSharedRewriteRoundTripIntegration|TestSharedRewriteUDPChecksumDeliveryIntegration|TestSharedRewriteClsactReplacementPreservesICMPEchoReplyFilter|TestICMPEchoSharedRewrite.*)$'
    ;;
  *)
    result=0
    .kernel-tests/core.test -test.v || result=$?
    .kernel-tests/runtime.test -test.v || result=$?
    exit "$result"
    ;;
esac
