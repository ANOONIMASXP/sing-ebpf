#!/usr/bin/env bash
set -euo pipefail

# vmtest boots a minimal guest without a network manager. Real socket tests
# require the same loopback setup that ordinary Linux distributions provide.
ip link set dev lo up
export SING_EBPF_INTEGRATION=1
export PATH="$PWD/.kernel-tests/bin:$PATH"

if [[ "$(uname -r)" == 5.4.* ]]; then
  # No sk_assign on upstream 5.4: require real compatibility-path loads/runs.
  .kernel-tests/core.test -test.v -test.run 'TestCompatibilityObjectsIntegration|TestCgroupProgramMatrixIntegration|TestCgroupUDPFlowCacheDoesNotOverrideUIDBypass|TestCgroupUDPRecoverySweepRemovesExpiredEntries|TestSharedPacketRewrite.*Integration|TestMapScanBudgetIntegration|TestRuntimeInspectionUsesOwnerIDs'
else
  result=0
  .kernel-tests/core.test -test.v || result=$?
  .kernel-tests/runtime.test -test.v || result=$?
  exit "$result"
fi
