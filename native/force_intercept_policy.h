// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_FORCE_INTERCEPT_POLICY_H
#define SING_EBPF_FORCE_INTERCEPT_POLICY_H

#include "force_intercept_slot.h"
#include "private_address.h"

// ForceIntercept destinations are mandatory interception targets. The caller supplies
// the data-plane-specific flag and normalized prefix from its control object.
static __attribute__((always_inline)) bool sb_ebpf_force_intercept_ipv4(
    const __u8 destination[4],
    __u32 flags,
    __u32 enabled_flag,
    const __u8 prefix[4],
    const __u8 mask[4]) {
    return (flags & enabled_flag) != 0U &&
        sb_ebpf_ipv4_prefix_match(destination, prefix, mask);
}

static __attribute__((always_inline)) bool sb_ebpf_force_intercept_ipv6(
    const __u8 destination[16],
    __u32 flags,
    __u32 enabled_flag,
    const __u8 prefix[16],
    const __u8 mask[16]) {
    return (flags & enabled_flag) != 0U &&
        sb_ebpf_prefix_match(destination, prefix, mask);
}

// A destination is force-intercepted when it matches any enabled slot.
static __attribute__((always_inline)) bool sb_ebpf_force_intercept_slots_ipv4(
    const __u8 destination[4],
    __u32 flags,
    __u32 slot0_flag,
    __u32 slot1_flag,
    const struct sb_ebpf_force_intercept_slot slots[SB_EBPF_FORCE_INTERCEPT_SLOTS]) {
    return sb_ebpf_force_intercept_ipv4(destination, flags, slot0_flag, slots[0].ipv4_prefix, slots[0].ipv4_mask) ||
        sb_ebpf_force_intercept_ipv4(destination, flags, slot1_flag, slots[1].ipv4_prefix, slots[1].ipv4_mask);
}

static __attribute__((always_inline)) bool sb_ebpf_force_intercept_slots_ipv6(
    const __u8 destination[16],
    __u32 flags,
    __u32 slot0_flag,
    __u32 slot1_flag,
    const struct sb_ebpf_force_intercept_slot slots[SB_EBPF_FORCE_INTERCEPT_SLOTS]) {
    return sb_ebpf_force_intercept_ipv6(destination, flags, slot0_flag, slots[0].ipv6_prefix, slots[0].ipv6_mask) ||
        sb_ebpf_force_intercept_ipv6(destination, flags, slot1_flag, slots[1].ipv6_prefix, slots[1].ipv6_mask);
}

#endif
