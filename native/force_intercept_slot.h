// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_FORCE_INTERCEPT_SLOT_H
#define SING_EBPF_FORCE_INTERCEPT_SLOT_H

#include <linux/types.h>

// The interception data planes keep SB_EBPF_FORCE_INTERCEPT_SLOTS prefixes per
// address family, each enabled by its own control flag. A slot has the layout
// the controls used for their single prefix, so slot 0 keeps that ABI offset.
#define SB_EBPF_FORCE_INTERCEPT_SLOTS 2

struct sb_ebpf_force_intercept_slot {
    __u8 ipv4_prefix[4];
    __u8 ipv4_mask[4];
    __u8 ipv6_prefix[16];
    __u8 ipv6_mask[16];
};

_Static_assert(sizeof(struct sb_ebpf_force_intercept_slot) == 40U, "unexpected force-intercept slot ABI");

#endif
