// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_FORCE_INTERCEPT_POLICY_H
#define SING_EBPF_FORCE_INTERCEPT_POLICY_H

#include "bpf_compat.h"
#include <linux/bpf.h>

struct sb_force4_key { __u32 prefixlen; __u8 address[4]; };
struct sb_force6_key { __u32 prefixlen; __u8 address[16]; };

// Immutable scoped sets; sized by the loader, without entry preallocation.
#define SB_FORCE_MAPS(name) \
    struct bpf_map_def SEC("maps") name##_force4 = { \
        .type = BPF_MAP_TYPE_LPM_TRIE, .key_size = sizeof(struct sb_force4_key), \
        .value_size = 1U, .max_entries = 1U, .map_flags = BPF_F_NO_PREALLOC, \
    }; \
    struct bpf_map_def SEC("maps") name##_force6 = { \
        .type = BPF_MAP_TYPE_LPM_TRIE, .key_size = sizeof(struct sb_force6_key), \
        .value_size = 1U, .max_entries = 1U, .map_flags = BPF_F_NO_PREALLOC, \
    }

#define SB_FORCE_LOOKUP(name) \
    INLINE bool name##_force_ipv4(const __u8 address[4]) { \
        struct sb_force4_key key = {.prefixlen = 32U}; \
        __builtin_memcpy(key.address, address, 4U); \
        return map_lookup(&name##_force4, &key) != 0; \
    } \
    INLINE bool name##_force_ipv6(const __u8 address[16]) { \
        struct sb_force6_key key = {.prefixlen = 128U}; \
        __builtin_memcpy(key.address, address, 16U); \
        return map_lookup(&name##_force6, &key) != 0; \
    }

#define SB_PORT_PASS 1U
#define SB_PORT_INTERCEPT 2U
#define SB_PORT_AFTER_SELECTORS 4U

#endif
