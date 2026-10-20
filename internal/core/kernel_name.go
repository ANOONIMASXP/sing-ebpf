//go:build with_ebpf && (linux || android)

package core

// Linux exposes BPF object names through a 16-byte field including the
// terminating NUL, so kernel-visible program and map names may contain at
// most 15 bytes. Keep this limit in one place for both loaders.
const kernelObjectNameLimit = 15
