/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * uet_shim_arena - allocation inside the shared region.
 *
 * Why an allocator at all: the host and the guest map the same bytes at
 * different virtual addresses, so a pointer is meaningless across the
 * boundary and an OFFSET is the only portable currency. Something has to
 * hand out non-overlapping offsets, and that something is this.
 *
 * The allocator is HOST-PRIVATE on purpose. Only the host allocates - it is
 * the side that knows what the application asked for - and the guest merely
 * turns an offset into its own pointer. So there is no allocator metadata in
 * shared memory, no cross-side locking, and nothing for a crashed peer to
 * corrupt. A host restart resets the allocator, which is correct: every
 * registration and transfer from the old session died with it.
 *
 * shim_arena_ptr() is the one function BOTH sides call, and it bounds-checks
 * because the guest must never trust an offset that arrived over the wire.
 */
#ifndef UET_SHIM_ARENA_H
#define UET_SHIM_ARENA_H

#include <stdint.h>
#include <stddef.h>

/* Host: take the region from the transport and prepare the free list.
 * Returns 0, or -ENODEV if this transport has no shared region. */
int shim_arena_init(void);

/* Guest: the same, minus the free list - resolution only. */
int shim_arena_attach(void);

/* Host only. Returns an offset >= SHIM_ARENA_ALIGN, or 0 on failure, so 0
 * is always available as "no arena buffer". */
uint64_t shim_arena_alloc(size_t len);
void     shim_arena_free(uint64_t off);

/* Both sides. NULL if the range escapes the arena, which is the check that
 * keeps a bad or hostile offset from turning into a wild pointer. */
void *shim_arena_ptr(uint64_t off, size_t len);

size_t shim_arena_avail(void);   /* largest allocatable run, for diagnostics */
size_t shim_arena_size(void);

#endif /* UET_SHIM_ARENA_H */
