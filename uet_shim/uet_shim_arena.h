/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * uet_shim_arena - allocation inside the shared regions.
 *
 * Why an allocator at all: the host and the guest map the same bytes at
 * different virtual addresses, so a pointer is meaningless across the
 * boundary and an OFFSET is the only portable currency. Something has to
 * hand out non-overlapping offsets, and that something is this.
 *
 * ABI 5 has TWO arenas, one per region, and each has exactly ONE allocator:
 *
 *   SHIM_REG_ARENA_H  the HOST owns the free list. Memory regions and
 *                     transmit staging live here.
 *   SHIM_REG_ARENA_G  the GUEST owns the free list. Receive landing zones
 *                     and reply payloads live here.
 *
 * Note that single-allocator is NOT single-writer. An MR's bytes are
 * written by the host when it seeds a registration and by the guest's stack
 * when an inbound RMA write lands - that is what an MR is for. What the
 * split buys is one free list per region with one owner: no cross-side
 * locking, no allocator metadata in shared memory, and a crashed peer that
 * can only corrupt the arena it owned.
 *
 * Every function takes the region it acts on. A side that does not own an
 * arena may still RESOLVE offsets in it; it just cannot allocate.
 *
 * shim_arena_ptr() is the one function BOTH sides call on BOTH arenas, and
 * it bounds-checks because neither side may trust an offset that arrived
 * over the wire.
 */
#ifndef UET_SHIM_ARENA_H
#define UET_SHIM_ARENA_H

#include <stdint.h>
#include <stddef.h>

/* Map every region the transport found and prepare the free list of the one
 * this side owns. The host owns ARENA_H, the guest owns ARENA_G.
 * Returns 0, or -ENODEV if a region is missing. */
int shim_arena_init(void);               /* host  */
int shim_arena_attach(void);             /* guest */

/*
 * Allocate in `reg`. Only the owner of that arena may call it. Returns a
 * TAGGED offset as carried in shim_hdr.off - region in the high bits, byte
 * offset in the low - or 0 on failure, so 0 is always available as "no
 * arena buffer".
 *
 * Tagging at birth rather than at the point a header is filled in means the
 * region travels with the value through every table and every struct, and
 * there is no site that can forget to apply it.
 *
 * Byte arithmetic on a tagged offset is safe and is relied on:
 * stage_iov() computes `off + cur` to address within a block. The offset
 * field is 61 bits and a region is a few hundred MiB, so a carry can never
 * reach the tag.
 */
uint64_t shim_arena_alloc(unsigned reg, size_t len);
void     shim_arena_free(uint64_t tagged_off);

/* Both sides, both arenas. Decodes the region from the tag, rejects one
 * that is out of range or names an unmapped region, then bounds-checks the
 * range. NULL for a tagged offset of 0, which means "no buffer" rather than
 * "bad offset" - callers must tell the two apart by their own error flag,
 * not by the pointer. This is the check that keeps an offset arriving over
 * the wire from becoming a wild pointer. */
void *shim_arena_ptr(uint64_t tagged_off, size_t len);

size_t shim_arena_avail(unsigned reg);   /* largest run, for diagnostics */
size_t shim_arena_size(unsigned reg);

#endif /* UET_SHIM_ARENA_H */
