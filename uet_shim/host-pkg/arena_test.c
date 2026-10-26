/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * CHECKPOINT 3: the arena allocator, on its own.
 *
 * Links uet_shim_arena.o and a four-line stub of the transport, so it needs
 * no shared memory, no QEMU and no UET stack. Everything downstream - memory
 * regions, every transfer - addresses the arena by offset, so a fault here
 * would surface as corrupted payloads or allocation failures after minutes of
 * healthy traffic. Cheaper to find it in a second.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uet_shim.h"
#include "uet_shim_arena.h"

#define FAKE_SIZE (1u << 20)
static char fake[FAKE_SIZE];

/* stands in for uet_shim_xport_shm.c */
void *shim_xport_arena(size_t *len)
{
	if (len != NULL)
		*len = FAKE_SIZE;
	return fake;
}

static int fails;

#define CHECK(cond, ...) do {                                           \
	if (cond) {                                                     \
		printf("  ok    ");                                     \
	} else {                                                        \
		printf("  FAIL  ");                                     \
		fails++;                                                \
	}                                                               \
	printf(__VA_ARGS__);                                            \
	printf("\n");                                                   \
} while (0)

int main(void)
{
	uint64_t a, b, c, big;
	uint64_t many[64];
	int i;

	printf("=== CHECKPOINT 3: arena allocator ===\n");

	CHECK(shim_arena_init() == 0, "init");
	CHECK(shim_arena_size() == FAKE_SIZE, "size reported as given");

	/* --- offset 0 must never be handed out: hdr.off == 0 means "none" */
	a = shim_arena_alloc(100);
	CHECK(a >= SHIM_ARENA_ALIGN, "first alloc skips offset 0 (got %lu)",
	      (unsigned long)a);

	/* --- alignment, so two live blocks cannot share a cache line */
	b = shim_arena_alloc(1);
	c = shim_arena_alloc(4096);
	CHECK((a % SHIM_ARENA_ALIGN) == 0 && (b % SHIM_ARENA_ALIGN) == 0 &&
	      (c % SHIM_ARENA_ALIGN) == 0, "all offsets %u-aligned",
	      SHIM_ARENA_ALIGN);

	/* --- no overlap: the whole point */
	CHECK((a + 128) <= b && (b + 64) <= c, "blocks do not overlap "
	      "(%lu, %lu, %lu)", (unsigned long)a, (unsigned long)b,
	      (unsigned long)c);

	/* --- resolution, and the bounds checks the guest depends on */
	CHECK(shim_arena_ptr(a, 100) == (fake + a), "ptr resolves");
	CHECK(shim_arena_ptr(0, 1) == NULL, "offset 0 rejected");
	CHECK(shim_arena_ptr(FAKE_SIZE, 1) == NULL, "offset past end rejected");
	CHECK(shim_arena_ptr(FAKE_SIZE - 10, 100) == NULL,
	      "range crossing the end rejected");
	CHECK(shim_arena_ptr(64, (size_t)-1) == NULL,
	      "wrapping length rejected");

	/* --- reuse: a freed block must come back */
	shim_arena_free(b);
	CHECK(shim_arena_alloc(1) == b, "freed block is reused");
	shim_arena_free(b);

	/* --- coalescing, the one that matters.
	 * Allocate the arena away in 64 pieces, free them in an interleaved
	 * order, then ask for a run only an empty arena can satisfy. Without
	 * coalescing this fails and a long run would die of fragmentation. */
	shim_arena_free(a);
	shim_arena_free(c);
	for (i = 0; i < 64; i++)
		many[i] = shim_arena_alloc(8192);
	CHECK(many[63] != 0, "64 x 8 KiB all allocated");

	for (i = 0; i < 64; i += 2)          /* evens first... */
		shim_arena_free(many[i]);
	for (i = 1; i < 64; i += 2)          /* ...then odds   */
		shim_arena_free(many[i]);

	big = shim_arena_alloc(FAKE_SIZE - SHIM_ARENA_ALIGN);
	CHECK(big != 0, "whole arena allocatable again -> extents coalesced");
	shim_arena_free(big);

	/* --- exhaustion is reported, not faked */
	CHECK(shim_arena_alloc(FAKE_SIZE * 2) == 0,
	      "oversized request refused");
	CHECK(shim_arena_alloc(0) == 0, "zero-length request refused");

	big = shim_arena_alloc(FAKE_SIZE - SHIM_ARENA_ALIGN);
	CHECK(shim_arena_alloc(64) == 0, "full arena refuses further allocs");
	shim_arena_free(big);
	CHECK(shim_arena_alloc(64) != 0, "and recovers after a free");

	/* --- a double free must not corrupt the list */
	a = shim_arena_alloc(256);
	shim_arena_free(a);
	shim_arena_free(a);
	CHECK(shim_arena_alloc(256) == a, "double free tolerated");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "all passed",
	       fails, (fails == 1) ? "" : "s");
	return fails ? 1 : 0;
}
