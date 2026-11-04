/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * uet_shim_arena - first-fit allocation inside the shared regions.
 *
 * See uet_shim_arena.h for why offsets rather than pointers, and why each
 * arena has exactly one allocator.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "uet_shim.h"
#include "uet_shim_arena.h"

/*
 * Bounds the metadata. Every live allocation needs one entry and each may
 * leave a free entry behind, so this caps concurrent allocations at ~4096 -
 * far above the few hundred a real workload reaches, and small enough to
 * stay cache-friendly.
 *
 * Carried per arena. Only the arena this side OWNS ever populates its
 * array, so one of the two is dead weight in each process - ~190 KiB,
 * which is not worth the conditional complexity of sharing one.
 */
#define ARENA_MAX_EXTENTS  8192

struct extent {
	uint64_t off;            /* from the arena base, never 0 */
	uint64_t len;
	int      used;
};

struct arena {
	char           *base;
	size_t          size;
	struct extent   ext[ARENA_MAX_EXTENTS];
	size_t          next;    /* extents in use */
	pthread_mutex_t lock;
	int             owned;   /* this side holds the free list */
};

static struct arena g_arena[SHIM_REG_MAX];

static uint64_t align_up(uint64_t v)
{
	return (v + (SHIM_ARENA_ALIGN - 1)) & ~((uint64_t)SHIM_ARENA_ALIGN - 1);
}

/* A region index that is in range AND has an arena. CTRL carries no arena,
 * so it is rejected here rather than at every call site. */
static struct arena *arena_of(unsigned reg)
{
	if ((reg != SHIM_REG_ARENA_H) && (reg != SHIM_REG_ARENA_G))
		return NULL;
	return &g_arena[reg];
}

static int arena_map_one(unsigned reg)
{
	struct arena *a = arena_of(reg);
	size_t len = 0;
	void *base;

	if (a == NULL)
		return -EINVAL;

	base = shim_xport_arena(reg, &len);
	if ((base == NULL) || (len <= SHIM_ARENA_ALIGN))
		return -ENODEV;

	a->base = base;
	a->size = len;
	pthread_mutex_init(&a->lock, NULL);
	return 0;
}

/*
 * One free extent covering everything except the first alignment unit.
 * Offset 0 is withheld permanently so that a tagged hdr.off of 0 can mean
 * "no arena buffer" without ambiguity - a sentinel is only safe if the
 * value it shadows can never occur.
 */
static void arena_own(unsigned reg)
{
	struct arena *a = &g_arena[reg];

	a->ext[0].off  = SHIM_ARENA_ALIGN;
	a->ext[0].len  = a->size - SHIM_ARENA_ALIGN;
	a->ext[0].used = 0;
	a->next  = 1;
	a->owned = 1;

	fprintf(stderr, "[shim/arena] %s: %zu bytes available (%zu MiB)\n",
		shim_region_name(reg), (size_t)a->ext[0].len,
		(size_t)(a->ext[0].len >> 20));
}

/* Both sides map BOTH arenas - resolving an offset in the arena the peer
 * owns is the normal case. They differ only in which free list they set up.
 */
static int arena_map_all(unsigned own)
{
	int rc = arena_map_one(SHIM_REG_ARENA_H);

	if (rc != 0)
		return rc;

	rc = arena_map_one(SHIM_REG_ARENA_G);
	if (rc != 0)
		return rc;

	arena_own(own);
	return 0;
}

int shim_arena_init(void)                /* host owns ARENA_H */
{
	return arena_map_all(SHIM_REG_ARENA_H);
}

int shim_arena_attach(void)              /* guest owns ARENA_G */
{
	return arena_map_all(SHIM_REG_ARENA_G);
}

size_t shim_arena_size(unsigned reg)
{
	struct arena *a = arena_of(reg);

	return (a != NULL) ? a->size : 0;
}

/* Raw (untagged) allocation; the public entry point tags the result. */
static uint64_t arena_alloc_raw(unsigned reg, size_t len)
{
	struct arena *a = arena_of(reg);
	uint64_t want;
	size_t i;

	if ((a == NULL) || (a->base == NULL) || !a->owned || (len == 0))
		return 0;

	want = align_up(len);

	pthread_mutex_lock(&a->lock);
	for (i = 0; i < a->next; i++) {
		struct extent *e = &a->ext[i];

		if (e->used || (e->len < want))
			continue;

		if (e->len == want) {             /* exact: just claim it */
			e->used = 1;
			pthread_mutex_unlock(&a->lock);
			return e->off;
		}

		if (a->next == ARENA_MAX_EXTENTS) {
			/* No room to record the remainder. Claiming the whole
			 * extent would silently waste it, so refuse instead -
			 * a visible -ENOMEM beats invisible drift. */
			break;
		}

		/* split: [want][remainder], keeping the array sorted */
		memmove(&a->ext[i + 1], &a->ext[i],
			(a->next - i) * sizeof(a->ext[0]));
		a->next++;
		a->ext[i].len      = want;
		a->ext[i].used     = 1;
		a->ext[i + 1].off  = e->off + want;
		a->ext[i + 1].len -= want;
		a->ext[i + 1].used = 0;

		pthread_mutex_unlock(&a->lock);
		return a->ext[i].off;
	}
	pthread_mutex_unlock(&a->lock);
	return 0;
}

uint64_t shim_arena_alloc(unsigned reg, size_t len)
{
	uint64_t off = arena_alloc_raw(reg, len);

	return (off == 0) ? 0 : SHIM_OFF(reg, off);
}

void shim_arena_free(uint64_t tagged_off)
{
	unsigned reg = SHIM_OFF_REG(tagged_off);
	uint64_t off = SHIM_OFF_VAL(tagged_off);
	struct arena *a = arena_of(reg);
	size_t i;

	if ((a == NULL) || (a->base == NULL) || !a->owned || (off == 0))
		return;

	pthread_mutex_lock(&a->lock);
	for (i = 0; i < a->next; i++) {
		if (a->ext[i].off != off)
			continue;
		if (!a->ext[i].used)
			break;                    /* double free: ignore */

		a->ext[i].used = 0;

		/* coalesce forward, then backward */
		if (((i + 1) < a->next) && !a->ext[i + 1].used) {
			a->ext[i].len += a->ext[i + 1].len;
			memmove(&a->ext[i + 1], &a->ext[i + 2],
				(a->next - i - 2) * sizeof(a->ext[0]));
			a->next--;
		}
		if ((i > 0) && !a->ext[i - 1].used) {
			a->ext[i - 1].len += a->ext[i].len;
			memmove(&a->ext[i], &a->ext[i + 1],
				(a->next - i - 1) * sizeof(a->ext[0]));
			a->next--;
		}
		break;
	}
	pthread_mutex_unlock(&a->lock);
}

void *shim_arena_ptr(uint64_t tagged_off, size_t len)
{
	unsigned reg;
	uint64_t off;
	struct arena *a;

	/* A tagged offset of 0 is the "no buffer" sentinel, not an error.
	 * Test the WHOLE word before decoding: region 0 is CTRL and has no
	 * arena, so the sentinel can never collide with a real block. */
	if (tagged_off == 0)
		return NULL;

	reg = SHIM_OFF_REG(tagged_off);
	off = SHIM_OFF_VAL(tagged_off);
	a   = arena_of(reg);

	/*
	 * Called with an offset that arrived over shared memory, so every
	 * term is checked: a region that exists and is mapped, inside that
	 * arena, non-zero, and off + len must not wrap. Skip any one of
	 * those and a corrupt or hostile offset becomes a wild pointer.
	 */
	if ((a == NULL) || (a->base == NULL) || (off == 0) || (off >= a->size))
		return NULL;
	if ((len > a->size) || ((off + len) > a->size))
		return NULL;

	return a->base + off;
}

size_t shim_arena_avail(unsigned reg)
{
	struct arena *a = arena_of(reg);
	size_t i, best = 0;

	if ((a == NULL) || !a->owned)
		return 0;

	pthread_mutex_lock(&a->lock);
	for (i = 0; i < a->next; i++) {
		if (!a->ext[i].used && (a->ext[i].len > best))
			best = a->ext[i].len;
	}
	pthread_mutex_unlock(&a->lock);
	return best;
}
