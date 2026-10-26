/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * First-fit allocator over the shared region's arena. See uet_shim_arena.h
 * for why it is host-private.
 *
 * The free list is an array of extents kept sorted by offset, with used and
 * free runs interleaved. First fit, split on allocate, coalesce with both
 * neighbours on free. Not a general-purpose malloc: the expected population
 * is a few dozen memory regions plus a few hundred in-flight transfers, and
 * at that scale a linear scan over a contiguous array beats a tree - it is
 * one or two cache lines and no pointer chasing.
 *
 * The one property worth insisting on: coalescing. Without it, a long NCCL
 * run that allocates and frees per-message blocks would fragment the arena
 * into unusable slivers and start failing allocations after minutes of
 * apparently healthy traffic - a failure that looks like a leak and is not.
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
 * far above the few hundred a real workload reaches, and small enough
 * (128 KiB) to stay cache-friendly.
 */
#define ARENA_MAX_EXTENTS  8192

struct extent {
	uint64_t off;            /* from the arena base, never 0 */
	uint64_t len;
	int      used;
};

static char           *g_base;
static size_t          g_size;
static struct extent   g_ext[ARENA_MAX_EXTENTS];
static size_t          g_next;          /* extents in use */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_is_host;

static uint64_t align_up(uint64_t v)
{
	return (v + (SHIM_ARENA_ALIGN - 1)) & ~((uint64_t)SHIM_ARENA_ALIGN - 1);
}

static int arena_map(void)
{
	size_t len = 0;
	void *base = shim_xport_arena(&len);

	if ((base == NULL) || (len <= SHIM_ARENA_ALIGN))
		return -ENODEV;

	g_base = base;
	g_size = len;
	return 0;
}

int shim_arena_attach(void)
{
	int rc = arena_map();

	g_is_host = 0;
	return rc;
}

int shim_arena_init(void)
{
	int rc = arena_map();

	if (rc != 0)
		return rc;

	/*
	 * One free extent covering everything except the first alignment
	 * unit. Offset 0 is withheld permanently so that hdr.off == 0 can
	 * mean "no arena buffer" without ambiguity - a sentinel is only
	 * safe if the value it shadows can never occur.
	 */
	g_ext[0].off  = SHIM_ARENA_ALIGN;
	g_ext[0].len  = g_size - SHIM_ARENA_ALIGN;
	g_ext[0].used = 0;
	g_next = 1;
	g_is_host = 1;

	fprintf(stderr, "[shim/arena] %zu bytes available (%zu MiB)\n",
		(size_t)g_ext[0].len, (size_t)(g_ext[0].len >> 20));
	return 0;
}

size_t shim_arena_size(void)
{
	return g_size;
}

uint64_t shim_arena_alloc(size_t len)
{
	uint64_t want;
	size_t i;

	if ((g_base == NULL) || !g_is_host || (len == 0))
		return 0;

	want = align_up(len);

	pthread_mutex_lock(&g_lock);
	for (i = 0; i < g_next; i++) {
		struct extent *e = &g_ext[i];

		if (e->used || (e->len < want))
			continue;

		if (e->len == want) {             /* exact: just claim it */
			e->used = 1;
			pthread_mutex_unlock(&g_lock);
			return e->off;
		}

		if (g_next == ARENA_MAX_EXTENTS) {
			/* No room to record the remainder. Claiming the whole
			 * extent would silently waste it, so refuse instead -
			 * a visible -ENOMEM beats invisible drift. */
			break;
		}

		/* split: [want][remainder], keeping the array sorted */
		memmove(&g_ext[i + 1], &g_ext[i],
			(g_next - i) * sizeof(g_ext[0]));
		g_next++;
		g_ext[i].len      = want;
		g_ext[i].used     = 1;
		g_ext[i + 1].off  = e->off + want;
		g_ext[i + 1].len -= want;
		g_ext[i + 1].used = 0;

		pthread_mutex_unlock(&g_lock);
		return g_ext[i].off;
	}
	pthread_mutex_unlock(&g_lock);
	return 0;
}

void shim_arena_free(uint64_t off)
{
	size_t i;

	if ((g_base == NULL) || !g_is_host || (off == 0))
		return;

	pthread_mutex_lock(&g_lock);
	for (i = 0; i < g_next; i++) {
		if (g_ext[i].off != off)
			continue;
		if (!g_ext[i].used)
			break;                    /* double free: ignore */

		g_ext[i].used = 0;

		/* coalesce forward, then backward */
		if (((i + 1) < g_next) && !g_ext[i + 1].used) {
			g_ext[i].len += g_ext[i + 1].len;
			memmove(&g_ext[i + 1], &g_ext[i + 2],
				(g_next - i - 2) * sizeof(g_ext[0]));
			g_next--;
		}
		if ((i > 0) && !g_ext[i - 1].used) {
			g_ext[i - 1].len += g_ext[i].len;
			memmove(&g_ext[i], &g_ext[i + 1],
				(g_next - i - 1) * sizeof(g_ext[0]));
			g_next--;
		}
		break;
	}
	pthread_mutex_unlock(&g_lock);
}

void *shim_arena_ptr(uint64_t off, size_t len)
{
	/*
	 * The guest calls this with an offset that arrived over shared
	 * memory, so every term is checked: inside the arena, non-zero, and
	 * off + len must not wrap. Skip any one of those and a corrupt or
	 * malicious offset becomes a write through a wild pointer.
	 */
	if ((g_base == NULL) || (off == 0) || (off >= g_size))
		return NULL;
	if ((len > g_size) || ((off + len) > g_size))
		return NULL;

	return g_base + off;
}

size_t shim_arena_avail(void)
{
	size_t i, best = 0;

	if (!g_is_host)
		return 0;

	pthread_mutex_lock(&g_lock);
	for (i = 0; i < g_next; i++) {
		if (!g_ext[i].used && (g_ext[i].len > best))
			best = g_ext[i].len;
	}
	pthread_mutex_unlock(&g_lock);
	return best;
}
