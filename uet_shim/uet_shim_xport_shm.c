/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * Shared-memory transport for the shim.
 *
 * ABI 5 uses THREE regions, each a separate backing file and a separate
 * ivshmem BAR:
 *
 *   uet_ctrl    mailboxes and handshake. Small, hot, both CPUs on it.
 *   uet_dp_h2g  the arena the HOST allocates from: MRs and tx staging.
 *   uet_dp_g2h  the arena the GUEST allocates from: rx landing zones.
 *
 *   host  : mmap each by path
 *   guest : mmap BAR2 of each unclaimed ivshmem device (1af4:1110)
 *   QEMU  : -object memory-backend-file,id=ctrl,mem-path=/dev/shm/uet_ctrl,\
 *                   size=2M,share=on
 *           -device ivshmem-plain,memdev=ctrl           (repeat per region)
 *
 * Both sides end up on the same PHYSICAL pages, so after mmap() there is no
 * kernel and no QEMU in the path: every exchange is loads and stores.
 * ivshmem BAR2 is registered as a RAM MemoryRegion, so KVM installs it in
 * the guest's second-level page tables and accesses never trap.
 *
 * Measured: 0.37-0.49 us round trip, against 30-75 us for vsock, which
 * crosses the kernel twice per message.
 *
 * WHO NAMES A REGION. The host opens the three files BY PATH, so it alone
 * knows which is which; the guest sees three anonymous BARs whose PCI order
 * shifts with machine type and with the order of -device arguments. So the
 * host STAMPS each region with its magic and the guest DISCOVERS them by
 * reading it. That inverts ABI 4, where the guest claimed the single
 * region, and it means either side may now start first.
 *
 * The channel is still a pair of single-slot MAILBOXES, not rings. That is
 * sufficient because shim_rpc() holds a mutex for the whole request and
 * keeps exactly one operation outstanding. Rings only pay off once the data
 * path goes asynchronous.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <glob.h>
#include <time.h>
#include <sys/mman.h>

#include "uet_shim.h"

/*
 * Each must match QEMU's size= exactly, and each must be a power of two
 * because pci_register_bar() asserts it.
 *
 * CTRL is small: it holds two mailboxes and nothing else. The arenas hold
 * every live memory region plus every in-flight transfer. 128 MiB and not
 * more because the guest firmware has to assign each as a prefetchable BAR
 * out of its PCI window, and with three of them a larger size can fail
 * assignment depending on machine type - a failure that costs a VM restart
 * to diagnose. Raising one later is this constant plus QEMU's size=; check
 * the result with "lspci -v -d 1af4:1110" and look for [size=...].
 */
#define SHM_CTRL_SIZE      (2u << 20)
#define SHM_ARENA_SIZE     (128u << 20)

/*
 * Where an arena region's usable bytes begin. 2 MiB, not
 * sizeof(struct shm_region_hdr), so a transparent hugepage can back the
 * arena and so the header can grow later without moving a single arena
 * byte.
 */
#define SHM_ARENA_OFF      (2u << 20)

/*
 * Ring depth and slot size. 256 entries against today's ONE outstanding
 * operation, and comfortably more than any endpoint's tx_attr->size that
 * this rig uses - the descriptor pool, not the ring, should be what
 * backpressures.
 *
 * A 2 KiB slot holds the 80-byte header plus the largest control payload
 * in use (struct shim_fi_info, 1072). 256 x 2 KiB = 512 KiB per ring, so
 * the pair plus the handshake stays near 1 MiB and still fits CTRL.
 */
#define SHM_RING_ENTRIES   256u
#define SHM_RING_MASK      (SHM_RING_ENTRIES - 1u)

#define SHM_PATH_PREFIX    "/dev/shm/uet"       /* UET_SHIM_SHM overrides */
#define SHM_PSEUDO_FD      1000               /* not a real descriptor: the
					       * interface is fd-shaped from
					       * its vsock origin            */

/* Busy for this many iterations - the hot path - then nap, so an idle guest
 * does not burn a core while waiting hours for work. */
#define SHM_SPIN_BUDGET    20000
#define SHM_IDLE_NS        50000              /* 50 us */

/*
 * Bound every wait. magic and guest_up PERSIST in the region after a peer
 * dies - these are files, and nothing zeroes them on exit - so a wait that
 * cannot time out is a wait that hangs forever on a stale flag.
 */
#define SHM_TIMEOUT_DEFAULT 30

/*
 * Without this pair, the compiler or CPU may make the doorbell visible
 * BEFORE the payload, and the reader sees a fresh seq with stale bytes - a
 * bug that only appears under load and is miserable to find. On x86 these
 * emit no extra instructions; they constrain reordering.
 */
#define pub(p, v)   __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define obs(p)      __atomic_load_n((p), __ATOMIC_ACQUIRE)

/*
 * One RING per direction, so each has exactly ONE producer and ONE
 * consumer. That is what removes the need for locking - only ordering
 * remains.
 *
 * ABI 5 had a single-slot mailbox per direction, which was correct only
 * because shim_rpc() held a mutex across the whole request and kept one
 * operation outstanding. A ring lets the host queue many before the guest
 * has answered any, and lets the guest reap a BATCH: one acquire and one
 * release for N messages instead of two per message.
 *
 * head and tail are free-running uint32 counters, masked to index. Wrap
 * after four billion messages is a non-event because every comparison is
 * != or an unsigned difference, never >. They sit on SEPARATE CACHE LINES:
 * the producer writes head constantly and the consumer writes tail
 * constantly, and sharing a line would ping-pong it between cores on every
 * message - more expensive than the payload copy it announces.
 */
struct shm_slot {
	uint32_t len;                         /* payload bytes after hdr */
	uint32_t _pad[3];                     /* 8-align the header      */
	struct shim_hdr hdr;
	uint8_t  data[SHIM_MAX_PAYLOAD];
};

struct shm_ring {
	uint32_t head;                        /* PRODUCER writes          */
	uint8_t  _p0[60];                     /* head owns its line       */
	uint32_t tail;                        /* CONSUMER writes          */
	uint8_t  _p1[60];                     /* tail owns its line       */
	struct shm_slot slot[SHM_RING_ENTRIES];
};

/*
 * The CTRL region. Its region header is the first member rather than a
 * separate block, so the rings begin at a fixed offset the assertions
 * below pin.
 */
struct shm_chan {
	struct shm_region_hdr rh;  /* 24 B: magic, abi, session, bytes */
	uint32_t host_up;          /* container attached               */
	uint32_t guest_up;         /* guest armed for this session     */
	uint32_t _pad[8];          /* pad the control block to 64      */

	struct shm_ring h2g;     /* host  -> guest */
	struct shm_ring g2h;     /* guest -> host  */
};

/*
 * The LAYOUT is the contract: no address is ever negotiated or sent. Both
 * sides mmap at whatever base the kernel gives them and reach every field
 * by compile-time offset, so the two must agree exactly.
 *
 * These assertions pin the offsets. Change a field and the BUILD fails on
 * both sides, rather than one side silently reading the wrong bytes - a
 * fault that looks like data corruption, not a mismatch. If you intend a
 * layout change, update these numbers AND bump SHIM_ABI_VERSION so a
 * half-deployed pair refuses to connect.
 */
_Static_assert(sizeof(struct shim_hdr) == 80, "shim_hdr layout changed");
_Static_assert(offsetof(struct shim_hdr, op) == 4, "hdr.op moved");
_Static_assert(offsetof(struct shim_hdr, payload_len) == 8, "hdr.len moved");
_Static_assert(offsetof(struct shim_hdr, seq) == 12, "hdr.seq moved");

_Static_assert(sizeof(struct shm_region_hdr) == 24, "region hdr changed");
_Static_assert(offsetof(struct shm_region_hdr, magic) == 0, "magic moved");

_Static_assert(sizeof(struct shm_slot) == 2048, "slot is no longer 2 KiB");
_Static_assert(offsetof(struct shm_slot, hdr) == 16, "slot.hdr moved");
_Static_assert(offsetof(struct shm_slot, data) == 96, "slot.data moved");

_Static_assert(offsetof(struct shm_ring, head) == 0, "ring.head moved");
_Static_assert(offsetof(struct shm_ring, tail) == 64, "head and tail share a line");
_Static_assert(offsetof(struct shm_ring, slot) == 128, "ring.slot moved");

_Static_assert(offsetof(struct shm_chan, h2g) == 64, "h2g moved");
_Static_assert(sizeof(struct shm_chan) <= SHM_CTRL_SIZE,
	       "the rings do not fit their region");
_Static_assert(SHM_ARENA_OFF < SHM_ARENA_SIZE,
	       "no room left for an arena");
_Static_assert((SHM_RING_ENTRIES & SHM_RING_MASK) == 0,
	       "ring depth must be a power of two for the mask to index");

/* A performance property, asserted: put head and tail within a cache line
 * of each other and the build refuses, because the false sharing would be
 * invisible and cost more than the copy. */
_Static_assert(offsetof(struct shm_ring, tail)
	       - offsetof(struct shm_ring, head) >= 64,
	       "head and tail could false-share");

/* Every mapped region. Indexed by enum shim_region, so a tag that arrived
 * over the wire indexes this directly once bounds-checked. */
struct shm_region {
	void    *base;
	size_t   size;
};

static struct shm_region g_reg[SHIM_REG_MAX];
static struct shm_chan  *g_chan;              /* == g_reg[CTRL].base */
static int      g_is_host;
static uint64_t g_session;                    /* latched at handshake */
/*
 * Private cursors, in THIS side's own memory, never in the region.
 *
 * g_tx_cached_tail is what we last saw of the consumer's tail; the
 * producer re-reads the shared tail only when the ring looks full, so the
 * common path never touches the consumer's cache line.
 *
 * g_rx_cached_head is the same trick on the other side.
 */
static uint32_t g_tx_cached_tail;
static uint32_t g_rx_cached_head;

static const struct {
	const char *name;
	const char *suffix;
	uint32_t    magic;
	size_t      size;
} g_rdesc[SHIM_REG_MAX] = {
	[SHIM_REG_CTRL]    = { "ctrl",    "_ctrl",
			       SHIM_MAGIC_CTRL,    SHM_CTRL_SIZE  },
	[SHIM_REG_ARENA_H] = { "arena_h", "_dp_h2g",
			       SHIM_MAGIC_ARENA_H, SHM_ARENA_SIZE },
	[SHIM_REG_ARENA_G] = { "arena_g", "_dp_g2h",
			       SHIM_MAGIC_ARENA_G, SHM_ARENA_SIZE },
};

const char *shim_region_name(unsigned reg)
{
	return (reg < SHIM_REG_MAX) ? g_rdesc[reg].name : "?";
}

/* How many messages a ring holds. The host needs it to size its own
 * credit accounting, so it is published rather than duplicated. */
unsigned shim_xport_ring_depth(void)
{
	return SHM_RING_ENTRIES;
}

const char *shim_xport_name(void)
{
	return "shared memory (ivshmem, 3 regions)";
}

/* --------------------------------------------------------------- mapping */

/*
 * An arena region's usable bytes, for uet_shim_arena.c to carve up. Valid
 * only once the region is mapped. CTRL has no arena and returns NULL.
 */
void *shim_xport_arena(unsigned reg, size_t *len)
{
	if (len != NULL)
		*len = 0;

	if ((reg != SHIM_REG_ARENA_H) && (reg != SHIM_REG_ARENA_G))
		return NULL;
	if (g_reg[reg].base == NULL)
		return NULL;

	if (len != NULL)
		*len = g_reg[reg].size - SHM_ARENA_OFF;
	return (char *)g_reg[reg].base + SHM_ARENA_OFF;
}

static void *map_path(const char *path, size_t size, int create, int pin)
{
	void *p;
	int fd = open(path, create ? (O_RDWR | O_CREAT) : O_RDWR, 0666);

	if (fd < 0) {
		fprintf(stderr, "[shim/shm] open %s: %s\n",
			path, strerror(errno));
		return NULL;
	}
	if (create && (ftruncate(fd, (off_t)size) != 0))
		perror("[shim/shm] ftruncate");

	/* MAP_SHARED, never MAP_PRIVATE: private would be copy-on-write and
	 * the two sides would silently diverge on first write. */
	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);                            /* the mapping outlives the fd */

	if (p == MAP_FAILED) {
		fprintf(stderr, "[shim/shm] mmap %s: %s\n",
			path, strerror(errno));
		return NULL;
	}

	/*
	 * Keep the CHANNEL resident. ftruncate() leaves a SPARSE file, so
	 * mlock here does double duty: it pins the pages and forces them in.
	 * A major fault on a swapped page turns a 100 ns load into
	 * milliseconds, which can exceed the 5 ms PDS retransmit timeout and
	 * look exactly like packet loss.
	 *
	 * Only the channel, deliberately. Pinning both arenas would commit a
	 * quarter gigabyte on each side before a single byte is used, and an
	 * arena is bulk data where one extra minor fault per new page is
	 * irrelevant. The channel is the latency-critical part.
	 *
	 * Warn rather than fail: unpinned still works, it just loses the
	 * guarantee. Privileged processes bypass RLIMIT_MEMLOCK entirely.
	 */
	if (pin && (mlock(p, sizeof(struct shm_chan)) != 0))
		fprintf(stderr, "[shim/shm] mlock: %s (continuing unpinned; "
				"raise RLIMIT_MEMLOCK to fix)\n",
			strerror(errno));
	return p;
}

/*
 * Locate every ivshmem device in the guest. No in-tree driver claims
 * 1af4:1110, so sysfs lets a privileged userspace process map its BAR
 * directly - which is exactly why this works without a kernel module.
 *
 * Searched by vendor/device ID, not by slot, and the ORDER FOUND IS NOT
 * TRUSTED: the caller maps each and reads its magic to learn what it is.
 * Both the PCI slot and the BAR base are assigned at enumeration and move
 * if you reorder devices in the QEMU command line.
 */
static size_t find_ivshmem_all(char out[][256], size_t max)
{
	glob_t g;
	size_t i, n = 0;

	if (glob("/sys/bus/pci/devices/*", 0, NULL, &g) != 0)
		return 0;

	for (i = 0; (i < g.gl_pathc) && (n < max); i++) {
		char p[320], buf[32];
		unsigned vendor, device;
		int fd, r;

		snprintf(p, sizeof(p), "%s/vendor", g.gl_pathv[i]);
		fd = open(p, O_RDONLY);
		if (fd < 0)
			continue;
		r = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (r <= 0)
			continue;
		buf[r] = '\0';
		vendor = (unsigned)strtoul(buf, NULL, 0);
		if (vendor != 0x1af4)             /* Red Hat / virtio range */
			continue;

		snprintf(p, sizeof(p), "%s/device", g.gl_pathv[i]);
		fd = open(p, O_RDONLY);
		if (fd < 0)
			continue;
		r = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (r <= 0)
			continue;
		buf[r] = '\0';
		device = (unsigned)strtoul(buf, NULL, 0);
		if (device != 0x1110)             /* ivshmem */
			continue;

		/* resource2 == BAR2. BAR0 is the register window, unused by
		 * ivshmem-plain; BAR2 is the shared memory. */
		snprintf(out[n], 256, "%s/resource2", g.gl_pathv[i]);
		fprintf(stderr, "[shim/shm] ivshmem at %s\n", g.gl_pathv[i]);
		n++;
	}
	globfree(&g);
	return n;
}

static void region_path(unsigned reg, char *out, size_t cap)
{
	const char *pfx = getenv("UET_SHIM_SHM");

	snprintf(out, cap, "%s%s", (pfx != NULL) ? pfx : SHM_PATH_PREFIX,
		 g_rdesc[reg].suffix);
}

/* --------------------------------------------------------- spin / backoff */

static unsigned shim_timeout_secs(void)
{
	static unsigned t = (unsigned)-1;

	if (t == (unsigned)-1) {
		const char *e = getenv("UET_SHIM_TIMEOUT");

		t = (e != NULL) ? (unsigned)strtoul(e, NULL, 0)
				: SHM_TIMEOUT_DEFAULT;
	}
	return t;
}

static double now_secs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void idle_wait(unsigned long *spins)
{
	if (++(*spins) < SHM_SPIN_BUDGET) {
		/* PAUSE hints to the CPU that this is a spin-wait: it
		 * reduces power and avoids a memory-order violation penalty
		 * on exit from the loop. */
#if defined(__x86_64__) || defined(__i386__)
		__builtin_ia32_pause();
#else
		__asm__ __volatile__("" ::: "memory");
#endif
		return;
	}
	{
		struct timespec ts = { 0, SHM_IDLE_NS };

		nanosleep(&ts, NULL);
	}
}

/* ------------------------------------------------------------ host: stamp */

/*
 * Nonce for this run. Only has to differ from the PREVIOUS run's, so that
 * a guest still holding regions from a dead session notices; it is not a
 * secret and never leaves the machine.
 */
static uint64_t session_nonce(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t)ts.tv_sec << 20) ^ (uint64_t)ts.tv_nsec
	       ^ ((uint64_t)getpid() << 48);
}

/*
 * Write a region's identity. magic goes LAST under a release store, so
 * whoever sees it is guaranteed to see abi, session and region_bytes too.
 */
static void stamp_region(unsigned reg)
{
	struct shm_region_hdr *rh = g_reg[reg].base;

	rh->abi          = SHIM_ABI_VERSION;
	rh->session      = g_session;
	rh->region_bytes = g_reg[reg].size;

	pub(&rh->magic, g_rdesc[reg].magic);
}

int shim_xport_connect(void)
{
	unsigned long spins = 0;
	unsigned reg;

	for (reg = 0; reg < SHIM_REG_MAX; reg++) {
		char path[256];

		region_path(reg, path, sizeof(path));
		g_reg[reg].base = map_path(path, g_rdesc[reg].size, 1,
					   reg == SHIM_REG_CTRL);
		if (g_reg[reg].base == NULL)
			return -EIO;
		g_reg[reg].size = g_rdesc[reg].size;
	}

	g_chan    = g_reg[SHIM_REG_CTRL].base;
	g_is_host = 1;
	g_session = session_nonce();

	/*
	 * Zero the mailboxes BEFORE claiming any region: a guest that sees
	 * our magic must not then find a previous run's doorbell still set.
	 * The counters themselves are latched, not reset - see below.
	 */
	g_chan->host_up  = 0;
	g_chan->guest_up = 0;
	g_chan->h2g.head = 0;  g_chan->h2g.tail = 0;
	g_chan->g2h.head = 0;  g_chan->g2h.tail = 0;

	/*
	 * Arenas first, CTRL last. The guest waits on CTRL, so by the time
	 * it sees "UETC" the arenas are already fully published and it can
	 * bind all three without a second wait loop.
	 */
	stamp_region(SHIM_REG_ARENA_H);
	stamp_region(SHIM_REG_ARENA_G);
	stamp_region(SHIM_REG_CTRL);

	fprintf(stderr, "[shim/shm] regions stamped, session %016llx\n",
		(unsigned long long)g_session);

	/*
	 * Two-phase handshake, so a RECONNECT cannot pick up the previous
	 * session's leftovers:
	 *
	 *   we raise host_up  ->  guest latches its counters, raises guest_up
	 *                     ->  we latch the same counters
	 *
	 * Latching the CURRENT values rather than zero is what makes a
	 * reconnect safe. The counters keep climbing across sessions, so a
	 * stale reply still sitting in the mailbox is never NEWER than what
	 * we latched. Resetting to 0 here made that stale reply look fresh,
	 * and the host returned the previous run's answer: "seq 220 != 1".
	 */
	pub(&g_chan->host_up, 1);

	{
		double t0 = now_secs();
		unsigned tmo = shim_timeout_secs();

		while (obs(&g_chan->guest_up) == 0) {
			if ((tmo != 0) && ((now_secs() - t0) > tmo)) {
				fprintf(stderr, "[shim/shm] guest did not arm "
						"within %us.\n"
					"           Start uet_shim_guest in "
					"the VM, then retry.\n", tmo);
				return -ETIMEDOUT;
			}
			idle_wait(&spins);
		}
	}

	/*
	 * Latch the CURRENT cursors, never zero. The counters keep climbing
	 * across sessions, so a stale reply still sitting in the ring is
	 * never newer than what we latched. Resetting to 0 made a stale
	 * reply look fresh and returned the previous run's answer.
	 *
	 * We read g2h, so we own its tail: discard anything left there by
	 * skipping straight to head.
	 */
	g_rx_cached_head = obs(&g_chan->g2h.head);
	pub(&g_chan->g2h.tail, g_rx_cached_head);
	g_tx_cached_tail = obs(&g_chan->h2g.tail);

	fprintf(stderr, "[shim/shm] connected (abi %u)\n", SHIM_ABI_VERSION);
	return SHM_PSEUDO_FD;
}

/* -------------------------------------------------------- guest: discover */

/*
 * Bind one mapped candidate to whichever region its magic names. Returns 0
 * if it was claimed. A region that is not yet stamped reads as 0 and is
 * simply not claimed this pass.
 */
/*
 * Which region does this candidate's magic name? SHIM_REG_MAX means "not
 * stamped yet", which is normal while the host is still starting, not an
 * error.
 */
static unsigned probe_region(const void *base)
{
	const struct shm_region_hdr *rh = base;
	uint32_t magic = obs(&rh->magic);
	unsigned reg;

	for (reg = 0; reg < SHIM_REG_MAX; reg++) {
		if (magic == g_rdesc[reg].magic)
			return reg;
	}
	return SHIM_REG_MAX;
}

/*
 * Three checks, three different faults, three different fixes - so they are
 * reported separately rather than collapsed into one "handshake failed".
 */
static int verify_regions(void)
{
	const struct shm_region_hdr *ctrl = g_reg[SHIM_REG_CTRL].base;
	unsigned reg;

	for (reg = 0; reg < SHIM_REG_MAX; reg++) {
		const struct shm_region_hdr *rh = g_reg[reg].base;

		if (rh == NULL) {
			fprintf(stderr, "[shim/shm] region %s not found. Is "
					"-device ivshmem-plain present for "
					"all three?\n",
				shim_region_name(reg));
			return -ENODEV;
		}
		if (rh->abi != SHIM_ABI_VERSION) {
			fprintf(stderr, "[shim/shm] abi mismatch on %s: "
					"host %u, guest %u - rebuild both "
					"sides\n",
				shim_region_name(reg), rh->abi,
				SHIM_ABI_VERSION);
			return -EPROTO;
		}
		if (rh->session != ctrl->session) {
			fprintf(stderr, "[shim/shm] session mismatch on %s: "
					"regions are from different host "
					"runs. Restart the host shim; it "
					"re-stamps all three.\n",
				shim_region_name(reg));
			return -EPROTO;
		}
		if (rh->region_bytes != g_reg[reg].size) {
			fprintf(stderr, "[shim/shm] size mismatch on %s: "
					"host %llu, mapped %zu - check "
					"QEMU's size=\n",
				shim_region_name(reg),
				(unsigned long long)rh->region_bytes,
				g_reg[reg].size);
			return -EPROTO;
		}
	}

	g_session = ctrl->session;
	return 0;
}

/*
 * A BAR is only as large as QEMU made it, so mapping a 2 MiB CTRL BAR at
 * the 128 MiB arena size would fail or SIGBUS on first touch. Identity is
 * not known until the magic is read, and the magic is in the first 24
 * bytes, so probe with ONE PAGE, learn what each region is, then map each
 * at its real size.
 */
#define SHM_PROBE_SIZE  4096u

static int probe_and_bind(char path[][256], size_t n)
{
	void *probe[SHIM_REG_MAX + 4];
	unsigned found[SHIM_REG_MAX + 4];
	unsigned long spins = 0;
	size_t i, nprobe = 0;
	unsigned reg;
	double t0;
	unsigned tmo;
	int rc = 0;

	for (i = 0; i < n; i++) {
		probe[nprobe] = map_path(path[i], SHM_PROBE_SIZE, 0, 0);
		if (probe[nprobe] == NULL)
			continue;
		found[nprobe] = SHIM_REG_MAX;
		nprobe++;
	}
	if (nprobe < SHIM_REG_MAX) {
		fprintf(stderr, "[shim/shm] only %zu of %d regions could be "
				"mapped\n", nprobe, SHIM_REG_MAX);
		rc = -ENODEV;
		goto out;
	}

	/*
	 * Poll until the host has stamped all three. Either side may start
	 * first, so finding nothing yet is normal.
	 */
	t0  = now_secs();
	tmo = shim_timeout_secs();
	for (;;) {
		unsigned seen = 0;

		for (i = 0; i < nprobe; i++) {
			if (found[i] == SHIM_REG_MAX)
				found[i] = probe_region(probe[i]);
			if (found[i] != SHIM_REG_MAX)
				seen |= 1u << found[i];
		}
		if (seen == ((1u << SHIM_REG_MAX) - 1u))
			break;

		if ((tmo != 0) && ((now_secs() - t0) > tmo)) {
			fprintf(stderr, "[shim/shm] timed out after %us: the "
					"host shim has not stamped the "
					"regions.\n"
				"           Start the host side, then "
				"retry.\n", tmo);
			rc = -ETIMEDOUT;
			goto out;
		}
		idle_wait(&spins);
	}

	/* Identity known: remap each at its real size. */
	for (i = 0; i < nprobe; i++) {
		reg = found[i];
		if ((reg >= SHIM_REG_MAX) || (g_reg[reg].base != NULL))
			continue;

		g_reg[reg].base = map_path(path[i], g_rdesc[reg].size, 0,
					   reg == SHIM_REG_CTRL);
		if (g_reg[reg].base == NULL) {
			rc = -EIO;
			goto out;
		}
		g_reg[reg].size = g_rdesc[reg].size;
	}

out:
	for (i = 0; i < nprobe; i++)
		munmap(probe[i], SHM_PROBE_SIZE);
	return rc;
}

int shim_xport_listen(void)
{
	char path[SHIM_REG_MAX + 4][256];
	size_t ncand = 0;
	unsigned reg;
	int rc;

	if (getenv("UET_SHIM_SHM") != NULL) {
		/* loopback testing: the paths are known, but identity still
		 * comes from the magic so both code paths stay the same */
		for (reg = 0; reg < SHIM_REG_MAX; reg++)
			region_path(reg, path[ncand++], sizeof(path[0]));
	} else {
		ncand = find_ivshmem_all(path, SHIM_REG_MAX + 4);
		if (ncand < SHIM_REG_MAX) {
			fprintf(stderr, "[shim/shm] found %zu ivshmem devices "
					"(1af4:1110), need %d. Check the "
					"-device ivshmem-plain lines in the "
					"QEMU command.\n",
				ncand, SHIM_REG_MAX);
			return -ENODEV;
		}
	}

	rc = probe_and_bind(path, ncand);
	if (rc != 0)
		return rc;

	rc = verify_regions();
	if (rc != 0)
		return rc;

	g_chan    = g_reg[SHIM_REG_CTRL].base;
	g_is_host = 0;

	fprintf(stderr, "[shim/shm] bound 3 regions, session %016llx\n",
		(unsigned long long)g_session);
	return SHM_PSEUDO_FD;
}

int shim_xport_accept(int lfd)
{
	unsigned long spins = 0;

	(void)lfd;
	if (g_chan == NULL)
		return -EIO;

	/* a previous host may have left host_up set; either way, wait */
	while (obs(&g_chan->host_up) == 0)
		idle_wait(&spins);

	/* Latch BEFORE arming. Otherwise the host can send into the gap
	 * between us raising guest_up and reading the counters, and that
	 * request would be missed forever - the first bug this design hit. */
	/* Mirror image: we read h2g, so we own its tail. Latch before
	 * arming - otherwise the host can send into the gap between us
	 * raising guest_up and reading the cursors, and that request would
	 * be missed forever. */
	g_rx_cached_head = obs(&g_chan->h2g.head);
	pub(&g_chan->h2g.tail, g_rx_cached_head);
	g_tx_cached_tail = obs(&g_chan->g2h.tail);

	pub(&g_chan->guest_up, 1);
	return SHM_PSEUDO_FD;
}

void shim_xport_close(int fd)
{
	(void)fd;
	if (g_chan == NULL)
		return;

	pub(g_is_host ? &g_chan->host_up : &g_chan->guest_up, 0);
	/* The mappings themselves are left in place: the peer may still be
	 * reading, and the regions are reused on reconnect. */
}

/* -------------------------------------------------------------- messaging */

/*
 * Producer. The slot is filled with plain stores and then head is
 * published with a RELEASE store, so a consumer that observes the new head
 * is guaranteed to see the slot behind it.
 *
 * g_tx_cached_tail is this side's PRIVATE copy of the consumer's tail. It
 * exists so the common case never reads the consumer's cache line: only
 * when the ring looks full do we pay that miss and re-read.
 */
int shim_send_msg(int fd, const struct shim_hdr *h, const void *payload)
{
	struct shm_ring *r;
	struct shm_slot *slot;
	uint32_t head;

	(void)fd;
	if (g_chan == NULL)
		return -ENOTCONN;
	if (h->payload_len > SHIM_MAX_PAYLOAD)
		return -EMSGSIZE;

	r = g_is_host ? &g_chan->h2g : &g_chan->g2h;

	head = r->head;                       /* we own it: plain load */
	if ((head - g_tx_cached_tail) >= SHM_RING_ENTRIES) {
		g_tx_cached_tail = obs(&r->tail);   /* only now pay the miss */
		if ((head - g_tx_cached_tail) >= SHM_RING_ENTRIES)
			return -EAGAIN;             /* genuinely full */
	}

	slot = &r->slot[head & SHM_RING_MASK];
	slot->hdr = *h;
	slot->hdr.magic = SHIM_MAGIC;
	slot->len = h->payload_len;
	if ((h->payload_len > 0) && (payload != NULL))
		memcpy(slot->data, payload, h->payload_len);

	/* RELEASE: everything above must be visible before the doorbell */
	pub(&r->head, head + 1);
	return 0;
}

/*
 * Consumer. Reads ONE message; a caller that wants a batch calls it in a
 * loop, and only the first call per batch pays the acquire because
 * g_rx_cached_head holds what we last saw.
 */
int shim_recv_msg(int fd, struct shim_hdr *h, void *payload,
		  size_t payload_cap)
{
	struct shm_ring *r;
	struct shm_slot *slot;
	uint32_t *peer_up;
	unsigned long spins = 0;
	uint32_t tail;

	(void)fd;
	if (g_chan == NULL)
		return -ENOTCONN;

	r       = g_is_host ? &g_chan->g2h : &g_chan->h2g;
	peer_up = g_is_host ? &g_chan->guest_up : &g_chan->host_up;
	tail    = r->tail;                    /* we own it */

	{
		double t0 = now_secs();
		unsigned tmo = shim_timeout_secs();

		/* Compared with !=, never >, so a uint32 wrap after four
		 * billion messages is a non-event rather than a wedge. */
		while (tail == g_rx_cached_head) {
			g_rx_cached_head = obs(&r->head);
			if (tail != g_rx_cached_head)
				break;
			if (obs(peer_up) == 0)
				return -ENOTCONN;
			if ((tmo != 0) && ((now_secs() - t0) > tmo)) {
				fprintf(stderr,
					"[shim/shm] timed out after %us "
					"waiting for the peer (it may have "
					"died without being able to "
					"clear it). Restart both sides; "
					"re-create the regions if it "
					"persists.\n", tmo);
				return -ETIMEDOUT;
			}
			idle_wait(&spins);
		}
	}

	slot = &r->slot[tail & SHM_RING_MASK];
	*h = slot->hdr;
	if (h->magic != SHIM_MAGIC) {
		fprintf(stderr, "[shim/shm] bad magic 0x%08x\n", h->magic);
		return -EPROTO;
	}
	/* The peer DECLARES a length; the receiver decides whether to
	 * believe it. */
	if (h->payload_len > payload_cap) {
		pub(&r->tail, tail + 1);      /* retire it anyway, or the
					       * ring wedges on a bad slot */
		return -EMSGSIZE;
	}
	if ((h->payload_len > 0) && (payload != NULL))
		memcpy(payload, slot->data, h->payload_len);

	/* RELEASE: the slot must be fully read before it is handed back */
	pub(&r->tail, tail + 1);
	return 0;
}
