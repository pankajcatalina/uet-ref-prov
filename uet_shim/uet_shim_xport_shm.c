/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * Shared-memory transport for the shim.
 *
 *   host  : mmap /dev/shm/uet_dp directly
 *   guest : mmap BAR2 of the unclaimed ivshmem device (1af4:1110)
 *   QEMU  : -object memory-backend-file,id=dp,mem-path=/dev/shm/uet_dp,\
 *                   size=16M,share=on
 *           -device ivshmem-plain,memdev=dp
 *
 * Both sides end up on the same PHYSICAL pages, so after mmap() there is no
 * kernel and no QEMU in the path: every exchange is loads and stores.
 * ivshmem BAR2 is registered as a RAM MemoryRegion, so KVM installs it in
 * the guest's second-level page tables and accesses never trap.
 *
 * Measured: 0.37-0.49 us round trip, against 30-75 us for vsock, which
 * crosses the kernel twice per message.
 *
 * The channel is a pair of single-slot MAILBOXES, not rings. That is
 * sufficient because shim_rpc() holds a mutex for the whole request and
 * keeps exactly one operation outstanding. Rings only pay off once the data
 * path goes asynchronous; the spare 15.5 MiB is where they will go.
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

#define SHM_DEFAULT_PATH   "/dev/shm/uet_dp"
/*
 * Must match QEMU's size= exactly, and must be a power of two because
 * pci_register_bar() asserts it.
 *
 * 256 MiB, up from ABI 1's 16 MiB, because the arena now has to hold every
 * live memory region plus every in-flight transfer rather than just two
 * 256 KiB mailboxes. 256 MiB and not more because the guest firmware has to
 * assign this as a prefetchable BAR out of its PCI window, and a larger one
 * can fail assignment depending on machine type - a failure that costs a VM
 * restart to diagnose. Raising it later is this constant plus QEMU's size=;
 * check the result with "lspci -v -s 00:04.0" and look for [size=...].
 */
#define SHM_REGION_SIZE    (256u << 20)

/*
 * The region is cut in two. The channel sits at offset 0 so its compile-time
 * offsets are unchanged from ABI 1; the arena takes everything from
 * SHM_ARENA_OFF on.
 *
 * 2 MiB, not sizeof(struct shm_chan), for two reasons: a transparent
 * hugepage can then back the arena, and the channel can grow later without
 * moving a single arena byte.
 */
#define SHM_ARENA_OFF      (2u << 20)
#define SHM_CHAN_MAGIC     0x55455443u        /* "UETC" - marks the REGION;
					       * SHIM_MAGIC marks a MESSAGE  */
#define SHM_PSEUDO_FD      1000               /* not a real descriptor: the
					       * interface is fd-shaped from
					       * its vsock origin            */

/* Busy for this many iterations - the hot path - then nap, so an idle guest
 * does not burn a core while waiting hours for work. */
#define SHM_SPIN_BUDGET    20000
#define SHM_IDLE_NS        50000              /* 50 us */

/*
 * Bound every wait. magic and guest_up PERSIST in the region after a peer
 * dies - a SIGKILL leaves no chance to clear them - so without a deadline
 * the other side attaches to a dead channel and blocks forever with nothing
 * to show for it. Override with UET_SHIM_TIMEOUT (seconds; 0 = wait
 * indefinitely, useful when deliberately starting the host first).
 */
#define SHM_TIMEOUT_DEFAULT 30

/*
 * RELEASE on the doorbell store: everything written before it is visible to
 * anyone doing an ACQUIRE load of it. ACQUIRE on the doorbell load: nothing
 * after it can be hoisted above.
 *
 * Without this pair, the compiler or CPU may make the doorbell visible
 * BEFORE the payload, and the reader sees a fresh seq with stale bytes - a
 * bug that only appears under load and is miserable to find. On x86 these
 * emit no extra instructions; they constrain reordering.
 */
#define pub(p, v)   __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define obs(p)      __atomic_load_n((p), __ATOMIC_ACQUIRE)

/*
 * One mailbox per direction, so each has exactly ONE writer and ONE reader.
 * That is what removes the need for locking - only ordering remains.
 *
 * seq is the doorbell and owns a full cache line. Both CPUs hammer it, one
 * writing and one reading; if len or hdr shared that line, every write
 * would invalidate it on the other core and the line would ping-pong on
 * every message, costing more than the payload copy.
 */
struct shm_box {
	uint32_t seq;
	uint32_t _pad[15];                    /* 60 B: seq owns its line */
	uint32_t len;                         /* payload bytes after hdr */
	struct shim_hdr hdr;
	uint8_t  data[SHIM_MAX_PAYLOAD];
};

struct shm_chan {
	uint32_t magic;          /* "UETC", published LAST by the guest */
	uint32_t abi;            /* SHIM_ABI_VERSION                    */
	uint32_t host_up;        /* container attached                  */
	uint32_t guest_up;       /* guest armed for this session        */
	uint32_t _pad[12];       /* pad the control block to 64         */

	struct shm_box h2g;      /* host  -> guest */
	struct shm_box g2h;      /* guest -> host  */
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

_Static_assert(offsetof(struct shm_box, seq) == 0, "box.seq moved");
_Static_assert(offsetof(struct shm_box, len) == 64, "box.seq lost its line");
_Static_assert(offsetof(struct shm_box, hdr) == 72, "box.hdr moved");
_Static_assert(offsetof(struct shm_box, data) == 152, "box.data moved");

_Static_assert(offsetof(struct shm_chan, h2g) == 64, "h2g moved");
_Static_assert(offsetof(struct shm_chan, g2h) == 262360, "g2h moved");
_Static_assert(sizeof(struct shm_chan) <= SHM_ARENA_OFF,
	       "the channel has grown into the arena");
_Static_assert(SHM_ARENA_OFF < SHM_REGION_SIZE,
	       "no room left for an arena");

/* A performance property, asserted: put the two doorbells within a cache
 * line of each other and the build refuses, because the false sharing would
 * be invisible and cost more than the copy. */
_Static_assert((offsetof(struct shm_chan, g2h) + offsetof(struct shm_box, seq))
	       - (offsetof(struct shm_chan, h2g) + offsetof(struct shm_box, seq))
	       >= 64, "the two doorbells could false-share");

static struct shm_chan *g_chan;
static int      g_is_host;
static uint32_t g_tx_seq;                     /* the last value I published */
static uint32_t g_rx_seen;                    /* the last value I consumed  */

const char *shim_xport_name(void)
{
	return "shared memory (ivshmem)";
}

/* --------------------------------------------------------------- mapping */

/*
 * The arena, for uet_shim_host.c to allocate from and uet_shim_guest.c to
 * resolve offsets against. Valid only once the region is mapped, which is
 * why it reads g_chan rather than keeping a second base pointer: one
 * variable, one lifetime.
 */
void *shim_xport_arena(size_t *len)
{
	if (g_chan == NULL) {
		if (len != NULL)
			*len = 0;
		return NULL;
	}
	if (len != NULL)
		*len = SHM_REGION_SIZE - SHM_ARENA_OFF;
	return (char *)g_chan + SHM_ARENA_OFF;
}

static void *map_path(const char *path, int create)
{
	void *p;
	int fd = open(path, create ? (O_RDWR | O_CREAT) : O_RDWR, 0666);

	if (fd < 0) {
		fprintf(stderr, "[shim/shm] open %s: %s\n",
			path, strerror(errno));
		return NULL;
	}
	if (create && (ftruncate(fd, SHM_REGION_SIZE) != 0))
		perror("[shim/shm] ftruncate");

	/* MAP_SHARED, never MAP_PRIVATE: private would be copy-on-write and
	 * the two sides would silently diverge on first write. */
	p = mmap(NULL, SHM_REGION_SIZE, PROT_READ | PROT_WRITE,
		 MAP_SHARED, fd, 0);
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
	 * Only the channel, deliberately. ABI 1 pinned the whole 16 MiB
	 * region; pinning all 256 MiB would commit a quarter gigabyte of RAM
	 * on each side before a single byte is used, and the arena is bulk
	 * data where one extra minor fault per new page is irrelevant. The
	 * channel is the latency-critical part and it is under 512 KiB.
	 *
	 * Warn rather than fail: unpinned still works, it just loses the
	 * guarantee. Privileged processes bypass RLIMIT_MEMLOCK entirely.
	 */
	if (mlock(p, sizeof(struct shm_chan)) != 0)
		fprintf(stderr, "[shim/shm] mlock: %s (continuing unpinned; "
				"raise RLIMIT_MEMLOCK to fix)\n",
			strerror(errno));
	return p;
}

/*
 * Locate the ivshmem device in the guest. No in-tree driver claims
 * 1af4:1110, so sysfs lets a privileged userspace process map its BAR
 * directly - which is exactly why this works without a kernel module.
 *
 * Searched by vendor/device ID, not by slot: the guest assigns both the PCI
 * slot and the BAR base at enumeration, and they move if you reorder
 * devices in the QEMU command line.
 */
static char *find_ivshmem(void)
{
	static char res[256];
	glob_t g;
	size_t i;

	if (glob("/sys/bus/pci/devices/*", 0, NULL, &g) != 0)
		return NULL;

	for (i = 0; i < g.gl_pathc; i++) {
		char p[320], buf[32];
		unsigned vendor = 0, device = 0;
		int fd, n;

		snprintf(p, sizeof(p), "%s/vendor", g.gl_pathv[i]);
		fd = open(p, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		vendor = (unsigned)strtoul(buf, NULL, 0);
		if (vendor != 0x1af4)             /* Red Hat / virtio range */
			continue;

		snprintf(p, sizeof(p), "%s/device", g.gl_pathv[i]);
		fd = open(p, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		device = (unsigned)strtoul(buf, NULL, 0);
		if (device != 0x1110)             /* ivshmem */
			continue;

		/* resource2 == BAR2. BAR0 is the register window, unused by
		 * ivshmem-plain; BAR2 is the shared memory. */
		snprintf(res, sizeof(res), "%s/resource2", g.gl_pathv[i]);
		fprintf(stderr, "[shim/shm] ivshmem at %s\n", g.gl_pathv[i]);
		globfree(&g);
		return res;
	}
	globfree(&g);
	return NULL;
}

/* One function, two doors onto the same physical pages. */
static void *map_region(int is_host)
{
	const char *env = getenv("UET_SHIM_SHM");

	if (env != NULL)                  /* override: loopback testing */
		return map_path(env, is_host);
	if (is_host)
		return map_path(SHM_DEFAULT_PATH, 1);

	{
		char *bar = find_ivshmem();

		if (bar == NULL) {
			fprintf(stderr, "[shim/shm] no ivshmem device "
					"(1af4:1110). Is -device "
					"ivshmem-plain in the QEMU command?\n"
					"           Set UET_SHIM_SHM=<path> "
					"to override.\n");
			return NULL;
		}
		return map_path(bar, 0);
	}
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

/* ------------------------------------------------------------- interface */

int shim_xport_connect(void)
{
	unsigned long spins = 0;

	g_chan = map_region(1);
	if (g_chan == NULL)
		return -EIO;
	g_is_host = 1;

	fprintf(stderr, "[shim/shm] waiting for the guest shim...\n");
	{
		double t0 = now_secs();
		unsigned tmo = shim_timeout_secs();

		while (obs(&g_chan->magic) != SHM_CHAN_MAGIC) {
			if ((tmo != 0) && ((now_secs() - t0) > tmo)) {
				fprintf(stderr,
					"[shim/shm] timed out after %us: the "
					"guest shim has not claimed the "
					"region.\n"
					"           Start uet_shim_guest in "
					"the VM first, then retry.\n", tmo);
				return -ETIMEDOUT;
			}
			idle_wait(&spins);
		}
	}

	if (obs(&g_chan->abi) != SHIM_ABI_VERSION) {
		fprintf(stderr, "[shim/shm] abi mismatch: guest %u, host %u - "
				"rebuild both sides\n",
			obs(&g_chan->abi), SHIM_ABI_VERSION);
		return -EPROTO;
	}

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
						"within %us\n", tmo);
				return -ETIMEDOUT;
			}
			idle_wait(&spins);
		}
	}

	g_rx_seen = obs(&g_chan->g2h.seq);
	g_tx_seq  = obs(&g_chan->h2g.seq);

	fprintf(stderr, "[shim/shm] connected (abi %u)\n", SHIM_ABI_VERSION);
	return SHM_PSEUDO_FD;
}

int shim_xport_listen(void)
{
	g_chan = map_region(0);
	if (g_chan == NULL)
		return -EIO;
	g_is_host = 0;

	/*
	 * Claim the region. guest_up is deliberately NOT raised here: it is
	 * armed per session in accept(), so a serve loop that exits and
	 * re-accepts comes back properly instead of leaving the flag clear
	 * and failing every later call with ENOTCONN.
	 *
	 * magic is published LAST, with a RELEASE store, so anyone who sees
	 * "UETC" is guaranteed to see the zeroed counters and the abi too.
	 */
	g_chan->host_up = 0;
	g_chan->guest_up = 0;
	g_chan->h2g.seq = 0;
	g_chan->g2h.seq = 0;
	g_chan->abi = SHIM_ABI_VERSION;
	g_rx_seen = 0;
	g_tx_seq = 0;

	pub(&g_chan->magic, SHM_CHAN_MAGIC);

	fprintf(stderr, "[shim/shm] region ready, %zu bytes of channel\n",
		sizeof(struct shm_chan));
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
	g_rx_seen = obs(&g_chan->h2g.seq);
	g_tx_seq  = obs(&g_chan->g2h.seq);

	pub(&g_chan->guest_up, 1);
	return SHM_PSEUDO_FD;
}

void shim_xport_close(int fd)
{
	(void)fd;
	if (g_chan == NULL)
		return;

	pub(g_is_host ? &g_chan->host_up : &g_chan->guest_up, 0);
	/* The mapping itself is left in place: the peer may still be reading,
	 * and the region is reused on reconnect. */
}

int shim_send_msg(int fd, const struct shim_hdr *h, const void *payload)
{
	struct shm_box *box;

	(void)fd;
	if (g_chan == NULL)
		return -ENOTCONN;
	if (h->payload_len > SHIM_MAX_PAYLOAD)
		return -EMSGSIZE;

	box = g_is_host ? &g_chan->h2g : &g_chan->g2h;

	box->hdr = *h;
	box->hdr.magic = SHIM_MAGIC;
	box->len = h->payload_len;
	if ((h->payload_len > 0) && (payload != NULL))
		memcpy(box->data, payload, h->payload_len);

	/* RELEASE: everything above must be visible before the doorbell */
	pub(&box->seq, ++g_tx_seq);
	return 0;
}

int shim_recv_msg(int fd, struct shim_hdr *h, void *payload,
		  size_t payload_cap)
{
	struct shm_box *box;
	uint32_t *peer_up;
	unsigned long spins = 0;
	uint32_t cur;

	(void)fd;
	if (g_chan == NULL)
		return -ENOTCONN;

	box = g_is_host ? &g_chan->g2h : &g_chan->h2g;
	peer_up = g_is_host ? &g_chan->guest_up : &g_chan->host_up;

	/*
	 * ACQUIRE, and compared with != rather than >, so a uint32_t wrap is
	 * a non-event. g_rx_seen is private to this side and the peer never
	 * touches it, so "is there a new message?" is a purely local test
	 * against a value only the peer writes. No clearing step, so no
	 * window where both sides write the same word.
	 */
	{
		double t0 = now_secs();
		unsigned tmo = shim_timeout_secs();

		while ((cur = obs(&box->seq)) == g_rx_seen) {
			if (obs(peer_up) == 0)
				return -ENOTCONN;   /* peer closed cleanly */
			if ((tmo != 0) && ((now_secs() - t0) > tmo)) {
				fprintf(stderr,
					"[shim/shm] no reply after %us. The "
					"peer is gone but left the region "
					"marked live\n"
					"           (a killed process cannot "
					"clear it). Restart both sides; "
					"re-create\n"
					"           /dev/shm/uet_dp with "
					"conv=notrunc if it persists.\n", tmo);
				return -ETIMEDOUT;
			}
			idle_wait(&spins);
		}
	}
	g_rx_seen = cur;

	*h = box->hdr;
	if (h->magic != SHIM_MAGIC) {
		fprintf(stderr, "[shim/shm] bad magic 0x%08x\n", h->magic);
		return -EPROTO;
	}
	/* The peer DECLARES a length; the receiver decides whether to
	 * believe it. */
	if (h->payload_len > payload_cap)
		return -EMSGSIZE;
	if ((h->payload_len > 0) && (payload != NULL))
		memcpy(payload, box->data, h->payload_len);

	return 0;
}
