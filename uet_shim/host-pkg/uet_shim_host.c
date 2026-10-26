/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * HOST side of the shim. Runs in the container, underneath uet_provider.
 *
 * It DEFINES the uet_api.h surface that uet_provider imports - all 25
 * symbols - and forwards each call to uet_shim_guest.c, which invokes the
 * real SES/PDS stack inside the QEMU guest.
 *
 * Link this INSTEAD of libuet_fabric.so:
 *     uet_provider  ->  uet_shim_host.o  --shared memory-->  guest
 *
 * The guest side CALLS these 25; this side DEFINES them. Same names,
 * mirrored roles - nm proves it:
 *     nm uet_shim_host.o  | grep " T uet_"   -> 25
 *     nm uet_shim_guest.o | grep " U uet_"   -> 25
 *
 * Three translations happen here and nowhere else:
 *
 *   handles    every uet_*_handle_t is opaque, so the guest's table index
 *              is handed to the provider AS a pointer and round-trips back
 *              untouched. The provider never dereferences one, so this side
 *              needs no table at all.
 *
 *   context    void *context is the APPLICATION's pointer (NCCL's). It is
 *              meaningless in the guest, so it stays here in ctx_tbl[] and
 *              only an id crosses the wire.
 *
 *   rx buffers uet_recv() is handed a buffer the guest cannot write to. We
 *              remember it against the context id and fill it when the
 *              matching completion comes back through uet_cq_read().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/uio.h>

#include "uet_api.h"
#include "uet_shim.h"
#include "uet_shim_info.h"
#include "uet_shim_arena.h"

/* ------------------------------------------------------------ connection */

static int      g_fd = -1;
static uint32_t g_seq;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char     g_payload[SHIM_MAX_PAYLOAD];   /* reply staging, under g_lock */

/*
 * Clear our liveness flag when the process ends, so the guest's serve loop
 * breaks and it returns to accept() rather than spinning on a dead peer.
 * Does not help after SIGKILL, which is why both sides also time out.
 */
static __attribute__((destructor)) void shim_host_fini(void)
{
	if (g_fd >= 0) {
		shim_xport_close(g_fd);
		g_fd = -1;
	}
}

/*
 * Lazy connect. The provider offers no init hook the shim can hang off, and
 * connecting at load time would mean a 30 s timeout inside dlopen() if the
 * guest is not up yet.
 */
static int shim_connect_once(void)
{
	if (g_fd >= 0)
		return 0;

	g_fd = shim_xport_connect();
	if (g_fd < 0) {
		fprintf(stderr, "[shim/host] cannot reach the guest shim over "
				"%s: %s\n"
				"            uet_shim_guest must be running in "
				"the VM before any host call.\n",
			shim_xport_name(), strerror(-g_fd));
		return g_fd;
	}
	/*
	 * The arena is not optional. Every buffer the application hands us
	 * crosses as an offset into it, so without one there is no data path
	 * at all - and failing here, loudly, beats failing later as a
	 * truncated transfer. A transport with no shared region would need
	 * its own bulk strategy anyway.
	 */
	if (shim_arena_init() != 0) {
		fprintf(stderr, "[shim/host] %s provides no shared region; "
				"the arena is required by ABI %u\n",
			shim_xport_name(), SHIM_ABI_VERSION);
		shim_xport_close(g_fd);
		g_fd = -1;
		return -ENODEV;
	}

	fprintf(stderr, "[shim/host] connected over %s\n", shim_xport_name());
	return 0;
}

/* ===================================================================
 * arena staging
 *
 * The application gives us pointers into its own heap; the guest can only
 * address the shared region. So every buffer is either ALREADY inside a
 * registered region - in which case it has a permanent home in the arena
 * and we use that - or it is transient, and gets a block for the lifetime
 * of the operation.
 *
 * "For the lifetime of the operation" is the part that matters. ABI 1
 * passed send buffers inline and the mailbox was reused by the next
 * message, so a transfer still in flight could read another request's
 * bytes. A block owned by the context id cannot: it is freed only when the
 * completion is reaped.
 * =================================================================== */

#define MR_MAX 256               /* domain_attr->mr_cnt is 16 today */

struct mr_ent {
	int           used;
	shim_handle_t h;         /* the guest's handle: our key      */
	const void   *ubuf;      /* the application's buffer         */
	size_t        len;
	uint64_t      off;       /* arena offset of the shadow       */
	uint64_t      access;
};

static struct mr_ent   mr_tbl[MR_MAX];
static pthread_mutex_t mr_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * If [buf, buf+len) lies wholly inside a registered region, return the
 * matching arena offset. Partial overlap deliberately returns 0: staging
 * half a buffer would be worse than copying all of it.
 */
static uint64_t mr_off_for(const void *buf, size_t len)
{
	const char *p = buf;
	uint64_t off = 0;
	size_t i;

	if ((buf == NULL) || (len == 0))
		return 0;

	pthread_mutex_lock(&mr_lock);
	for (i = 0; i < MR_MAX; i++) {
		const char *b = mr_tbl[i].ubuf;

		if (!mr_tbl[i].used || (b == NULL))
			continue;
		if ((p >= b) && ((p + len) <= (b + mr_tbl[i].len))) {
			off = mr_tbl[i].off + (uint64_t)(p - b);
			break;
		}
	}
	pthread_mutex_unlock(&mr_lock);
	return off;
}

/*
 * Copy every remotely-writable region back out of the arena.
 *
 * Called when a completion is reaped, because that is the first moment the
 * application is entitled to look. Only FI_REMOTE_WRITE regions: a send
 * buffer is never modified by the peer, and syncing it would cost real
 * bandwidth on the hot path for nothing.
 */
static void mr_sync_in(void)
{
	size_t i;

	pthread_mutex_lock(&mr_lock);
	for (i = 0; i < MR_MAX; i++) {
		void *src;

		if (!mr_tbl[i].used || (mr_tbl[i].ubuf == NULL))
			continue;
		if ((mr_tbl[i].access & FI_REMOTE_WRITE) == 0)
			continue;

		src = shim_arena_ptr(mr_tbl[i].off, mr_tbl[i].len);
		if (src != NULL)
			memcpy((void *)mr_tbl[i].ubuf, src, mr_tbl[i].len);
	}
	pthread_mutex_unlock(&mr_lock);
}

struct stage {
	uint64_t off;            /* what travels in hdr.off */
	int      owned;          /* we allocated it, so we free it */
};

/*
 * A vector gets ONE arena block with its segments laid out end to end, and
 * the shim_iov table carries each segment's offset within it. The guest
 * rebuilds a real iovec from those offsets, so the stack still sees N
 * separate segments - we have only made them share an allocation, which
 * turns N allocator calls per operation into one.
 */
static size_t iov_total(const struct iovec *iov, size_t n)
{
	size_t i, t = 0;

	for (i = 0; i < n; i++)
		t += iov[i].iov_len;
	return t;
}

static int stage_iov(const struct iovec *iov, size_t n,
		     struct shim_iov *tbl, struct stage *st, int copy_in)
{
	size_t total = iov_total(iov, n);
	uint64_t cur = 0;
	size_t i;

	st->off = 0;
	st->owned = 0;

	if ((n == 0) || (n > SHIM_MAX_IOV))
		return -FI_EINVAL;
	if (total == 0)
		return -FI_EINVAL;

	st->off = shim_arena_alloc(total);
	if (st->off == 0)
		return -FI_ENOMEM;
	st->owned = 1;

	for (i = 0; i < n; i++) {
		tbl[i].off = cur;              /* relative to st->off */
		tbl[i].len = iov[i].iov_len;

		if (copy_in && (iov[i].iov_len > 0)) {
			void *dst = shim_arena_ptr(st->off + cur,
						   iov[i].iov_len);

			if (dst == NULL) {
				shim_arena_free(st->off);
				st->off = 0;
				st->owned = 0;
				return -FI_EINVAL;
			}
			memcpy(dst, iov[i].iov_base, iov[i].iov_len);
		}
		cur += iov[i].iov_len;
	}
	return 0;
}

/* Keep the application's iovec so a vectored receive can be scattered back
 * once the bytes land. A copy, not the pointer: the caller may reuse its
 * array the moment we return. */
static struct iovec *iov_dup(const struct iovec *iov, size_t n)
{
	struct iovec *d = malloc(n * sizeof(*d));

	if (d != NULL)
		memcpy(d, iov, n * sizeof(*d));
	return d;
}

/* outbound: the guest must see the current bytes, so copy them in */
static int stage_tx(const void *buf, size_t len, struct stage *st)
{
	void *dst;

	st->off = 0;
	st->owned = 0;

	if ((buf == NULL) || (len == 0))
		return 0;

	st->off = mr_off_for(buf, len);
	if (st->off == 0) {
		st->off = shim_arena_alloc(len);
		if (st->off == 0)
			return -FI_ENOMEM;
		st->owned = 1;
	}

	dst = shim_arena_ptr(st->off, len);
	if (dst == NULL) {
		if (st->owned)
			shim_arena_free(st->off);
		st->off = 0;
		st->owned = 0;
		return -FI_EINVAL;
	}
	memcpy(dst, buf, len);
	return 0;
}

/* inbound: reserve space only; the bytes arrive later */
static int stage_rx(void *buf, size_t len, struct stage *st)
{
	st->off = 0;
	st->owned = 0;

	if ((buf == NULL) || (len == 0))
		return 0;

	st->off = mr_off_for(buf, len);
	if (st->off == 0) {
		st->off = shim_arena_alloc(len);
		if (st->off == 0)
			return -FI_ENOMEM;
		st->owned = 1;
	}
	return 0;
}

/*
 * One synchronous call. Every one of the 25 stubs below is a thin wrapper
 * around this, so instrumenting it shows you everything.
 *
 * The caller supplies the SEMANTICS (h1, h2, a1..a4); this supplies the
 * PROTOCOL (opcode, length, sequence). A stub never touches seq and this
 * never interprets a1.
 *
 * reply_payload may be NULL when the caller does not expect one, or when it
 * intends to read g_payload directly.
 */
static int64_t shim_rpc(uint32_t op, struct shim_hdr *h,
			const void *in, uint32_t in_len,
			void *reply_payload, size_t reply_cap,
			uint32_t *reply_len)
{
	struct shim_hdr rsp;
	int rc;

	/*
	 * One lock for the whole request/response. Three consequences:
	 *   - exactly ONE call outstanding, which is why single-slot
	 *     mailboxes are correct and rings are unnecessary;
	 *   - g_seq and g_payload are safe without further locking;
	 *   - the whole shim serialises. At ~0.5 us that is tolerable, but
	 *     it is the scalability ceiling, and the reason an asynchronous
	 *     uet_cq_read() must bypass shim_rpc() rather than go through it.
	 */
	pthread_mutex_lock(&g_lock);

	if (shim_connect_once() != 0) {
		pthread_mutex_unlock(&g_lock);
		return -FI_EIO;
	}

	h->op = op;
	h->payload_len = in_len;
	h->seq = ++g_seq;

	rc = shim_send_msg(g_fd, h, in);
	if (rc != 0)
		goto fail;

	rc = shim_recv_msg(g_fd, &rsp, g_payload, sizeof(g_payload));
	if (rc != 0)
		goto fail;

	/*
	 * A correctness backstop independent of the transport: even if the
	 * doorbell logic were wrong, a reply belonging to a different
	 * request is detected rather than silently used. This is the check
	 * that caught the reconnect bug ("seq 220 != 1").
	 */
	if (rsp.seq != h->seq) {
		fprintf(stderr, "[shim/host] %s: seq %u != %u (out of sync)\n",
			shim_op_name(op), rsp.seq, h->seq);
		rc = -EPROTO;
		goto fail;
	}

	/* Clamp the copy, but report the FULL declared length, so the caller
	 * can tell a short reply from a complete one. */
	if ((reply_payload != NULL) && (rsp.payload_len > 0)) {
		size_t n = (rsp.payload_len > reply_cap) ?
			   reply_cap : rsp.payload_len;
		memcpy(reply_payload, g_payload, n);
	}
	if (reply_len != NULL)
		*reply_len = rsp.payload_len;

	/* hand the reply's handles and scalars back through *h. Only a1/a2
	 * are copied: CQ_READ is the only op returning scalars and it uses
	 * exactly two. */
	h->h1 = rsp.h1;
	h->h2 = rsp.h2;
	h->a1 = rsp.a1;
	h->a2 = rsp.a2;

	pthread_mutex_unlock(&g_lock);
	return rsp.ret;

fail:
	/*
	 * The specific cause goes to the log; the provider gets -FI_EIO,
	 * because its API has no vocabulary for "the call never arrived" -
	 * the fundamental difference between an RPC and a local call.
	 *
	 * Tear the connection down: after a sequence mismatch the channel is
	 * desynchronised and continuing would compound the error. The next
	 * call re-handshakes and re-latches both counters.
	 */
	fprintf(stderr, "[shim/host] %s failed: %s\n",
		shim_op_name(op), strerror(-rc));
	shim_xport_close(g_fd);
	g_fd = -1;
	pthread_mutex_unlock(&g_lock);
	return -FI_EIO;
}

/* ------------------------------------------------------------ ctx table
 * Maps the application's void *context - and any pending receive buffer -
 * to a small integer that can cross the wire. The mirror image of the
 * guest's hdl_tbl: each side tables the pointers IT owns.
 *
 * Its own mutex, separate from g_lock, so ctx_get() does not serialise
 * behind an in-flight RPC.
 *
 * Linear scan is fine while g_lock allows one operation at a time. Once the
 * data path goes asynchronous this becomes O(CTX_MAX) per post on the hot
 * path and wants a free list - not before.
 */
#define CTX_MAX 4096

struct ctx_ent {
	int      used;
	void    *context;        /* the application's pointer, never sent */
	void    *rx_buf;         /* uet_recv target, NULL for sends       */
	size_t   rx_len;
	uint64_t a_off;          /* arena block backing this operation    */
	int      a_owned;        /* transient: free it on completion      */
	struct iovec *rx_iov;    /* vectored receive: where to scatter to  */
	size_t   rx_iov_n;
};

static struct ctx_ent ctx_tbl[CTX_MAX];
static pthread_mutex_t ctx_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t ctx_get(void *context, void *rx_buf, size_t rx_len)
{
	uint64_t i;

	pthread_mutex_lock(&ctx_lock);
	for (i = 1; i < CTX_MAX; i++) {          /* 0 means "none" */
		if (!ctx_tbl[i].used) {
			ctx_tbl[i].used = 1;
			ctx_tbl[i].context = context;
			ctx_tbl[i].rx_buf = rx_buf;
			ctx_tbl[i].rx_len = rx_len;
			pthread_mutex_unlock(&ctx_lock);
			return i;
		}
	}
	pthread_mutex_unlock(&ctx_lock);
	fprintf(stderr, "[shim/host] ctx table full (%d in flight)\n", CTX_MAX);
	return 0;                 /* callers turn this into -FI_EAGAIN */
}

/*
 * Record which arena block an in-flight operation is using. Separate from
 * ctx_get() so the five data-path stubs keep their existing call, and so an
 * operation that needs no staging simply never calls this.
 */
static void ctx_attach(uint64_t id, const struct stage *st)
{
	if ((id == 0) || (id >= CTX_MAX))
		return;
	pthread_mutex_lock(&ctx_lock);
	ctx_tbl[id].a_off = st->off;
	ctx_tbl[id].a_owned = st->owned;
	pthread_mutex_unlock(&ctx_lock);
}

static void ctx_attach_iov(uint64_t id, struct iovec *iov, size_t n)
{
	if ((id == 0) || (id >= CTX_MAX)) {
		free(iov);
		return;
	}
	pthread_mutex_lock(&ctx_lock);
	ctx_tbl[id].rx_iov = iov;
	ctx_tbl[id].rx_iov_n = n;
	pthread_mutex_unlock(&ctx_lock);
}

/* get and free in one step: a completion consumes the operation */
static struct ctx_ent ctx_take(uint64_t id)
{
	struct ctx_ent e = { 0 };

	if ((id == 0) || (id >= CTX_MAX))
		return e;
	pthread_mutex_lock(&ctx_lock);
	e = ctx_tbl[id];
	ctx_tbl[id].used = 0;
	pthread_mutex_unlock(&ctx_lock);
	return e;
}

/* The provider's eq callbacks. Function pointers cannot cross a process
 * boundary, so they stay here to be invoked locally once a reader thread
 * exists to receive events. uet_provider.c passes NULL for both today. */
static uet_eq_callback_t     g_eq_cb;
static uet_eq_err_callback_t g_eq_err_cb;

/* ===================================================================
 * lifecycle
 * =================================================================== */

int uet_initialize(uet_handle_t *handle)
{
	struct shim_hdr h = { 0 };
	int64_t rc = shim_rpc(SHIM_INITIALIZE, &h, NULL, 0, NULL, 0, NULL);

	if (rc < 0)
		return (int)rc;
	*handle = shim_h2p(h.h1);         /* index, disguised as a pointer */
	return (int)rc;
}

int uet_finalize(uet_handle_t handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(handle) };

	return (int)shim_rpc(SHIM_FINALIZE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_getinfo(uet_handle_t handle, struct uet_addr *node,
		const struct fi_info *hints, struct fi_info **info)
{
	struct shim_hdr h = { .h1 = shim_p2h(handle) };
	struct shim_fi_info flat;
	uint32_t rlen = 0;
	int64_t rc;

	(void)hints;   /* uet_getinfo() ignores hints today - it carries a
			* literal "need to process hints" TODO */

	rc = shim_rpc(SHIM_GETINFO, &h, node,
		      (node != NULL) ? (uint32_t)sizeof(*node) : 0,
		      &flat, sizeof(flat), &rlen);
	if (rc < 0)
		return (int)rc;

	/* this is why shim_rpc reports the full length, not the clamped one */
	if (rlen < sizeof(flat)) {
		fprintf(stderr, "[shim/host] getinfo: short reply %u\n", rlen);
		return -FI_EIO;
	}

	*info = shim_info_build(&flat);
	return (*info != NULL) ? 0 : -FI_ENOMEM;
}

int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr)
{
	struct shim_hdr h = { .h1 = shim_p2h(ep_handle) };

	return (int)shim_rpc(SHIM_GETNAME, &h, NULL, 0,
			     uet_addr, sizeof(*uet_addr), NULL);
}

/* ===================================================================
 * domain
 * =================================================================== */

int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
	       struct fi_info *info, struct fid_domain *domain,
	       void *context, uet_eq_callback_t eq_callback,
	       uet_eq_err_callback_t eq_err_callback,
	       uet_domain_handle_t *domain_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(handle) };
	struct shim_fi_info flat;
	int64_t rc;

	/*
	 * fabric and domain are libfabric objects. The UET stack STORES them
	 * and never dereferences them, so they cross as opaque tokens.
	 */
	h.a1 = shim_p2h(fabric);
	h.a2 = shim_p2h(domain);
	h.a3 = ctx_get(context, NULL, 0);

	/* kept local: a function pointer is meaningless in the guest */
	g_eq_cb = eq_callback;
	g_eq_err_cb = eq_err_callback;

	shim_info_flatten(info, &flat);

	rc = shim_rpc(SHIM_DOMAIN, &h, &flat, sizeof(flat), NULL, 0, NULL);
	if (rc < 0)
		return (int)rc;
	*domain_handle = shim_h2p(h.h1);
	return (int)rc;
}

int uet_domain_close(uet_domain_handle_t domain_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(domain_handle) };

	return (int)shim_rpc(SHIM_DOMAIN_CLOSE, &h, NULL, 0, NULL, 0, NULL);
}

/* ===================================================================
 * endpoint
 * =================================================================== */

int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(domain_handle) };
	struct shim_fi_info flat;
	int64_t rc;

	h.a1 = shim_p2h(ep);                 /* opaque token */
	h.a2 = ctx_get(context, NULL, 0);

	shim_info_flatten(info, &flat);

	rc = shim_rpc(SHIM_ENDPOINT, &h, &flat, sizeof(flat), NULL, 0, NULL);
	if (rc < 0)
		return (int)rc;
	*ep_handle = shim_h2p(h.h1);
	return (int)rc;
}

int uet_ep_enable(uet_ep_handle_t ep_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(ep_handle) };

	return (int)shim_rpc(SHIM_EP_ENABLE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_ep_close(uet_ep_handle_t ep_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(ep_handle) };

	return (int)shim_rpc(SHIM_EP_CLOSE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
		   struct fid_cq *cq, uint64_t flags, void *context,
		   uet_cq_handle_t *cq_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(ep_handle) };
	int64_t rc;

	h.a1 = shim_p2h(cq);                 /* opaque token */
	h.a2 = flags;
	h.a3 = ctx_get(context, NULL, 0);

	/* fi_cq_attr is flat - no pointers - so it crosses verbatim */
	rc = shim_rpc(SHIM_EP_BIND_CQ, &h, attr,
		      (attr != NULL) ? (uint32_t)sizeof(*attr) : 0,
		      NULL, 0, NULL);
	if (rc < 0)
		return (int)rc;
	*cq_handle = shim_h2p(h.h2);
	return (int)rc;
}

int uet_ep_bind_mr(uet_ep_handle_t ep_handle, uet_mr_handle_t mr_handle,
		   uint64_t flags)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = flags,
	};

	return (int)shim_rpc(SHIM_EP_BIND_MR, &h, NULL, 0, NULL, 0, NULL);
}

/* ===================================================================
 * memory region
 * =================================================================== */

int uet_mr_reg(uet_domain_handle_t domain_handle, const void *buf, size_t len,
	       uint64_t access, uint64_t requested_key, uint64_t flags,
	       void *context, uet_mr_handle_t *mr_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(domain_handle) };
	uint64_t off;
	void *shadow;
	size_t i;
	int64_t rc;

	h.a1 = len;
	h.a2 = access;
	h.a3 = requested_key;
	h.a4 = flags;

	/*
	 * The region gets a permanent home in the arena and the guest
	 * registers THAT, so both sides hold the same bytes at their own
	 * addresses. This is what makes RMA possible: a peer's write lands
	 * where the application can read it.
	 *
	 * ABI 1 shipped the contents inline and the guest registered a
	 * private copy, which capped a region at 256 KiB and made RMA and
	 * atomics impossible rather than merely slow.
	 */
	(void)context;   /* mr context is not reported through the CQ */

	if (len == 0)
		return -FI_EINVAL;

	off = shim_arena_alloc(len);
	if (off == 0) {
		fprintf(stderr, "[shim/host] mr_reg: no arena space for %zu "
				"bytes (largest free run %zu)\n",
			len, shim_arena_avail());
		return -FI_ENOMEM;
	}

	shadow = shim_arena_ptr(off, len);
	if (shadow == NULL) {
		shim_arena_free(off);
		return -FI_EINVAL;
	}
	/* seed it: a send-side region is registered with its data already
	 * in place, and the stack may read it before we next hear from the
	 * application */
	if (buf != NULL)
		memcpy(shadow, buf, len);
	else
		memset(shadow, 0, len);

	h.off = off;
	rc = shim_rpc(SHIM_MR_REG, &h, NULL, 0, NULL, 0, NULL);
	if (rc < 0) {
		shim_arena_free(off);
		return (int)rc;
	}
	*mr_handle = shim_h2p(h.h2);

	/* remember the mapping so mr_off_for() can spot buffers that live
	 * inside this region, and mr_sync_in() can copy it back */
	pthread_mutex_lock(&mr_lock);
	for (i = 0; i < MR_MAX; i++) {
		if (mr_tbl[i].used)
			continue;
		mr_tbl[i].used   = 1;
		mr_tbl[i].h      = h.h2;
		mr_tbl[i].ubuf   = buf;
		mr_tbl[i].len    = len;
		mr_tbl[i].off    = off;
		mr_tbl[i].access = access;
		break;
	}
	pthread_mutex_unlock(&mr_lock);
	if (i == MR_MAX)
		fprintf(stderr, "[shim/host] mr_reg: tracking table full "
				"(%d regions); this one will not sync back\n",
			MR_MAX);
	return (int)rc;
}

uint64_t uet_mr_key(uet_mr_handle_t mr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(mr_handle) };
	int64_t rc = shim_rpc(SHIM_MR_KEY, &h, NULL, 0, NULL, 0, NULL);

	/* returns uint64_t with no error channel, so a transport failure can
	 * only be signalled as an impossible key */
	return (rc < 0) ? UINT64_MAX : (uint64_t)rc;
}

int uet_mr_enable(uet_mr_handle_t mr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(mr_handle) };

	return (int)shim_rpc(SHIM_MR_ENABLE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_mr_disable(uet_mr_handle_t mr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(mr_handle) };

	/* Last chance to see what the peer wrote. uet.c validates an RMA
	 * target after disabling the region, and a completion may not have
	 * been reaped since the final write. */
	mr_sync_in();

	return (int)shim_rpc(SHIM_MR_DISABLE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_mr_close(uet_mr_handle_t mr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(mr_handle) };
	uint64_t off = 0;
	size_t i;
	int rc;

	/* Close on the guest FIRST, then reclaim: freeing the arena block
	 * while the stack still holds the registration would hand live
	 * memory to the next allocation. */
	rc = (int)shim_rpc(SHIM_MR_CLOSE, &h, NULL, 0, NULL, 0, NULL);

	pthread_mutex_lock(&mr_lock);
	for (i = 0; i < MR_MAX; i++) {
		if (mr_tbl[i].used && (mr_tbl[i].h == h.h2)) {
			off = mr_tbl[i].off;
			memset(&mr_tbl[i], 0, sizeof(mr_tbl[i]));
			break;
		}
	}
	pthread_mutex_unlock(&mr_lock);

	shim_arena_free(off);
	return rc;
}

/* ===================================================================
 * address vector
 * =================================================================== */

int uet_av_insert(uet_domain_handle_t domain_handle,
		  struct uet_addr *uet_addr,
		  uet_addr_handle_t *addr_handle)
{
	struct shim_hdr h = { .h1 = shim_p2h(domain_handle) };
	int64_t rc = shim_rpc(SHIM_AV_INSERT, &h, uet_addr,
			      (uet_addr != NULL) ?
			      (uint32_t)sizeof(*uet_addr) : 0,
			      NULL, 0, NULL);

	if (rc < 0)
		return (int)rc;
	*addr_handle = shim_h2p(h.h2);
	return (int)rc;
}

int uet_av_remove(uet_addr_handle_t addr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(addr_handle) };

	return (int)shim_rpc(SHIM_AV_REMOVE, &h, NULL, 0, NULL, 0, NULL);
}

/* ===================================================================
 * completion queue - the hot path
 * =================================================================== */

ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf, size_t count)
{
	struct shim_hdr h = { .h1 = shim_p2h(cq_handle), .a1 = count };
	uint32_t rlen = 0;
	int64_t rc;
	size_t entry_sz, i, n;

	/*
	 * reply_payload is NULL on purpose: the reply lands in g_payload and
	 * we read it straight from there below. Passing g_payload here would
	 * make shim_rpc() memcpy it onto itself, which is undefined for
	 * memcpy's restrict-qualified arguments and pointless work on the
	 * hottest path.
	 */
	rc = shim_rpc(SHIM_CQ_READ, &h, NULL, 0, NULL, 0, &rlen);
	if (rc <= 0)
		return (ssize_t)rc;        /* 0 = nothing ready, < 0 = error */

	n = (size_t)rc;

	/* the guest declares its entry stride in a1 and the rx blob offset
	 * in a2 - see the CQ_READ line in uet_shim.h */
	entry_sz = (h.a1 != 0) ? h.a1 : sizeof(struct fi_cq_tagged_entry);

	if ((n * entry_sz) > rlen) {
		fprintf(stderr, "[shim/host] cq_read: truncated reply\n");
		return -FI_EIO;
	}

	memcpy(buf, g_payload, n * entry_sz);

	/*
	 * Translate context ids back to the application's pointers and move
	 * received bytes out of the arena.
	 *
	 * ABI 1 read them from a blob appended to this reply, which capped a
	 * receive at the mailbox size. They now live in the arena block the
	 * post reserved, so there is nothing to append and no cap.
	 */
	for (i = 0; i < n; i++) {
		struct fi_cq_tagged_entry *e =
			(struct fi_cq_tagged_entry *)
			((char *)buf + (i * entry_sz));
		struct ctx_ent ce = ctx_take((uint64_t)
					     (uintptr_t)e->op_context);
		size_t got = e->len;

		e->op_context = ce.context;           /* id -> the app's ptr */

		if (ce.rx_iov != NULL) {
			/* vectored receive: scatter across every entry, which
			 * ABI 1 could not do - it kept only iov[0] */
			uint64_t cur = 0;
			size_t k;

			for (k = 0; (k < ce.rx_iov_n) && (got > 0); k++) {
				size_t take = ce.rx_iov[k].iov_len;
				void *src;

				if (take > got)
					take = got;
				src = shim_arena_ptr(ce.a_off + cur, take);
				if (src == NULL)
					break;
				memcpy(ce.rx_iov[k].iov_base, src, take);
				cur += ce.rx_iov[k].iov_len;
				got -= take;
			}
			free(ce.rx_iov);
		} else if (ce.rx_buf != NULL) {
			size_t take = (got > ce.rx_len) ? ce.rx_len : got;
			void *src = shim_arena_ptr(ce.a_off, take);

			if ((src != NULL) && (take > 0))
				memcpy(ce.rx_buf, src, take);
		}

		/* A transient block lives exactly as long as its operation.
		 * This is the line that makes the ABI 1 send-buffer hazard
		 * structurally impossible: nothing is reused mid-flight. */
		if (ce.a_owned)
			shim_arena_free(ce.a_off);
	}

	/* A completion is the first moment the application may look at a
	 * remotely-written region, so this is where those get copied back. */
	mr_sync_in();

	return (ssize_t)n;
}

ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle,
		       struct fi_cq_err_entry *buf)
{
	struct shim_hdr h = { .h1 = shim_p2h(cq_handle) };
	int64_t rc = shim_rpc(SHIM_CQ_READERR, &h, NULL, 0,
			      buf, sizeof(*buf), NULL);

	if ((rc > 0) && (buf != NULL)) {
		struct ctx_ent ce = ctx_take((uint64_t)(uintptr_t)
					     buf->op_context);
		buf->op_context = ce.context;
	}
	return (ssize_t)rc;
}

/* ===================================================================
 * data path
 * =================================================================== */

ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = job_id,
		.a2 = len,
		.a3 = shim_p2h(dst_addr_handle),
	};

	struct stage st;
	int rc;

	/* No size cap any more: the arena is the limit, not the mailbox. */
	rc = stage_tx(buf, len, &st);
	if (rc != 0)
		return rc;

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		if (st.owned)
			shim_arena_free(st.off);
		return -FI_EAGAIN;        /* table full: a legitimate answer */
	}
	h.off = st.off;
	ctx_attach(h.a4, &st);

	return (ssize_t)shim_rpc(SHIM_SEND, &h, NULL, 0, NULL, 0, NULL);
}


ssize_t uet_sendv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  const struct iovec *iov, size_t iov_count,
		  uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle, void *context)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = job_id,
		.a2 = iov_count,
		.a3 = shim_p2h(dst_addr_handle),
	};
	struct shim_iov tbl[SHIM_MAX_IOV];
	struct stage st;
	int rc;

	/* The segment table still travels inline - it is 16 bytes an entry
	 * and at most SHIM_MAX_IOV of them. Only the DATA moved to the
	 * arena, and the offsets in tbl are now arena-relative. */
	rc = stage_iov(iov, iov_count, tbl, &st, 1);
	if (rc != 0)
		return rc;

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		shim_arena_free(st.off);
		return -FI_EAGAIN;
	}
	h.off = st.off;
	ctx_attach(h.a4, &st);

	return (ssize_t)shim_rpc(SHIM_SENDV, &h, tbl,
				 (uint32_t)(iov_count * sizeof(tbl[0])),
				 NULL, 0, NULL);
}

ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = job_id,
		.a2 = len,
		.a3 = shim_p2h(src_addr_handle),
	};

	struct stage st;
	int rc;

	/*
	 * The guest receives into an arena block; we remember both that
	 * block and the application's buffer against the context id, and
	 * uet_cq_read() copies one into the other when the completion
	 * arrives. The application's pointer never crosses.
	 */
	rc = stage_rx(buf, len, &st);
	if (rc != 0)
		return rc;

	h.a4 = ctx_get(context, buf, len);
	if (h.a4 == 0) {
		if (st.owned)
			shim_arena_free(st.off);
		return -FI_EAGAIN;
	}
	h.off = st.off;
	ctx_attach(h.a4, &st);

	return (ssize_t)shim_rpc(SHIM_RECV, &h, NULL, 0, NULL, 0, NULL);
}

ssize_t uet_tsendv(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const struct iovec *iov, size_t iov_count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle, uint64_t tag,
		   void *context)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = job_id,
		.a2 = iov_count,
		.a3 = shim_p2h(dst_addr_handle),
	};
	struct {
		struct shim_tag_args ta;
		struct shim_iov      tbl[SHIM_MAX_IOV];
	} pkt;
	struct stage st;
	int rc;

	/* tag rides in front of the segment table: a1..a4 are all spoken
	 * for, and hdr.off now carries the arena block */
	pkt.ta.tag = tag;
	pkt.ta.ignore = 0;

	rc = stage_iov(iov, iov_count, pkt.tbl, &st, 1);
	if (rc != 0)
		return rc;

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		shim_arena_free(st.off);
		return -FI_EAGAIN;
	}
	h.off = st.off;
	ctx_attach(h.a4, &st);

	return (ssize_t)shim_rpc(SHIM_TSENDV, &h, &pkt,
				 (uint32_t)(sizeof(pkt.ta) +
					    iov_count * sizeof(pkt.tbl[0])),
				 NULL, 0, NULL);
}

ssize_t uet_trecvv(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const struct iovec *iov, size_t iov_count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t src_addr_handle, uint64_t tag,
		   uint64_t ignore, void *context)
{
	struct shim_hdr h = {
		.h1 = shim_p2h(ep_handle),
		.h2 = shim_p2h(mr_handle),
		.a1 = job_id,
		.a2 = iov_count,
		.a3 = shim_p2h(src_addr_handle),
	};
	struct {
		struct shim_tag_args ta;
		struct shim_iov      tbl[SHIM_MAX_IOV];
	} pkt;
	struct iovec *keep;
	struct stage st;
	int rc;

	pkt.ta.tag = tag;
	pkt.ta.ignore = ignore;

	/* a receive sends no data, only the SHAPE of the target buffers */
	rc = stage_iov(iov, iov_count, pkt.tbl, &st, 0);
	if (rc != 0)
		return rc;

	/*
	 * ABI 1 recorded only iov[0] as the fill target, so a message
	 * scattered across several buffers silently lost everything after
	 * the first. Keeping a copy of the shape fixes that: uet_cq_read()
	 * walks it and scatters the arena block back across every entry.
	 */
	keep = iov_dup(iov, iov_count);
	if (keep == NULL) {
		shim_arena_free(st.off);
		return -FI_ENOMEM;
	}

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		shim_arena_free(st.off);
		free(keep);
		return -FI_EAGAIN;
	}
	h.off = st.off;
	ctx_attach(h.a4, &st);
	ctx_attach_iov(h.a4, keep, iov_count);

	return (ssize_t)shim_rpc(SHIM_TRECVV, &h, &pkt,
				 (uint32_t)(sizeof(pkt.ta) +
					    iov_count * sizeof(pkt.tbl[0])),
				 NULL, 0, NULL);
}

/*
 * ===================================================================
 * Not yet done, deliberately
 *
 * 1. Async events. The guest can push SHIM_EVENT_EQ / SHIM_EVENT_EQ_ERR at
 *    any time, but shim_rpc() is strictly request/response and would
 *    mistake one for a reply. A reader thread owning g_fd, dispatching
 *    replies by seq and events to g_eq_cb/g_eq_err_cb, is the fix. Not
 *    blocking: uet_provider.c passes NULL for both callbacks.
 *
 * 2. uet_cq_read() is a synchronous RPC. NCCL polls it hard and the common
 *    answer is "nothing ready", which should not leave the process at all.
 *    It should drain a host-local queue fed by the guest over a ring in the
 *    spare 15.5 MiB, making an empty poll ~100 ns instead of a round trip.
 *
 * 3. uet_mr_reg() copies the region's contents inline. Correct only for
 *    small send-side buffers; RMA needs the peer to write into OUR memory,
 *    which requires the shared-memory arena and offsets. This is the one
 *    gap that is a CORRECTNESS issue, not just performance.
 * ===================================================================
 */
