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
	fprintf(stderr, "[shim/host] connected over %s\n", shim_xport_name());
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
	int    used;
	void  *context;          /* the application's pointer, never sent */
	void  *rx_buf;           /* uet_recv target, NULL for sends       */
	size_t rx_len;
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
	uint32_t in_len = 0;
	int64_t rc;

	h.a1 = len;
	h.a2 = access;
	h.a3 = requested_key;
	h.a4 = flags;

	/*
	 * Stage A copies the region's current CONTENTS across so the guest
	 * has something to register. That is wrong for anything large, and
	 * wrong in principle for RMA, where the peer writes into OUR memory
	 * - which shipping a copy cannot express. Stage B replaces this with
	 * a shadow buffer in the shared-memory arena and sends an OFFSET.
	 */
	if ((buf != NULL) && (len > 0) && (len <= SHIM_MAX_PAYLOAD))
		in_len = (uint32_t)len;
	else if (len > SHIM_MAX_PAYLOAD)
		fprintf(stderr, "[shim/host] mr_reg: %zu bytes exceeds the "
				"%u inline cap; registering WITHOUT contents\n",
			len, SHIM_MAX_PAYLOAD);

	(void)context;   /* mr context is not reported through the CQ */

	rc = shim_rpc(SHIM_MR_REG, &h, buf, in_len, NULL, 0, NULL);
	if (rc < 0)
		return (int)rc;
	*mr_handle = shim_h2p(h.h2);
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

	return (int)shim_rpc(SHIM_MR_DISABLE, &h, NULL, 0, NULL, 0, NULL);
}

int uet_mr_close(uet_mr_handle_t mr_handle)
{
	struct shim_hdr h = { .h2 = shim_p2h(mr_handle) };

	return (int)shim_rpc(SHIM_MR_CLOSE, &h, NULL, 0, NULL, 0, NULL);
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
	 * Translate context ids back to the application's pointers, and copy
	 * any received bytes into the buffer uet_recv() recorded.
	 */
	{
		char *rx = g_payload + h.a2;
		size_t rx_left = (h.a2 <= rlen) ? (rlen - h.a2) : 0;

		for (i = 0; i < n; i++) {
			struct fi_cq_tagged_entry *e =
				(struct fi_cq_tagged_entry *)
				((char *)buf + (i * entry_sz));
			struct ctx_ent ce = ctx_take((uint64_t)
						     (uintptr_t)e->op_context);

			e->op_context = ce.context;   /* id -> the app's ptr */

			if (ce.rx_buf != NULL) {      /* a receive completion */
				size_t take = e->len;

				if (take > ce.rx_len)
					take = ce.rx_len;
				if (take > rx_left)
					take = rx_left;
				if (take > 0) {
					memcpy(ce.rx_buf, rx, take);
					rx += take;
					rx_left -= take;
				}
			}
		}
	}

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

	if (len > SHIM_MAX_PAYLOAD)
		return -FI_EMSGSIZE;

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0)
		return -FI_EAGAIN;        /* table full: a legitimate answer */

	return (ssize_t)shim_rpc(SHIM_SEND, &h, buf, (uint32_t)len,
				 NULL, 0, NULL);
}

/*
 * Flatten an iovec into [shim_iov table][data] and return the total bytes.
 * Returns 0 on overflow, which callers turn into -FI_EMSGSIZE.
 * iov_base is a HOST address, so only the offset and length can travel.
 */
static uint32_t pack_iov(const struct iovec *iov, size_t iov_count,
			 char *out, size_t out_cap, size_t *data_len)
{
	struct shim_iov *tbl = (struct shim_iov *)out;
	size_t tbl_sz = iov_count * sizeof(struct shim_iov);
	size_t off = tbl_sz;
	size_t i;

	*data_len = 0;
	if (iov_count > SHIM_MAX_IOV)
		return 0;

	for (i = 0; i < iov_count; i++) {
		if ((off + iov[i].iov_len) > out_cap)
			return 0;
		tbl[i].off = off;
		tbl[i].len = iov[i].iov_len;
		memcpy(out + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
		*data_len += iov[i].iov_len;
	}
	return (uint32_t)off;
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
	char *pkt;
	uint32_t pkt_len;
	size_t data_len;

	pkt = malloc(SHIM_MAX_PAYLOAD);
	if (pkt == NULL)
		return -FI_ENOMEM;

	pkt_len = pack_iov(iov, iov_count, pkt, SHIM_MAX_PAYLOAD, &data_len);
	if (pkt_len == 0) {
		free(pkt);
		return -FI_EMSGSIZE;
	}

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		free(pkt);
		return -FI_EAGAIN;
	}

	{
		ssize_t rc = (ssize_t)shim_rpc(SHIM_SENDV, &h, pkt, pkt_len,
					       NULL, 0, NULL);
		free(pkt);
		return rc;
	}
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

	/*
	 * No payload goes out: the guest cannot write into our buffer, so we
	 * remember it against the context id here and uet_cq_read() fills it
	 * when the completion for this receive comes back.
	 */
	h.a4 = ctx_get(context, buf, len);
	if (h.a4 == 0)
		return -FI_EAGAIN;

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
	struct shim_tag_args *ta;
	char *pkt;
	uint32_t pkt_len;
	size_t data_len;

	pkt = malloc(SHIM_MAX_PAYLOAD);
	if (pkt == NULL)
		return -FI_ENOMEM;

	/* tag rides in front of the payload: a1..a4 are all spoken for */
	ta = (struct shim_tag_args *)pkt;
	ta->tag = tag;
	ta->ignore = 0;

	pkt_len = pack_iov(iov, iov_count, pkt + sizeof(*ta),
			   SHIM_MAX_PAYLOAD - sizeof(*ta), &data_len);
	if (pkt_len == 0) {
		free(pkt);
		return -FI_EMSGSIZE;
	}
	pkt_len += (uint32_t)sizeof(*ta);

	h.a4 = ctx_get(context, NULL, 0);
	if (h.a4 == 0) {
		free(pkt);
		return -FI_EAGAIN;
	}

	{
		ssize_t rc = (ssize_t)shim_rpc(SHIM_TSENDV, &h, pkt, pkt_len,
					       NULL, 0, NULL);
		free(pkt);
		return rc;
	}
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
	struct shim_tag_args ta = { .tag = tag, .ignore = ignore };
	struct shim_iov tbl[SHIM_MAX_IOV];
	char pkt[sizeof(ta) + sizeof(tbl)];
	size_t i, total = 0;

	if (iov_count > SHIM_MAX_IOV)
		return -FI_EMSGSIZE;

	/* a receive sends no data, only the SHAPE of the target buffers */
	for (i = 0; i < iov_count; i++) {
		tbl[i].off = total;
		tbl[i].len = iov[i].iov_len;
		total += iov[i].iov_len;
	}

	memcpy(pkt, &ta, sizeof(ta));
	memcpy(pkt + sizeof(ta), tbl, iov_count * sizeof(tbl[0]));

	/*
	 * LIMITATION: only the first iov entry is recorded as the fill
	 * target. Scattering a received message back across several host
	 * buffers needs the iov shape kept in the ctx table - a stage B item,
	 * and harmless while the provider uses single-entry iovecs.
	 */
	h.a4 = ctx_get(context, (iov_count > 0) ? iov[0].iov_base : NULL,
		       (iov_count > 0) ? iov[0].iov_len : 0);
	if (h.a4 == 0)
		return -FI_EAGAIN;

	return (ssize_t)shim_rpc(SHIM_TRECVV, &h, pkt,
				 (uint32_t)(sizeof(ta) +
					    iov_count * sizeof(tbl[0])),
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
