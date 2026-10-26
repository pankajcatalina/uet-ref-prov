/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * GUEST side of the shim. An ordinary userspace process inside the QEMU
 * guest that drives the real UET stack - uet_api.c (SES), uet_pds*.c (PDS),
 * uet_sec.c - on behalf of uet_provider running in the container.
 *
 *     host: uet_provider -> uet_shim_host  --shared mem-->  THIS -> uet_api.c
 *                                                                      |
 *                                                               nic_shim -> wire
 *
 * Build it against libuet_fabric.so exactly as ./uet is, and run it with
 * the same environment the stack expects:
 *
 *     UET_IFNAME=enp0s3 UET_PDS=pds sudo -E ./uet_shim_guest
 *
 * Note the SHAPE difference from the host side: the host needs 25 separate
 * FUNCTIONS because the linker demands 25 distinct symbols. This side needs
 * one switch, because it dispatches on an integer.
 *
 * It owns two tables, and the reason there are two is symmetry:
 *
 *   hdl_tbl  pointers THIS side owns (real uet_*_handle_t values). Only an
 *            index crosses, so a corrupt id can never become a pointer
 *            dereference here.
 *
 *   rx_tbl   buffers allocated on the host's behalf by RECV/TRECVV. The
 *            host cannot hand us memory, so we allocate locally and ship
 *            the bytes back with the completion.
 *
 * The host keeps the mirror-image table for the pointers IT owns
 * (the application's void *context).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/uio.h>

#include "uet_api.h"
#include "uet_shim.h"
#include "uet_shim_info.h"

static int g_verbose = 1;

#define LOG(...)                                            \
	do {                                                \
		if (g_verbose) {                            \
			fprintf(stderr, "[shim/guest] ");   \
			fprintf(stderr, __VA_ARGS__);       \
			fflush(stderr);                     \
		}                                           \
	} while (0)

/* ------------------------------------------------------------ handle table
 * The host only ever sees indices. Index 0 is reserved for "none", matching
 * SHIM_HANDLE_NONE and UET_NULL_HANDLE.
 */
#define HDL_MAX 1024

static void *hdl_tbl[HDL_MAX];
static uint64_t hdl_next = 1;

static shim_handle_t hdl_put(void *p)
{
	uint64_t i;

	if (p == NULL)
		return SHIM_HANDLE_NONE;

	/* search forward from the last allocation, then wrap: a cheap
	 * allocator that reuses freed slots without a free list */
	for (i = hdl_next; i < HDL_MAX; i++) {
		if (hdl_tbl[i] == NULL) {
			hdl_tbl[i] = p;
			hdl_next = i + 1;
			return (shim_handle_t)i;
		}
	}
	for (i = 1; i < hdl_next; i++) {
		if (hdl_tbl[i] == NULL) {
			hdl_tbl[i] = p;
			hdl_next = i + 1;
			return (shim_handle_t)i;
		}
	}
	LOG("handle table full (%d live objects)\n", HDL_MAX);
	return SHIM_HANDLE_NONE;
}

/*
 * The bounds check is the security property, not just hygiene: a corrupt or
 * hostile index yields NULL and the stack returns an error. Had real
 * pointers travelled on the wire, the same value would be a dereference of
 * memory the peer chose.
 */
static void *hdl_get(shim_handle_t h)
{
	if ((h == SHIM_HANDLE_NONE) || (h >= HDL_MAX))
		return NULL;
	return hdl_tbl[h];
}

static void hdl_del(shim_handle_t h)
{
	if ((h != SHIM_HANDLE_NONE) && (h < HDL_MAX)) {
		hdl_tbl[h] = NULL;
		if (h < hdl_next)
			hdl_next = h;         /* rewind so the slot is reused */
	}
}

/* --------------------------------------------------------------- rx table
 * Receive buffers we allocated for the host, keyed by the host's CONTEXT
 * ID. The completion carries that id back as op_context, so the lookup
 * needs no extra bookkeeping - the key is already in the data.
 */
#define RX_MAX 4096

struct rx_ent {
	void  *buf;
	size_t len;
};

static struct rx_ent rx_tbl[RX_MAX];

static void *rx_alloc(uint64_t ctx_id, size_t len)
{
	if ((ctx_id == 0) || (ctx_id >= RX_MAX))
		return NULL;

	free(rx_tbl[ctx_id].buf);             /* a re-post reuses the slot */
	rx_tbl[ctx_id].buf = calloc(1, (len > 0) ? len : 1);
	rx_tbl[ctx_id].len = len;
	return rx_tbl[ctx_id].buf;
}

/* get and clear in one step: a completion consumes the operation */
static struct rx_ent rx_take(uint64_t ctx_id)
{
	struct rx_ent e = { 0 };

	if ((ctx_id == 0) || (ctx_id >= RX_MAX))
		return e;
	e = rx_tbl[ctx_id];
	rx_tbl[ctx_id].buf = NULL;
	rx_tbl[ctx_id].len = 0;
	return e;
}

/* ------------------------------------------------------------- eq events
 * The stack wants function pointers, which cannot cross a process
 * boundary. We give it these, which forward the event to the host where
 * the provider's own callbacks live.
 *
 * NOT YET WIRED UP on the host: shim_rpc() is strict request/response and
 * would mistake an unsolicited event for a reply. Not blocking, because
 * uet_provider.c passes NULL for both callbacks.
 */
static int g_conn_fd = -1;

static void push_event(uint32_t op, uint64_t ctx_id,
		       const void *body, uint32_t body_len)
{
	struct shim_hdr h = {
		.op = op,
		.seq = 0,                 /* 0 marks it unsolicited */
		.a1 = ctx_id,
		.payload_len = body_len,
	};

	if (g_conn_fd < 0)
		return;
	if (shim_send_msg(g_conn_fd, &h, body) != 0)
		LOG("failed to push %s\n", shim_op_name(op));
}

static void guest_eq_cb(uet_handle_t handle, struct fi_eq_entry *e)
{
	(void)handle;
	if (e == NULL)
		return;
	LOG("eq event, data=0x%llx\n", (unsigned long long)e->data);
	/* e->context is the id the host gave us; it travels in a1 so the
	 * host can map it back to the application's real pointer */
	push_event(SHIM_EVENT_EQ, (uint64_t)(uintptr_t)e->context,
		   e, (uint32_t)sizeof(*e));
}

static void guest_eq_err_cb(uet_handle_t handle, struct fi_eq_err_entry *e)
{
	(void)handle;
	if (e == NULL)
		return;
	LOG("eq ERROR event, err=%d prov_errno=%d\n", e->err, e->prov_errno);
	/*
	 * err_data is a pointer into the stack's memory and cannot cross the
	 * boundary; the host must treat it as invalid. If err_data ever
	 * carries something the provider needs, append err_data_size bytes
	 * after the struct and fix it up on the far side.
	 */
	push_event(SHIM_EVENT_EQ_ERR, (uint64_t)(uintptr_t)e->context,
		   e, (uint32_t)sizeof(*e));
}

/* ================================================================
 * dispatch
 *
 * g_in and g_out are process-LOCAL staging buffers, not the shared region.
 * shim_recv_msg copies the payload out of the mailbox into g_in, and that
 * is why shim_iov offsets are relative to the payload blob rather than to
 * the region - the distinction the MR arena will change.
 * ================================================================ */

static char g_in[SHIM_MAX_PAYLOAD];
static char g_out[SHIM_MAX_PAYLOAD];

static void handle_one(const struct shim_hdr *req, struct shim_hdr *rsp)
{
	memset(rsp, 0, sizeof(*rsp));
	rsp->op = req->op;
	rsp->seq = req->seq;              /* echo it: the host matches on this */
	rsp->ret = -EINVAL;

	switch (req->op) {

	/* ------------------------------------------------- lifecycle */
	case SHIM_INITIALIZE: {
		uet_handle_t uh = NULL;

		rsp->ret = uet_initialize(&uh);
		if (rsp->ret == 0)
			rsp->h1 = hdl_put(uh);
		break;
	}

	case SHIM_FINALIZE:
		rsp->ret = uet_finalize(hdl_get(req->h1));
		hdl_del(req->h1);
		break;

	case SHIM_GETINFO: {
		struct fi_info *info = NULL;
		struct uet_addr *node =
			(req->payload_len >= sizeof(struct uet_addr)) ?
			(struct uet_addr *)g_in : NULL;

		/* hints is passed as NULL: uet_getinfo() carries a literal
		 * "need to process hints" TODO and ignores them today */
		rsp->ret = uet_getinfo(hdl_get(req->h1), node, NULL, &info);
		if (rsp->ret == 0) {
			shim_info_flatten(info,
					  (struct shim_fi_info *)g_out);
			rsp->payload_len = sizeof(struct shim_fi_info);
			/* the stack keeps its own copy; ours is done with */
		}
		break;
	}

	case SHIM_GETNAME:
		rsp->ret = uet_getname(hdl_get(req->h1),
				       (struct uet_addr *)g_out);
		if (rsp->ret == 0)
			rsp->payload_len = sizeof(struct uet_addr);
		break;

	/* ---------------------------------------------------- domain */
	case SHIM_DOMAIN: {
		uet_domain_handle_t dh = NULL;
		struct fi_info *info =
			shim_info_build((struct shim_fi_info *)g_in);

		if (info == NULL) {
			rsp->ret = -ENOMEM;
			break;
		}
		/*
		 * a1/a2 are the host's fid_fabric and fid_domain tokens.
		 * uet_domain() STORES them and never dereferences them, so
		 * passing the token value through is safe and keeps the
		 * association intact. Verified; if that ever changes, this
		 * breaks and this comment is where to look.
		 */
		rsp->ret = uet_domain(hdl_get(req->h1),
				      (struct fid_fabric *)(uintptr_t)req->a1,
				      info,
				      (struct fid_domain *)(uintptr_t)req->a2,
				      (void *)(uintptr_t)req->a3,
				      guest_eq_cb, guest_eq_err_cb, &dh);
		if (rsp->ret == 0)
			rsp->h1 = hdl_put(dh);
		else
			fi_freeinfo(info);    /* the stack did not take it */
		break;
	}

	case SHIM_DOMAIN_CLOSE:
		rsp->ret = uet_domain_close(hdl_get(req->h1));
		hdl_del(req->h1);
		break;

	/* -------------------------------------------------- endpoint */
	case SHIM_ENDPOINT: {
		uet_ep_handle_t eh = NULL;
		struct fi_info *info =
			shim_info_build((struct shim_fi_info *)g_in);

		if (info == NULL) {
			rsp->ret = -ENOMEM;
			break;
		}
		rsp->ret = uet_endpoint(hdl_get(req->h1), info,
					(struct fid_ep *)(uintptr_t)req->a1,
					(void *)(uintptr_t)req->a2, &eh);
		if (rsp->ret == 0)
			rsp->h1 = hdl_put(eh);
		else
			fi_freeinfo(info);
		break;
	}

	case SHIM_EP_ENABLE:
		rsp->ret = uet_ep_enable(hdl_get(req->h1));
		break;

	case SHIM_EP_CLOSE:
		rsp->ret = uet_ep_close(hdl_get(req->h1));
		hdl_del(req->h1);
		break;

	case SHIM_EP_BIND_CQ: {
		uet_cq_handle_t ch = NULL;
		struct fi_cq_attr *attr =
			(req->payload_len >= sizeof(struct fi_cq_attr)) ?
			(struct fi_cq_attr *)g_in : NULL;

		rsp->ret = uet_ep_bind_cq(hdl_get(req->h1), attr,
					  (struct fid_cq *)(uintptr_t)req->a1,
					  req->a2,
					  (void *)(uintptr_t)req->a3, &ch);
		if (rsp->ret == 0)
			rsp->h2 = hdl_put(ch);
		break;
	}

	case SHIM_EP_BIND_MR:
		rsp->ret = uet_ep_bind_mr(hdl_get(req->h1),
					  hdl_get(req->h2), req->a1);
		break;

	/* -------------------------------------------- memory region */
	case SHIM_MR_REG: {
		uet_mr_handle_t mh = NULL;
		size_t len = req->a1;
		void *buf;

		/*
		 * Stage A: the host shipped the region's CONTENTS inline, so
		 * we register a local copy. Correct only for small send-side
		 * buffers - RMA needs the peer to write into the HOST's
		 * memory, which an inline copy cannot express. Stage B
		 * registers an offset into the shared arena instead.
		 */
		buf = calloc(1, (len > 0) ? len : 1);
		if (buf == NULL) {
			rsp->ret = -ENOMEM;
			break;
		}
		if (req->payload_len > 0) {
			size_t n = (req->payload_len > len) ?
				   len : req->payload_len;
			memcpy(buf, g_in, n);
		}
		rsp->ret = uet_mr_reg(hdl_get(req->h1), buf, len,
				      req->a2, req->a3, req->a4, NULL, &mh);
		if (rsp->ret == 0)
			rsp->h2 = hdl_put(mh);
		else
			free(buf);            /* otherwise the stack owns it */
		break;
	}

	case SHIM_MR_KEY:
		/* the only op whose result rides in ret: uet_mr_key()
		 * returns uint64_t and has no error channel */
		rsp->ret = (int64_t)uet_mr_key(hdl_get(req->h2));
		break;

	case SHIM_MR_ENABLE:
		rsp->ret = uet_mr_enable(hdl_get(req->h2));
		break;

	case SHIM_MR_DISABLE:
		rsp->ret = uet_mr_disable(hdl_get(req->h2));
		break;

	case SHIM_MR_CLOSE:
		rsp->ret = uet_mr_close(hdl_get(req->h2));
		hdl_del(req->h2);
		break;

	/* -------------------------------------------- address vector */
	case SHIM_AV_INSERT: {
		uet_addr_handle_t ah = NULL;

		if (req->payload_len < sizeof(struct uet_addr)) {
			rsp->ret = -EINVAL;
			break;
		}
		rsp->ret = uet_av_insert(hdl_get(req->h1),
					 (struct uet_addr *)g_in, &ah);
		if (rsp->ret == 0)
			rsp->h2 = hdl_put(ah);
		break;
	}

	case SHIM_AV_REMOVE:
		rsp->ret = uet_av_remove(hdl_get(req->h2));
		hdl_del(req->h2);
		break;

	/* ------------------------------------------ completion queue */
	case SHIM_CQ_READ: {
		size_t want = req->a1;
		size_t entry_sz = sizeof(struct fi_cq_tagged_entry);
		/* reserve half the buffer for the rx blob appended below */
		size_t max_ent = (SHIM_MAX_PAYLOAD / 2) / entry_sz;
		ssize_t n;

		if (want > max_ent)
			want = max_ent;

		n = uet_cq_read(hdl_get(req->h1), g_out, want);
		rsp->ret = n;
		if (n <= 0)
			break;

		/*
		 * Reply layout:
		 *   [ n x fi_cq_tagged_entry ][ received bytes ]
		 *
		 * The host cannot give us its receive buffer, so the bytes
		 * ride back WITH the completion. a1 tells the host the entry
		 * stride and a2 where the blob starts.
		 */
		{
			size_t off = (size_t)n * entry_sz;
			ssize_t i;

			for (i = 0; i < n; i++) {
				struct fi_cq_tagged_entry *e =
					(struct fi_cq_tagged_entry *)
					(g_out + ((size_t)i * entry_sz));
				uint64_t ctx_id =
					(uint64_t)(uintptr_t)e->op_context;
				struct rx_ent re = rx_take(ctx_id);
				size_t take;

				if (re.buf == NULL)
					continue;     /* a send completion */

				take = e->len;
				if (take > re.len)
					take = re.len;
				if ((off + take) > SHIM_MAX_PAYLOAD)
					take = SHIM_MAX_PAYLOAD - off;
				if (take > 0) {
					memcpy(g_out + off, re.buf, take);
					off += take;
				}
				free(re.buf);
			}

			rsp->a1 = entry_sz;
			rsp->a2 = (size_t)n * entry_sz;
			rsp->payload_len = (uint32_t)off;
		}
		break;
	}

	case SHIM_CQ_READERR:
		rsp->ret = uet_cq_readerr(hdl_get(req->h1),
					  (struct fi_cq_err_entry *)g_out);
		if (rsp->ret > 0)
			rsp->payload_len = sizeof(struct fi_cq_err_entry);
		break;

	/* ------------------------------------------------- data path */
	case SHIM_SEND:
		rsp->ret = uet_send(hdl_get(req->h1), (uint32_t)req->a1,
				    g_in, req->a2, hdl_get(req->h2),
				    hdl_get(req->a3),
				    (void *)(uintptr_t)req->a4);
		break;

	case SHIM_SENDV: {
		struct shim_iov *tbl = (struct shim_iov *)g_in;
		struct iovec iov[SHIM_MAX_IOV];
		size_t cnt = req->a2, i;

		/* bounds the stack array above: without this the peer
		 * controls how far we write */
		if (cnt > SHIM_MAX_IOV) {
			rsp->ret = -EINVAL;
			break;
		}
		for (i = 0; i < cnt; i++) {
			iov[i].iov_base = g_in + tbl[i].off;
			iov[i].iov_len = tbl[i].len;
		}
		rsp->ret = uet_sendv(hdl_get(req->h1), (uint32_t)req->a1,
				     iov, cnt, hdl_get(req->h2),
				     hdl_get(req->a3),
				     (void *)(uintptr_t)req->a4);
		break;
	}

	case SHIM_RECV: {
		void *buf = rx_alloc(req->a4, req->a2);

		if (buf == NULL) {
			rsp->ret = -ENOMEM;
			break;
		}
		rsp->ret = uet_recv(hdl_get(req->h1), (uint32_t)req->a1,
				    buf, req->a2, hdl_get(req->h2),
				    hdl_get(req->a3),
				    (void *)(uintptr_t)req->a4);
		break;
	}

	case SHIM_TSENDV: {
		struct shim_tag_args *ta = (struct shim_tag_args *)g_in;
		struct shim_iov *tbl =
			(struct shim_iov *)(g_in + sizeof(*ta));
		struct iovec iov[SHIM_MAX_IOV];
		size_t cnt = req->a2, i;

		if (cnt > SHIM_MAX_IOV) {
			rsp->ret = -EINVAL;
			break;
		}
		for (i = 0; i < cnt; i++) {
			iov[i].iov_base = g_in + sizeof(*ta) + tbl[i].off;
			iov[i].iov_len = tbl[i].len;
		}
		rsp->ret = uet_tsendv(hdl_get(req->h1), (uint32_t)req->a1,
				      iov, cnt, hdl_get(req->h2),
				      hdl_get(req->a3), ta->tag,
				      (void *)(uintptr_t)req->a4);
		break;
	}

	case SHIM_TRECVV: {
		struct shim_tag_args *ta = (struct shim_tag_args *)g_in;
		struct shim_iov *tbl =
			(struct shim_iov *)(g_in + sizeof(*ta));
		struct iovec iov[SHIM_MAX_IOV];
		size_t cnt = req->a2, i, total = 0;
		char *buf;

		if (cnt > SHIM_MAX_IOV) {
			rsp->ret = -EINVAL;
			break;
		}
		for (i = 0; i < cnt; i++)
			total += tbl[i].len;

		buf = rx_alloc(req->a4, total);
		if (buf == NULL) {
			rsp->ret = -ENOMEM;
			break;
		}
		for (i = 0; i < cnt; i++) {
			iov[i].iov_base = buf + tbl[i].off;
			iov[i].iov_len = tbl[i].len;
		}
		rsp->ret = uet_trecvv(hdl_get(req->h1), (uint32_t)req->a1,
				      iov, cnt, hdl_get(req->h2),
				      hdl_get(req->a3), ta->tag, ta->ignore,
				      (void *)(uintptr_t)req->a4);
		break;
	}

	default:
		/* reject rather than fall through: an opcode we do not know
		 * means the peer was built from a different header */
		LOG("unknown op %u\n", req->op);
		rsp->ret = -ENOSYS;
		break;
	}
}

/* ================================================================
 * main
 * ================================================================ */

/* Ctrl-C otherwise terminates without running .fini_array, so the stack's
 * [PDS] counter summary never prints. exit() makes it an orderly shutdown. */
static void on_sigint(int s)
{
	(void)s;
	fprintf(stderr, "\n[shim/guest] interrupted, exiting cleanly\n");
	exit(0);
}

int main(int argc, char **argv)
{
	int lfd, fd;

	if ((argc > 1) && (strcmp(argv[1], "-q") == 0))
		g_verbose = 0;

	if (getenv("UET_IFNAME") == NULL) {
		fprintf(stderr, "[shim/guest] UET_IFNAME is not set - the "
				"stack will fail to open its raw socket\n");
		return 1;
	}

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	lfd = shim_xport_listen();
	if (lfd < 0)
		return 1;

	LOG("ready on %s (ifname=%s pds=%s)\n",
	    shim_xport_name(), getenv("UET_IFNAME"),
	    getenv("UET_PDS") ? getenv("UET_PDS") : "sng");

	/* Re-accept after each host disconnect, so the container can be
	 * rerun repeatedly without touching the VM. */
	for (;;) {
		struct shim_hdr req, rsp;
		unsigned long calls = 0;

		LOG("waiting for the host shim...\n");
		fd = shim_xport_accept(lfd);
		if (fd < 0)
			continue;
		g_conn_fd = fd;
		LOG("host connected\n");

		for (;;) {
			int rc = shim_recv_msg(fd, &req, g_in, sizeof(g_in));

			if (rc != 0) {
				LOG("disconnected: %s\n", strerror(-rc));
				break;
			}
			calls++;
			/* log the first 64 calls: enough to see the whole
			 * setup sequence without drowning a long data run */
			if (g_verbose && (calls <= 64))
				LOG("<- %-12s h1=%llu h2=%llu len=%u\n",
				    shim_op_name(req.op),
				    (unsigned long long)req.h1,
				    (unsigned long long)req.h2,
				    req.payload_len);

			handle_one(&req, &rsp);

			if (shim_send_msg(fd, &rsp, g_out) != 0) {
				LOG("reply failed\n");
				break;
			}
		}

		g_conn_fd = -1;
		shim_xport_close(fd);
		LOG("connection closed after %lu calls\n", calls);
	}
	return 0;
}
