/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * Wire protocol for the uet_api.h shim boundary.
 *
 *   host  (container) : uet_provider -> uet_shim_host.c  --+
 *                                                          | transport
 *   guest (QEMU)      : uet_shim_guest.c -> uet_api.c   <--+
 *                                            (SES + PDS)
 *
 * Both sides compile this header; it IS the contract. Change it and both
 * sides must be rebuilt together, which SHIM_ABI_VERSION enforces at
 * connect time.
 *
 * Scope is the set uet_provider actually imports - derived, not chosen:
 *   nm -D --undefined-only uet_provider/libuetprov-fi.so \
 *       | grep -oE "uet_[a-z_0-9]+" | sort -u          -> 25 functions
 *
 * uet_api.h declares 89; the other 64 are unreachable from the provider
 * and are deliberately not implemented.
 */
#ifndef UET_SHIM_H
#define UET_SHIM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Only the C standard library. No libfabric, no uet headers: this file is
 * the contract and must stay readable - and compilable - without either
 * side's dependencies in scope.
 */

#define SHIM_ABI_VERSION   1u            /* bump on ANY change below */
#define SHIM_MAGIC         0x53484d31u   /* "SHM1", in every message */

/* inline payload cap for stage A; a shared-memory arena replaces this */
#define SHIM_MAX_PAYLOAD   (256u * 1024u)
#define SHIM_MAX_IOV       16            /* bounds a stack array in the guest */
#define SHIM_NAME_MAX      64
#define SHIM_AUTH_KEY_MAX  64
#define SHIM_ADDR_MAX      64            /* struct uet_addr is 32; asserted
                                          * in uet_shim_info.c, where
                                          * uet_addr.h is in scope */

/* -------------------------------------------------------------------- ops
 * Starts at 1, so a zeroed region can never look like a valid opcode.
 * Grouped in the order the provider calls them, so the enum reads like an
 * endpoint's lifecycle.
 */
enum shim_op {
	/* lifecycle */
	SHIM_INITIALIZE = 1,
	SHIM_FINALIZE,
	SHIM_GETINFO,
	SHIM_GETNAME,
	/* domain */
	SHIM_DOMAIN,
	SHIM_DOMAIN_CLOSE,
	/* endpoint */
	SHIM_ENDPOINT,
	SHIM_EP_ENABLE,
	SHIM_EP_CLOSE,
	SHIM_EP_BIND_CQ,
	SHIM_EP_BIND_MR,
	/* memory region */
	SHIM_MR_REG,
	SHIM_MR_KEY,
	SHIM_MR_ENABLE,
	SHIM_MR_DISABLE,
	SHIM_MR_CLOSE,
	/* address vector */
	SHIM_AV_INSERT,
	SHIM_AV_REMOVE,
	/* completion queue */
	SHIM_CQ_READ,
	SHIM_CQ_READERR,
	/* data path */
	SHIM_SEND,
	SHIM_SENDV,
	SHIM_RECV,
	SHIM_TSENDV,
	SHIM_TRECVV,
	/* guest -> host, unsolicited. Declared so the protocol has room for
	 * them and the gap is visible here rather than hidden in a TODO. */
	SHIM_EVENT_EQ,
	SHIM_EVENT_EQ_ERR,

	SHIM_OP_MAX
};

/* Takes uint32_t, not enum shim_op: it is called on unvalidated peer data
 * while logging a message that may be garbage. Never returns NULL. */
const char *shim_op_name(uint32_t op);

/* ---------------------------------------------------------------- handles
 * Every uet_*_handle_t is an opaque void *. The guest owns the real
 * pointers and keeps them in a table; the host hands the provider
 * (void *)(uintptr_t)index instead.
 *
 * The provider stores handles, passes them back and prints them, but never
 * dereferences one - so the host needs NO table at all. The index simply
 * round-trips. This is the single biggest simplification in the design.
 *
 * It is also a hardening win: a corrupt index becomes a bounds-checked
 * table miss in the guest, never a wild pointer.
 */
typedef uint64_t shim_handle_t;

#define SHIM_HANDLE_NONE  ((shim_handle_t)0)     /* matches UET_NULL_HANDLE */
#define shim_h2p(h)       ((void *)(uintptr_t)(h))
#define shim_p2h(p)       ((shim_handle_t)(uintptr_t)(p))

/* ---------------------------------------------------------------- fi_info
 * struct fi_info is pointer-rich - src_addr, dest_addr, fabric_attr,
 * domain_attr, ep_attr, tx_attr, rx_attr are each separately allocated -
 * so it cannot be memcpy'd across the boundary.
 *
 * This carries only the fields the stack READS. That set was enumerated
 * mechanically rather than guessed:
 *
 *   grep -ohE "info->[a-z_]+(->[a-z_]+)?" uet_api.c uet_pds*.c \
 *        util/uet_util.c | sort -u
 *
 * Add a field here if the stack ever reads another. Every pointer became
 * a fixed array or a flag.
 */
struct shim_fi_info {
	uint64_t caps;

	uint32_t src_addrlen;                     /* struct uet_addr, verbatim */
	uint32_t dest_addrlen;
	uint8_t  src_addr[SHIM_ADDR_MAX];
	uint8_t  dest_addr[SHIM_ADDR_MAX];

	char     fabric_name[SHIM_NAME_MAX];      /* fabric_attr */
	char     prov_name[SHIM_NAME_MAX];

	char     domain_name[SHIM_NAME_MAX];      /* domain_attr */
	uint64_t domain_mr_mode;
	uint64_t domain_mr_cnt;
	uint64_t domain_mr_key_size;
	uint32_t domain_auth_key_size;
	uint8_t  domain_auth_key[SHIM_AUTH_KEY_MAX];

	uint64_t ep_max_msg_size;                 /* ep_attr */
	uint32_t ep_auth_key_size;
	uint8_t  ep_auth_key[SHIM_AUTH_KEY_MAX];

	uint64_t tx_size;                         /* tx_attr */
	uint64_t tx_iov_limit;
	uint64_t tx_rma_iov_limit;
	uint64_t tx_msg_order;        /* & UET_ORDERING selects ROD over RUD */
	uint32_t tx_tclass;

	uint64_t rx_size;                         /* rx_attr */
	uint64_t rx_iov_limit;

	uint8_t  has_nic;        /* info->nic != NULL; the stack only tests it */
	uint8_t  has_next;
	uint8_t  _pad[2];        /* explicit, so the size is in the source */
};

/* An iovec entry as offset+len: a host pointer means nothing in the guest.
 * NOTE the offset is into the REQUEST PAYLOAD, not into the shared region.
 * That distinction is the whole difference between today's copy-based
 * design and the future zero-copy arena. */
struct shim_iov {
	uint64_t off;
	uint64_t len;
};

/* Tagged ops need seven values but the header carries four a* slots, so
 * these two are prepended to the payload rather than widening every
 * message by 16 bytes to serve 2 ops out of 25. */
struct shim_tag_args {
	uint64_t tag;
	uint64_t ignore;         /* trecvv only; tsendv sets 0 */
};

/* --------------------------------------------------------------- messages
 * Fixed 72-byte header, then payload_len bytes.
 *
 * Field order is deliberate: four uint32_t first fill exactly 16 bytes, so
 * every 8-byte field lands naturally aligned and there is NO implicit
 * padding. That is what lets the transport assert sizeof() == 72.
 */
struct shim_hdr {
	uint32_t magic;          /* SHIM_MAGIC, checked before anything else */
	uint32_t op;             /* the guest's switch key                   */
	uint32_t payload_len;
	uint32_t seq;            /* reply echoes it; 0 reserved for events   */
	int64_t  ret;            /* reply: >= 0 ok, < 0 -errno. int64 so a
				  * uint64 mr_key fits the same field       */
	shim_handle_t h1;        /* primary handle, IN and OUT               */
	shim_handle_t h2;        /* secondary handle (mr, addr, cq)          */
	uint64_t a1, a2, a3, a4; /* op-specific scalars                      */
};

/*
 * Per-op meaning of h1/h2/a1..a4. This block is the IDL: without it, a2
 * meaning "length" in SEND and "iov_count" in SENDV would be folklore
 * living in two .c files that could drift apart.
 *
 * INITIALIZE    out: h1 = uet handle
 * FINALIZE      in:  h1 = uet handle
 * GETINFO       in:  h1 = uet, payload = struct uet_addr node
 *               out: payload = struct shim_fi_info
 * GETNAME       in:  h1 = ep        out: payload = struct uet_addr
 * DOMAIN        in:  h1 = uet, a1 = fabric token, a2 = domain token,
 *                    a3 = context id, payload = struct shim_fi_info
 *               out: h1 = domain handle
 * DOMAIN_CLOSE  in:  h1 = domain
 * ENDPOINT      in:  h1 = domain, a1 = ep token, a2 = context id,
 *                    payload = struct shim_fi_info
 *               out: h1 = ep handle
 * EP_ENABLE     in:  h1 = ep
 * EP_CLOSE      in:  h1 = ep
 * EP_BIND_CQ    in:  h1 = ep, a1 = cq token, a2 = flags, a3 = context id,
 *                    payload = struct fi_cq_attr
 *               out: h2 = cq handle
 * EP_BIND_MR    in:  h1 = ep, h2 = mr, a1 = flags
 * MR_REG        in:  h1 = domain, a1 = len, a2 = access,
 *                    a3 = requested_key, a4 = flags, payload = contents
 *               out: h2 = mr handle
 * MR_KEY        in:  h2 = mr        out: ret = key
 * MR_ENABLE     in:  h2 = mr
 * MR_DISABLE    in:  h2 = mr
 * MR_CLOSE      in:  h2 = mr
 * AV_INSERT     in:  h1 = domain, payload = struct uet_addr
 *               out: h2 = addr handle
 * AV_REMOVE     in:  h2 = addr handle
 * CQ_READ       in:  h1 = cq, a1 = count
 *               out: ret = entries, a1 = entry stride, a2 = rx blob offset,
 *                    payload = entries then received bytes
 * CQ_READERR    in:  h1 = cq        out: payload = struct fi_cq_err_entry
 * SEND          in:  h1 = ep, h2 = mr, a1 = job_id, a2 = len,
 *                    a3 = addr handle, a4 = context id, payload = data
 * SENDV         as SEND, a2 = iov_count, payload = shim_iov[] then data
 * RECV          in:  h1 = ep, h2 = mr, a1 = job_id, a2 = len,
 *                    a3 = src addr handle, a4 = context id
 * TSENDV        as SENDV, payload prefixed by struct shim_tag_args
 * TRECVV        as TSENDV (uses .ignore too)
 * EVENT_EQ      guest -> host: a1 = context id, payload = the event
 * EVENT_EQ_ERR  guest -> host: a1 = context id, payload = the event
 */

/* -------------------------------------------------------------- transport
 * Deliberately tiny. uet_shim_host.c and uet_shim_guest.c call ONLY these
 * six, and mention neither shared memory nor sockets - which is what lets
 * the transport be replaced without touching either of them.
 *
 * connect/listen take no arguments: each transport reads its own config
 * from the environment (UET_SHIM_SHM, or a vsock cid/port), so this header
 * stays free of any one transport's vocabulary.
 *
 * The int fd is vestigial, from the vsock original. Shared memory has no
 * descriptor and returns a sentinel it then ignores.
 */
const char *shim_xport_name(void);                     /* for logs  */
int  shim_xport_connect(void);                         /* host      */
int  shim_xport_listen(void);                          /* guest     */
int  shim_xport_accept(int lfd);                       /* guest     */
void shim_xport_close(int fd);

int  shim_send_msg(int fd, const struct shim_hdr *h, const void *payload);
int  shim_recv_msg(int fd, struct shim_hdr *h, void *payload,
		   size_t payload_cap);

#endif /* UET_SHIM_H */
