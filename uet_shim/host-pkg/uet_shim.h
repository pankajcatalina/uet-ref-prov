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

#define SHIM_ABI_VERSION   4u            /* bump on ANY change below */
#define SHIM_MAGIC         0x53484d31u   /* "SHM1", in every message */

/*
 * Two ways for bulk data to cross, and the difference matters:
 *
 *   inline  - copied into the mailbox, capped at SHIM_MAX_PAYLOAD. Fine for
 *             control structures, which are small and short-lived.
 *   arena   - a byte range of the shared region that BOTH sides address, the
 *             host by pointer and the guest by the same offset. Nothing is
 *             copied across, so there is no size cap beyond the region, the
 *             buffer outlives the call (which inline data cannot - the
 *             mailbox is reused by the next message), and a peer's RMA write
 *             lands in memory the host can actually read.
 *
 * ABI 1 had only the inline path. That capped a message at 256 KiB, made
 * uet_mr_reg() register a guest-local COPY - so RMA and atomics could not
 * work at all - and left send buffers pointing at a mailbox that the next
 * request overwrote.
 *
 * hdr.off carries the arena offset. Zero means "not in the arena", so the
 * first arena byte is never handed out.
 */
#define SHIM_MAX_PAYLOAD   (256u * 1024u)
#define SHIM_ARENA_ALIGN   64u           /* cache line, so two blocks in
                                          * flight never false-share */
/*
 * Must be at least UET_IOV_LIMIT (uet_api_private.h: 64), which is what the
 * stack itself allows. 16 was enough for the provider - it uses
 * single-entry iovecs - but uet.c's iov_mode splits a message into up to 64
 * randomly sized segments, and stage_iov() rejected the whole operation
 * with -FI_EINVAL, so iov_mode never started.
 *
 * The cost is stack: the guest holds iovec[SHIM_MAX_IOV] (1 KiB at 64) and
 * the host a shim_iov[] table of the same count, both well inside a frame.
 */
#define SHIM_MAX_IOV       64
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
	SHIM_PROGRESS,
	/* endpoint */
	SHIM_ENDPOINT,
	SHIM_EP_ENABLE,
	SHIM_EP_CLOSE,
	SHIM_EP_BIND_CQ,
	SHIM_EP_BIND_MR,
	/* memory region */
	SHIM_MR_REG,
	SHIM_MR_REGV,
	SHIM_MR_REG_PBL,
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
	SHIM_CQ_CLOSE,
	/* data path - messaging */
	SHIM_SEND,
	SHIM_SENDV,
	SHIM_RECV,
	SHIM_RECVV,
	SHIM_TSEND,
	SHIM_TSENDV,
	SHIM_TRECV,
	SHIM_TRECVV,
	/* data path - RMA. The provider imports none of these; uet.c's RMA
	 * and atomic test sections do, which is how the shim gets exercised
	 * by the stack's own 100-iteration validator rather than by a test
	 * I wrote myself. */
	SHIM_WRITE,
	SHIM_WRITESEG,
	SHIM_WRITE_SYNC,
	SHIM_READ,
	SHIM_READSEG,
	/* data path - atomics */
	SHIM_ATOMIC,
	SHIM_FETCH_ATOMIC,
	SHIM_COMPARE_ATOMIC,
	SHIM_QUERY_ATOMIC,
	SHIM_ATOMIC_SYNC,
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
	uint64_t mode;
	uint32_t addr_format;
	uint32_t _pad_top;

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
	/*
	 * The REST of domain_attr. None of it is read by the stack, which is
	 * why ABI 3 and earlier omitted it - the field set was derived by
	 * grepping uet_api.c for "info->". But the provider and the NCCL
	 * plugin above it read these, and a zero is a meaningful WRONG answer:
	 * cq_data_size == 0 made aws-ofi-nccl reject its RDMA protocol with
	 * "Provider does not support 4 bytes of immediate data" and then fail
	 * initialisation outright.
	 *
	 * So the whole scalar surface crosses now, read by us or not.
	 */
	uint64_t domain_caps;
	uint64_t domain_mode;
	uint64_t domain_cq_data_size;
	uint64_t domain_cq_cnt;
	uint64_t domain_ep_cnt;
	uint64_t domain_tx_ctx_cnt;
	uint64_t domain_rx_ctx_cnt;
	uint64_t domain_max_ep_tx_ctx;
	uint64_t domain_max_ep_rx_ctx;
	uint64_t domain_cntr_cnt;
	uint64_t domain_mr_iov_limit;
	uint64_t domain_max_err_data;
	uint32_t domain_threading;
	uint32_t domain_control_progress;
	uint32_t domain_data_progress;
	uint32_t domain_resource_mgmt;
	uint32_t domain_av_type;
	uint32_t domain_tclass;

	uint64_t ep_max_msg_size;                 /* ep_attr */
	uint32_t ep_auth_key_size;
	uint8_t  ep_auth_key[SHIM_AUTH_KEY_MAX];
	uint32_t ep_type;                 /* enum fi_ep_type */
	uint32_t ep_protocol;
	uint32_t ep_protocol_version;
	uint32_t ep_tx_ctx_cnt;
	uint32_t ep_rx_ctx_cnt;
	uint32_t _pad_ep;
	uint64_t ep_msg_prefix_size;
	uint64_t ep_max_order_raw_size;
	uint64_t ep_max_order_war_size;
	uint64_t ep_max_order_waw_size;
	uint64_t ep_mem_tag_format;

	uint64_t tx_size;                         /* tx_attr */
	uint64_t tx_iov_limit;
	uint64_t tx_rma_iov_limit;
	uint64_t tx_msg_order;        /* & UET_ORDERING selects ROD over RUD */
	uint32_t tx_tclass;
	uint32_t _pad_tx;
	uint64_t tx_caps;
	uint64_t tx_mode;
	uint64_t tx_op_flags;
	uint64_t tx_comp_order;
	uint64_t tx_inject_size;

	uint64_t rx_size;                         /* rx_attr */
	uint64_t rx_iov_limit;
	uint64_t rx_caps;
	uint64_t rx_mode;
	uint64_t rx_op_flags;
	uint64_t rx_comp_order;
	uint64_t rx_total_buffered_recv;

	/*
	 * info->nic. The PROVIDER only ever tests this for NULL, which is why
	 * ABI 1 carried a single byte. uet.c dereferences it all the way down
	 * - info->nic->device_attr->name, ->link_attr->network_type, and so
	 * on - and segfaulted on the byte. Carrying the leaf values is enough:
	 * nothing reads any other part of a fid_nic.
	 */
	uint8_t  has_nic;
	uint8_t  has_next;
	uint8_t  _pad[2];        /* explicit, so the size is in the source */

	char     nic_dev_name[SHIM_NAME_MAX];     /* device_attr->name     */
	char     nic_net_type[SHIM_NAME_MAX];     /* link_attr->network_type */
	char     nic_address[SHIM_NAME_MAX];      /* link_attr->address    */
	uint64_t nic_mtu;
	uint64_t nic_speed;
	uint32_t nic_state;                       /* enum fi_link_state    */
	uint32_t _pad2;
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

/*
 * RMA and atomics take more arguments than h1/h2/a1-a4 can hold - uet_write()
 * alone has nine - so the surplus travels as a fixed struct at the front of
 * the payload, the same trick shim_tag_args uses for tagged messaging.
 */
struct shim_rma_args {
	uint64_t remote_addr;
	uint64_t remote_key;
	uint64_t len;
	uint64_t imm_data;       /* the value of uet_write()'s uint64_t *data */
	uint32_t has_imm;        /* that pointer may legitimately be NULL, and
				  * NULL is not a value we can send, so the
				  * presence travels separately               */
	uint32_t seg_count;      /* writeseg/readseg: shim_seg[] follows */
};

/*
 * One segment of a scatter list that is already registered. uet_mr_seg's
 * addr is "an offset from zero when base_va is 0", and every region the
 * shim registers has base_va 0 - so the address needs no translation and
 * crosses as-is. The handle does: it is an id here and a pointer there.
 */
struct shim_seg {
	shim_handle_t mr;
	uint64_t      addr;
	uint64_t      len;
};

/*
 * Atomics carry up to three buffers (operand, compare, result), each with
 * its own region, which is why none of this fits in the header.
 */
struct shim_atomic_args {
	uint64_t      remote_addr;
	uint64_t      remote_key;
	uint64_t      count;     /* ELEMENTS, not bytes - the stack scales by
				  * datatype, and conflating the two would be
				  * a silent 8x corruption                   */
	uint64_t      bytes;     /* count x sizeof(datatype). Redundant, and
				  * deliberately so: the guest needs it to
				  * bounds-check the arena offsets, and
				  * sending it beats keeping a second copy of
				  * the datatype table in sync across two
				  * files                                    */
	uint64_t      op_off;    /* arena offsets; 0 where unused */
	uint64_t      cmp_off;
	uint64_t      res_off;
	shim_handle_t op_mr;
	shim_handle_t cmp_mr;
	shim_handle_t res_mr;
	uint32_t      datatype;  /* enum fi_datatype */
	uint32_t      atomic_op; /* enum fi_op */
};

/* --------------------------------------------------------------- messages
 * Fixed 72-byte header, then payload_len bytes.
 *
 * Field order is deliberate: four uint32_t first fill exactly 16 bytes, so
 * every 8-byte field lands naturally aligned and there is NO implicit
 * padding. That is what lets the transport assert sizeof() == 80.
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
	uint64_t off;            /* arena offset of this op's data buffer, or
				  * 0 for "none" - which is why the arena
				  * never hands out offset 0              */
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
 * PROGRESS      in:  h1 = domain
 *               The provider's manual-progress hook. One RPC per call, and
 *               a provider may call it in a poll loop, so it lands on the
 *               same hot path as CQ_READ - see the gap notes at the end of
 *               uet_shim_host.c.
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
 * TSEND         as SEND,  payload prefixed by struct shim_tag_args
 * TRECV         as RECV,  payload prefixed by struct shim_tag_args
 * RECVV         as RECV,  a2 = iov_count, payload = shim_iov[]
 * CQ_CLOSE      in:  h1 = cq
 * MR_REGV       in:  h1 = domain, a1 = iov_count, a2 = access,
 *                    a3 = requested_key, a4 = flags,
 *                    payload = shim_iov[] whose offsets are ARENA offsets
 *               out: h2 = mr handle
 * MR_REG_PBL    as MR_REGV; the page list is the shim_iov[]
 *
 * The RMA and atomic ops all take h1 = ep, h2 = mr, a1 = job_id,
 * a3 = dst addr handle, a4 = context id, off = arena offset of the LOCAL
 * buffer, and carry their remaining arguments in the payload:
 *
 * WRITE         payload = struct shim_rma_args
 * READ          payload = struct shim_rma_args
 * WRITE_SYNC    payload = struct shim_rma_args
 * WRITESEG      payload = shim_rma_args then seg_count x struct shim_seg;
 *                         hdr.off unused, each segment names its own region
 * READSEG       as WRITESEG
 * ATOMIC        payload = struct shim_atomic_args
 * ATOMIC_SYNC   payload = struct shim_atomic_args
 * FETCH_ATOMIC  payload = struct shim_atomic_args (uses .res_*)
 * COMPARE_ATOMIC payload = struct shim_atomic_args (.cmp_* and .res_*)
 * QUERY_ATOMIC  in:  h1 = domain, a1 = datatype, a2 = atomic_op, a3 = flags
 *               out: ret, payload = struct fi_atomic_attr
 *
 * MR_REG_PBL is declared but returns -ENOSYS: its pbl_root is a DMA
 * address, which is meaningless in the other address space. uet.c only
 * takes that path when UET_MR_PBL is set.
 * EVENT_EQ      guest -> host: a1 = context id, payload = the event
 * EVENT_EQ_ERR  guest -> host: a1 = context id, payload = the event
 */

/* -------------------------------------------------------------- transport
 * Deliberately tiny. uet_shim_host.c and uet_shim_guest.c call ONLY these
 * seven, and mention neither shared memory nor sockets - which is what lets
 * the transport be replaced without touching either of them.
 *
 * connect/listen take no arguments: each transport reads its own config
 * from the environment (UET_SHIM_SHM, or a vsock cid/port), so this header
 * stays free of any one transport's vocabulary.
 *
 * The int fd is vestigial, from the vsock original. Shared memory has no
 * descriptor and returns a sentinel it then ignores.
 */
/*
 * The arena. Both sides map the same bytes at different virtual addresses,
 * so the only portable currency is an offset: the host allocates and gets
 * back an offset, the guest turns that offset into its own pointer. A
 * transport with no shared region returns NULL and *len = 0, and the host
 * then falls back to inline payloads.
 */
void *shim_xport_arena(size_t *len);

const char *shim_xport_name(void);                     /* for logs  */
int  shim_xport_connect(void);                         /* host      */
int  shim_xport_listen(void);                          /* guest     */
int  shim_xport_accept(int lfd);                       /* guest     */
void shim_xport_close(int fd);

int  shim_send_msg(int fd, const struct shim_hdr *h, const void *payload);
int  shim_recv_msg(int fd, struct shim_hdr *h, void *payload,
		   size_t payload_cap);

#endif /* UET_SHIM_H */
