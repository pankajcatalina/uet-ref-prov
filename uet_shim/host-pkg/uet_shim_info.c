/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * fi_info marshalling.
 *
 * struct fi_info is pointer-rich: src_addr, dest_addr, fabric_attr,
 * domain_attr, ep_attr, tx_attr and rx_attr are each separately allocated.
 * A memcpy would copy the POINTERS, which mean nothing in the peer's
 * address space - so it has to be flattened field by field.
 *
 * Rather than serialise all of it, this carries only the fields the UET
 * stack actually reads. That set was obtained mechanically, not by reading
 * and guessing:
 *
 *   grep -ohE "info->[a-z_]+(->[a-z_]+)?" uet_api.c uet_pds*.c \
 *        util/uet_util.c | sort -u
 *
 * If the stack ever reads another field, add it to struct shim_fi_info and
 * to both functions here. Nothing else needs to change.
 */
#include <stdlib.h>
#include <string.h>

#include <rdma/fabric.h>

#include "uet_api.h"            /* pulls in uet_addr.h for the assert below */
#include "uet_shim_info.h"

/*
 * Deferred from uet_shim.h, which cannot include uet_addr.h without losing
 * its independence. SHIM_ADDR_MAX is 64 and struct uet_addr is 32, so there
 * is double headroom - but if it ever grows past 64 the address would be
 * SILENTLY TRUNCATED by CPY_BLOB below. Fail the build instead.
 */
_Static_assert(sizeof(struct uet_addr) <= SHIM_ADDR_MAX,
	       "struct uet_addr outgrew SHIM_ADDR_MAX - addresses would "
	       "be truncated on the wire");

/* char * -> fixed array, always NUL terminated, NULL tolerated */
#define CPY_STR(dst, src)                                        \
	do {                                                     \
		if ((src) != NULL) {                             \
			strncpy((dst), (src), sizeof(dst) - 1);  \
			(dst)[sizeof(dst) - 1] = '\0';           \
		} else {                                         \
			(dst)[0] = '\0';                         \
		}                                                \
	} while (0)

/* void * + len -> fixed array + len, clamped so it can never overrun */
#define CPY_BLOB(dst, dstlen, src, srclen)                       \
	do {                                                     \
		size_t n = (srclen);                             \
		if (n > sizeof(dst))                             \
			n = sizeof(dst);                         \
		if (((src) != NULL) && (n > 0))                  \
			memcpy((dst), (src), n);                 \
		(dstlen) = (uint32_t)n;                          \
	} while (0)

void shim_info_flatten(const struct fi_info *in, struct shim_fi_info *out)
{
	/* zero first, so any field not set below is deterministic rather
	 * than whatever was on the caller's stack */
	memset(out, 0, sizeof(*out));
	if (in == NULL)
		return;

	out->caps = in->caps;
	out->mode = in->mode;
	out->addr_format = in->addr_format;

	CPY_BLOB(out->src_addr, out->src_addrlen,
		 in->src_addr, in->src_addrlen);
	CPY_BLOB(out->dest_addr, out->dest_addrlen,
		 in->dest_addr, in->dest_addrlen);

	/* every sub-attr is a separate allocation and may legitimately be
	 * NULL, so each is guarded */
	if (in->fabric_attr != NULL) {
		CPY_STR(out->fabric_name, in->fabric_attr->name);
		CPY_STR(out->prov_name, in->fabric_attr->prov_name);
	}

	if (in->domain_attr != NULL) {
		out->domain_caps            = in->domain_attr->caps;
		out->domain_mode            = in->domain_attr->mode;
		out->domain_cq_data_size    = in->domain_attr->cq_data_size;
		out->domain_cq_cnt          = in->domain_attr->cq_cnt;
		out->domain_ep_cnt          = in->domain_attr->ep_cnt;
		out->domain_tx_ctx_cnt      = in->domain_attr->tx_ctx_cnt;
		out->domain_rx_ctx_cnt      = in->domain_attr->rx_ctx_cnt;
		out->domain_max_ep_tx_ctx   = in->domain_attr->max_ep_tx_ctx;
		out->domain_max_ep_rx_ctx   = in->domain_attr->max_ep_rx_ctx;
		out->domain_cntr_cnt        = in->domain_attr->cntr_cnt;
		out->domain_mr_iov_limit    = in->domain_attr->mr_iov_limit;
		out->domain_max_err_data    = in->domain_attr->max_err_data;
		out->domain_threading       = (uint32_t)in->domain_attr->threading;
		out->domain_control_progress =
			(uint32_t)in->domain_attr->control_progress;
		out->domain_data_progress   =
			(uint32_t)in->domain_attr->data_progress;
		out->domain_resource_mgmt   =
			(uint32_t)in->domain_attr->resource_mgmt;
		out->domain_av_type         = (uint32_t)in->domain_attr->av_type;
		out->domain_tclass          = in->domain_attr->tclass;

		CPY_STR(out->domain_name, in->domain_attr->name);
		out->domain_mr_mode     = in->domain_attr->mr_mode;
		out->domain_mr_cnt      = in->domain_attr->mr_cnt;
		out->domain_mr_key_size = in->domain_attr->mr_key_size;
		CPY_BLOB(out->domain_auth_key, out->domain_auth_key_size,
			 in->domain_attr->auth_key,
			 in->domain_attr->auth_key_size);
	}

	if (in->ep_attr != NULL) {
		out->ep_max_msg_size = in->ep_attr->max_msg_size;
		CPY_BLOB(out->ep_auth_key, out->ep_auth_key_size,
			 in->ep_attr->auth_key, in->ep_attr->auth_key_size);

		out->ep_type              = (uint32_t)in->ep_attr->type;
		out->ep_protocol          = in->ep_attr->protocol;
		out->ep_protocol_version  = in->ep_attr->protocol_version;
		out->ep_tx_ctx_cnt        = (uint32_t)in->ep_attr->tx_ctx_cnt;
		out->ep_rx_ctx_cnt        = (uint32_t)in->ep_attr->rx_ctx_cnt;
		out->ep_msg_prefix_size   = in->ep_attr->msg_prefix_size;
		out->ep_max_order_raw_size = in->ep_attr->max_order_raw_size;
		out->ep_max_order_war_size = in->ep_attr->max_order_war_size;
		out->ep_max_order_waw_size = in->ep_attr->max_order_waw_size;
		out->ep_mem_tag_format    = in->ep_attr->mem_tag_format;
	}

	if (in->tx_attr != NULL) {
		out->tx_size          = in->tx_attr->size;
		out->tx_iov_limit     = in->tx_attr->iov_limit;
		out->tx_rma_iov_limit = in->tx_attr->rma_iov_limit;
		out->tx_msg_order     = in->tx_attr->msg_order;
		out->tx_tclass        = in->tx_attr->tclass;
		out->tx_caps          = in->tx_attr->caps;
		out->tx_mode          = in->tx_attr->mode;
		out->tx_op_flags      = in->tx_attr->op_flags;
		out->tx_comp_order    = in->tx_attr->comp_order;
		out->tx_inject_size   = in->tx_attr->inject_size;
	}

	if (in->rx_attr != NULL) {
		out->rx_size      = in->rx_attr->size;
		out->rx_iov_limit = in->rx_attr->iov_limit;
		out->rx_caps      = in->rx_attr->caps;
		out->rx_mode      = in->rx_attr->mode;
		out->rx_op_flags  = in->rx_attr->op_flags;
		out->rx_comp_order = in->rx_attr->comp_order;
		out->rx_total_buffered_recv = in->rx_attr->total_buffered_recv;
	}

	/*
	 * info->nic, down to the leaves uet.c actually prints. Each level is
	 * guarded: a provider may populate device_attr without link_attr.
	 */
	out->has_nic = (in->nic != NULL);
	if (in->nic != NULL) {
		if (in->nic->device_attr != NULL)
			CPY_STR(out->nic_dev_name,
				in->nic->device_attr->name);
		if (in->nic->link_attr != NULL) {
			CPY_STR(out->nic_net_type,
				in->nic->link_attr->network_type);
			CPY_STR(out->nic_address,
				in->nic->link_attr->address);
			out->nic_mtu   = in->nic->link_attr->mtu;
			out->nic_speed = in->nic->link_attr->speed;
			out->nic_state = (uint32_t)in->nic->link_attr->state;
		}
	}

	/* a pointer the stack only TESTS, reduced to one byte */
	out->has_next = (in->next != NULL);
}

/* strdup that treats an empty string as absent, so a flattened "" rebuilds
 * as NULL rather than as a pointer to "" */
static char *dup_or_null(const char *s)
{
	return ((s != NULL) && (s[0] != '\0')) ? strdup(s) : NULL;
}

/*
 * fi_freeinfo() closes info->nic only when its fid has a close op
 * (fabric.c: "FI_CHECK_OP(info->nic->fid.ops, struct fi_ops, close)").
 * libfabric's own ofi_nic_dup() would do all of this, but it is internal
 * and not exported from the shared library - so the nic is hand-built and
 * given a close op that frees exactly what was allocated. Leaving fid.ops
 * NULL would also "work", by leaking it on every fi_freeinfo().
 */
static int shim_nic_close(struct fid *fid)
{
	struct fid_nic *nic = (struct fid_nic *)fid;

	if (nic == NULL)
		return 0;

	if (nic->device_attr != NULL) {
		free(nic->device_attr->name);
		free(nic->device_attr);
	}
	if (nic->link_attr != NULL) {
		free(nic->link_attr->network_type);
		free(nic->link_attr->address);
		free(nic->link_attr);
	}
	free(nic);
	return 0;
}

static struct fi_ops shim_nic_fi_ops = {
	.size  = sizeof(struct fi_ops),
	.close = shim_nic_close,
};

static struct fid_nic *shim_nic_build(const struct shim_fi_info *in)
{
	struct fid_nic *nic = calloc(1, sizeof(*nic));

	if (nic == NULL)
		return NULL;

	nic->fid.fclass = FI_CLASS_NIC;
	nic->fid.ops    = &shim_nic_fi_ops;

	nic->device_attr = calloc(1, sizeof(*nic->device_attr));
	nic->link_attr   = calloc(1, sizeof(*nic->link_attr));
	if ((nic->device_attr == NULL) || (nic->link_attr == NULL)) {
		shim_nic_close(&nic->fid);
		return NULL;
	}

	nic->device_attr->name       = dup_or_null(in->nic_dev_name);
	nic->link_attr->network_type = dup_or_null(in->nic_net_type);
	nic->link_attr->address      = dup_or_null(in->nic_address);
	nic->link_attr->mtu          = in->nic_mtu;
	nic->link_attr->speed        = in->nic_speed;
	nic->link_attr->state        = (enum fi_link_state)in->nic_state;

	return nic;
}


static void *dup_blob(const void *src, uint32_t len)
{
	void *p;

	if (len == 0)
		return NULL;
	p = malloc(len);
	if (p != NULL)
		memcpy(p, src, len);
	return p;
}

struct fi_info *shim_info_build(const struct shim_fi_info *in)
{
	struct fi_info *fi = fi_allocinfo();

	if (fi == NULL)
		return NULL;

	fi->caps = in->caps;

	/* Set the length only when the allocation succeeded. A non-zero
	 * addrlen with a NULL addr would make the stack read from NULL. */
	fi->mode = in->mode;
	fi->addr_format = (uint32_t)in->addr_format;

	fi->src_addr = dup_blob(in->src_addr, in->src_addrlen);
	fi->src_addrlen = (fi->src_addr != NULL) ? in->src_addrlen : 0;

	fi->dest_addr = dup_blob(in->dest_addr, in->dest_addrlen);
	fi->dest_addrlen = (fi->dest_addr != NULL) ? in->dest_addrlen : 0;

	/* fi_allocinfo() has already allocated every sub-attr struct, so
	 * these are assignments, not allocations */
	fi->fabric_attr->name      = dup_or_null(in->fabric_name);
	fi->fabric_attr->prov_name = dup_or_null(in->prov_name);

	fi->domain_attr->name        = dup_or_null(in->domain_name);
	fi->domain_attr->mr_mode     = (int)in->domain_mr_mode;
	fi->domain_attr->mr_cnt      = in->domain_mr_cnt;
	fi->domain_attr->mr_key_size = in->domain_mr_key_size;
	fi->domain_attr->auth_key    = dup_blob(in->domain_auth_key,
						in->domain_auth_key_size);
	fi->domain_attr->auth_key_size =
		(fi->domain_attr->auth_key != NULL) ?
		in->domain_auth_key_size : 0;

	fi->domain_attr->caps          = in->domain_caps;
	fi->domain_attr->mode          = in->domain_mode;
	fi->domain_attr->cq_data_size  = in->domain_cq_data_size;
	fi->domain_attr->cq_cnt        = in->domain_cq_cnt;
	fi->domain_attr->ep_cnt        = in->domain_ep_cnt;
	fi->domain_attr->tx_ctx_cnt    = in->domain_tx_ctx_cnt;
	fi->domain_attr->rx_ctx_cnt    = in->domain_rx_ctx_cnt;
	fi->domain_attr->max_ep_tx_ctx = in->domain_max_ep_tx_ctx;
	fi->domain_attr->max_ep_rx_ctx = in->domain_max_ep_rx_ctx;
	fi->domain_attr->cntr_cnt      = in->domain_cntr_cnt;
	fi->domain_attr->mr_iov_limit  = in->domain_mr_iov_limit;
	fi->domain_attr->max_err_data  = in->domain_max_err_data;
	fi->domain_attr->threading     =
		(enum fi_threading)in->domain_threading;
	fi->domain_attr->control_progress =
		(enum fi_progress)in->domain_control_progress;
	fi->domain_attr->data_progress =
		(enum fi_progress)in->domain_data_progress;
	fi->domain_attr->resource_mgmt =
		(enum fi_resource_mgmt)in->domain_resource_mgmt;
	fi->domain_attr->av_type       = (enum fi_av_type)in->domain_av_type;
	fi->domain_attr->tclass        = in->domain_tclass;

	fi->ep_attr->max_msg_size = in->ep_max_msg_size;
	fi->ep_attr->auth_key     = dup_blob(in->ep_auth_key,
					     in->ep_auth_key_size);
	fi->ep_attr->auth_key_size =
		(fi->ep_attr->auth_key != NULL) ? in->ep_auth_key_size : 0;

	fi->ep_attr->type              = (enum fi_ep_type)in->ep_type;
	fi->ep_attr->protocol          = in->ep_protocol;
	fi->ep_attr->protocol_version  = in->ep_protocol_version;
	fi->ep_attr->tx_ctx_cnt        = in->ep_tx_ctx_cnt;
	fi->ep_attr->rx_ctx_cnt        = in->ep_rx_ctx_cnt;
	fi->ep_attr->msg_prefix_size   = in->ep_msg_prefix_size;
	fi->ep_attr->max_order_raw_size = in->ep_max_order_raw_size;
	fi->ep_attr->max_order_war_size = in->ep_max_order_war_size;
	fi->ep_attr->max_order_waw_size = in->ep_max_order_waw_size;
	fi->ep_attr->mem_tag_format    = in->ep_mem_tag_format;

	fi->tx_attr->size          = in->tx_size;
	fi->tx_attr->iov_limit     = in->tx_iov_limit;
	fi->tx_attr->rma_iov_limit = in->tx_rma_iov_limit;
	fi->tx_attr->msg_order     = in->tx_msg_order;
	fi->tx_attr->tclass        = in->tx_tclass;
	fi->tx_attr->caps          = in->tx_caps;
	fi->tx_attr->mode          = in->tx_mode;
	fi->tx_attr->op_flags      = in->tx_op_flags;
	fi->tx_attr->comp_order    = in->tx_comp_order;
	fi->tx_attr->inject_size   = in->tx_inject_size;

	fi->rx_attr->size      = in->rx_size;
	fi->rx_attr->iov_limit = in->rx_iov_limit;
	fi->rx_attr->caps      = in->rx_caps;
	fi->rx_attr->mode      = in->rx_mode;
	fi->rx_attr->op_flags  = in->rx_op_flags;
	fi->rx_attr->comp_order = in->rx_comp_order;
	fi->rx_attr->total_buffered_recv = in->rx_total_buffered_recv;

	/*
	 * info->nic, rebuilt. ABI 1 left this NULL because the provider only
	 * tests it; uet.c dereferences it to print the device, so it has to
	 * exist here.
	 *
	 * info->next is still left NULL: the shim presents a single fi_info,
	 * not a list.
	 */
	if (in->has_nic)
		fi->nic = shim_nic_build(in);

	return fi;
}
