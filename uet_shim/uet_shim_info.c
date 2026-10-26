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
	}

	if (in->tx_attr != NULL) {
		out->tx_size          = in->tx_attr->size;
		out->tx_iov_limit     = in->tx_attr->iov_limit;
		out->tx_rma_iov_limit = in->tx_attr->rma_iov_limit;
		out->tx_msg_order     = in->tx_attr->msg_order;
		out->tx_tclass        = in->tx_attr->tclass;
	}

	if (in->rx_attr != NULL) {
		out->rx_size      = in->rx_attr->size;
		out->rx_iov_limit = in->rx_attr->iov_limit;
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

	fi->ep_attr->max_msg_size = in->ep_max_msg_size;
	fi->ep_attr->auth_key     = dup_blob(in->ep_auth_key,
					     in->ep_auth_key_size);
	fi->ep_attr->auth_key_size =
		(fi->ep_attr->auth_key != NULL) ? in->ep_auth_key_size : 0;

	fi->tx_attr->size          = in->tx_size;
	fi->tx_attr->iov_limit     = in->tx_iov_limit;
	fi->tx_attr->rma_iov_limit = in->tx_rma_iov_limit;
	fi->tx_attr->msg_order     = in->tx_msg_order;
	fi->tx_attr->tclass        = in->tx_tclass;

	fi->rx_attr->size      = in->rx_size;
	fi->rx_attr->iov_limit = in->rx_iov_limit;

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
