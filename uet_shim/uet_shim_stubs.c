/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * uet_shim_stubs - the uet_api.h surface libuet does not implement.
 *
 * The guest shim's dispatcher covers the whole API, because the protocol
 * carries opcodes for all of it. libuet implements the 29 a provider
 * actually needs, which leaves these 14 undefined at link time: RMA,
 * atomics, and four messaging variants whose vectored or tagged sibling
 * libuet does provide.
 *
 * -FI_ENOSYS rather than omitting them, so the failure arrives as a clean
 * refusal at the one call that wanted it, with the opcode named in the
 * guest's log - instead of a link error that says nothing about which
 * operation an application tried to use.
 */
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#include <rdma/fabric.h>

#include "uet_api.h"

ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id, const void *local_op_buf, size_t count, uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_atomic_sync(uet_ep_handle_t ep_handle, uint32_t job_id, const void *local_op_buf, size_t count, uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_compare_atomic(uet_ep_handle_t ep_handle, uint32_t job_id, const void *local_op_buf, size_t count, uet_mr_handle_t op_mr_handle, const void *compare_buf, uet_mr_handle_t compare_mr_handle, void *result_buf, uet_mr_handle_t result_mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

int uet_cq_close(uet_cq_handle_t cq_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_fetch_atomic(uet_ep_handle_t ep_handle, uint32_t job_id, const void *local_op_buf, size_t count, uet_mr_handle_t op_mr_handle, void *result_buf, uet_mr_handle_t result_mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

int uet_query_atomic(uet_domain_handle_t domain_handle, enum fi_datatype datatype, enum fi_op op, struct fi_atomic_attr *attr, uint64_t flags)
{
	return -FI_ENOSYS;
}

ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, size_t len, uet_mr_handle_t mr_handle, uet_addr_handle_t uet_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_readseg(uet_ep_handle_t ep_handle, uint32_t job_id, const struct uet_mr_seg *seg, size_t seg_count, uet_addr_handle_t uet_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_recvv(uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov, size_t iov_count, uet_mr_handle_t mr_handle, uet_addr_handle_t src_addr_handle, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_trecv(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, size_t len, uet_mr_handle_t mr_handle, uet_addr_handle_t src_addr_handle, uint64_t tag, uint64_t ignore, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_tsend(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, size_t len, uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t tag, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, size_t len, uint64_t *data, uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_writeseg(uet_ep_handle_t ep_handle, uint32_t job_id, const struct uet_mr_seg *seg, size_t seg_count, uint64_t *data, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return -FI_ENOSYS;
}

ssize_t uet_write_sync(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, size_t len, uint64_t *data, uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle, uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return -FI_ENOSYS;
}

