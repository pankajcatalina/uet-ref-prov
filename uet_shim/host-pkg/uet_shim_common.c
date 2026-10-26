/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * Shared by both sides of the shim: opcode names for logging.
 *
 * This file deliberately has no dependencies beyond uet_shim.h - not even
 * libfabric. If it ever stops compiling on its own, the contract header has
 * grown a dependency it should not have.
 */
#include <stdio.h>

#include "uet_shim.h"

/*
 * Designated initialisers index the table BY the enum value, so reordering
 * enum shim_op cannot silently mislabel an opcode. Sized by SHIM_OP_MAX, so
 * adding an opcode without a name leaves a NULL rather than reading past
 * the end.
 */
const char *shim_op_name(uint32_t op)
{
	static const char *n[SHIM_OP_MAX] = {
		[SHIM_INITIALIZE]   = "INITIALIZE",
		[SHIM_FINALIZE]     = "FINALIZE",
		[SHIM_GETINFO]      = "GETINFO",
		[SHIM_GETNAME]      = "GETNAME",
		[SHIM_DOMAIN]       = "DOMAIN",
		[SHIM_DOMAIN_CLOSE] = "DOMAIN_CLOSE",
		[SHIM_PROGRESS]     = "PROGRESS",
		[SHIM_ENDPOINT]     = "ENDPOINT",
		[SHIM_EP_ENABLE]    = "EP_ENABLE",
		[SHIM_EP_CLOSE]     = "EP_CLOSE",
		[SHIM_EP_BIND_CQ]   = "EP_BIND_CQ",
		[SHIM_EP_BIND_MR]   = "EP_BIND_MR",
		[SHIM_MR_REG]       = "MR_REG",
		[SHIM_MR_REGV]      = "MR_REGV",
		[SHIM_MR_REG_PBL]   = "MR_REG_PBL",
		[SHIM_MR_KEY]       = "MR_KEY",
		[SHIM_MR_ENABLE]    = "MR_ENABLE",
		[SHIM_MR_DISABLE]   = "MR_DISABLE",
		[SHIM_MR_CLOSE]     = "MR_CLOSE",
		[SHIM_AV_INSERT]    = "AV_INSERT",
		[SHIM_AV_REMOVE]    = "AV_REMOVE",
		[SHIM_CQ_READ]      = "CQ_READ",
		[SHIM_CQ_READERR]   = "CQ_READERR",
		[SHIM_CQ_CLOSE]     = "CQ_CLOSE",
		[SHIM_SEND]         = "SEND",
		[SHIM_SENDV]        = "SENDV",
		[SHIM_RECV]         = "RECV",
		[SHIM_RECVV]        = "RECVV",
		[SHIM_TSEND]        = "TSEND",
		[SHIM_TSENDV]       = "TSENDV",
		[SHIM_TRECV]        = "TRECV",
		[SHIM_TRECVV]       = "TRECVV",
		[SHIM_WRITE]        = "WRITE",
		[SHIM_WRITESEG]     = "WRITESEG",
		[SHIM_WRITE_SYNC]   = "WRITE_SYNC",
		[SHIM_READ]         = "READ",
		[SHIM_READSEG]      = "READSEG",
		[SHIM_ATOMIC]       = "ATOMIC",
		[SHIM_FETCH_ATOMIC] = "FETCH_ATOMIC",
		[SHIM_COMPARE_ATOMIC] = "CMP_ATOMIC",
		[SHIM_QUERY_ATOMIC] = "QUERY_ATOMIC",
		[SHIM_ATOMIC_SYNC]  = "ATOMIC_SYNC",
		[SHIM_EVENT_EQ]     = "EVENT_EQ",
		[SHIM_EVENT_EQ_ERR] = "EVENT_EQ_ERR",
	};

	/*
	 * Defensive on purpose. This is called ON PEER DATA, before any
	 * validation, while logging a message that may be garbage:
	 *
	 *   op == 0            a zeroed region
	 *   op >= OP_MAX       a wild value
	 *   n[op] == NULL      an opcode added without a name
	 *
	 * It can never fault and never returns NULL, so the caller's
	 * printf("%s", ...) is always safe.
	 */
	if ((op == 0) || (op >= SHIM_OP_MAX) || (n[op] == NULL))
		return "UNKNOWN";
	return n[op];
}
