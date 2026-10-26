/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * fi_info <-> shim_fi_info marshalling.
 *
 * Kept out of uet_shim.h deliberately: this needs <rdma/fabric.h>, and the
 * contract header must stay compilable without libfabric in scope.
 *
 * Both sides flatten when sending and build when receiving, so both link
 * this file.
 */
#ifndef UET_SHIM_INFO_H
#define UET_SHIM_INFO_H

#include <rdma/fabric.h>

#include "uet_shim.h"

/* Copy the fields the stack reads out of a real fi_info. Tolerates NULL
 * sub-attrs and a NULL 'in'. */
void shim_info_flatten(const struct fi_info *in, struct shim_fi_info *out);

/*
 * Rebuild a real fi_info from the flattened form.
 *
 * OWNERSHIP: the caller owns the result and must release it with
 * fi_freeinfo(). Where the result is handed to the stack, the stack takes
 * it on SUCCESS and the caller must free it on FAILURE - getting that
 * backwards is either a leak or a double free.
 *
 * The sub-attr structs come from fi_allocinfo(), so only the fields the
 * stack reads are populated; everything else keeps fi_allocinfo()'s zeroes.
 */
struct fi_info *shim_info_build(const struct shim_fi_info *in);

#endif /* UET_SHIM_INFO_H */
