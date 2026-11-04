/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * post_test - does the HOST actually get more than one request in flight?
 *
 * xport_test proves the ring holds many messages, but it calls the
 * transport directly. This drives the real uet_* stubs, which is the path
 * NCCL takes, and checks the three things that make asynchronous posting
 * correct rather than merely fast:
 *
 *   1. a send returns without waiting for the guest, so several are
 *      outstanding at once;
 *   2. credits refuse the (N+1)th locally with -FI_EAGAIN, costing no
 *      round trip - libfabric's contract is that the caller retries;
 *   3. the next synchronous RPC drains every posted reply on its way to
 *      its own, so the g2h ring cannot fill and strand the guest.
 *
 * Run against "xport_test guest", whose echo loop answers any opcode with
 * ret = a1 + 1. The handles are not real and nothing validates them - this
 * exercises the shim's accounting, not the stack.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rdma/fabric.h>

#include "uet_api.h"
#include "uet_shim.h"

unsigned shim_host_outstanding(void);

static int fails;

#define CHECK(cond, ...) do {                                           \
	if (cond) {                                                     \
		printf("  ok    ");                                     \
	} else {                                                        \
		printf("  FAIL  ");                                     \
		fails++;                                                \
	}                                                               \
	printf(__VA_ARGS__);                                            \
	printf("\n");                                                   \
} while (0)

/* opaque to the shim: it only ever passes these back across */
#define FAKE_EP   ((uet_ep_handle_t)(uintptr_t)1)
#define FAKE_MR   ((uet_mr_handle_t)(uintptr_t)2)
#define FAKE_AV   ((uet_addr_handle_t)(uintptr_t)3)
#define FAKE_DOM  ((uet_domain_handle_t)(uintptr_t)4)

int main(void)
{
	static char buf[256];
	struct iovec iov = { buf, sizeof(buf) };
	unsigned posted = 0, before, base;
	ssize_t rc = 0;
	int i;

	printf("=== post_test: multiple requests in flight ===\n");

	/* This asserts ASYNCHRONOUS behaviour, so under the kill switch
	 * there is nothing here to test - skip rather than report a
	 * failure that is really the switch doing its job. */
	{
		const char *e = getenv("UET_SHIM_SYNC");

		if ((e != NULL) && (*e != '0')) {
			printf("  skip  UET_SHIM_SYNC is set: posting is "
			       "synchronous by request\n");
			return 0;
		}
	}

	memset(buf, 0xa5, sizeof(buf));

	/*
	 * Connect before anything else. The arena is mapped by
	 * shim_connect_once(), which only runs inside an RPC - and
	 * uet_tsendv() stages into the arena BEFORE it posts, so a data
	 * call cannot be the first thing a process does. In the real flow
	 * uet_initialize() always comes first. The echo guest answers
	 * ret = a1 + 1, so the return value here is meaningless; the point
	 * is the side effect.
	 */
	{
		uet_handle_t handle;

		(void)uet_initialize(&handle);
	}

	/*
	 * 0. One of EACH first. A transmit stages into ARENA_H, a receive
	 *    reserves a landing zone in ARENA_G - different arenas, and
	 *    for a while the host did not own the second one's free list.
	 *    That shipped because every loopback test posted only sends,
	 *    and it surfaced on the rig as "no arena space for 8 bytes
	 *    (0 free of 132120576)": mapped, empty, and refusing.
	 */
	rc = uet_tsendv(FAKE_EP, 1, &iov, 1, FAKE_MR, FAKE_AV, 0x1234,
			(void *)(uintptr_t)0x5e4d);
	CHECK(rc == 0, "a transmit posts, staging into ARENA_H (got %zd)", rc);

	rc = uet_trecvv(FAKE_EP, 1, &iov, 1, FAKE_MR, FAKE_AV, 0x1234, 0,
			(void *)(uintptr_t)0x4ecb);
	CHECK(rc == 0, "a receive posts, landing zone from ARENA_G (got %zd)",
	      rc);

	/* 1. post until the credits run out. Under ABI 5 the second call
	 *    could not even be issued before the first had been answered. */
	base = shim_host_outstanding();      /* the two posted above */

	for (i = 0; i < 100000; i++) {
		rc = uet_tsendv(FAKE_EP, 1, &iov, 1, FAKE_MR, FAKE_AV,
				0x1234, (void *)(uintptr_t)(i + 1));
		if (rc != 0)
			break;
		posted++;
	}

	CHECK(posted > 1, "more than one request in flight (%u posted)",
	      posted);
	CHECK(rc == -FI_EAGAIN,
	      "the post after the last credit is refused with -FI_EAGAIN "
	      "(got %zd)", rc);
	CHECK(shim_host_outstanding() == (base + posted),
	      "outstanding accounting matches what was posted (%u = %u + %u)",
	      shim_host_outstanding(), base, posted);

	/* 2. one synchronous RPC must retire every posted reply on its way
	 *    to its own - this is what keeps the g2h ring from filling. */
	before = shim_host_outstanding();
	(void)uet_progress(FAKE_DOM);

	CHECK(before > 1, "there were %u replies waiting to be reaped",
	      before);
	CHECK(shim_host_outstanding() == 0,
	      "one RPC drained them all (now %u)",
	      shim_host_outstanding());

	/* 3. and the credits come back */
	rc = uet_tsendv(FAKE_EP, 1, &iov, 1, FAKE_MR, FAKE_AV, 0x1234,
			(void *)(uintptr_t)0xbeef);
	CHECK(rc == 0, "credits recovered, posting works again (got %zd)",
	      rc);

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "all passed",
	       fails, (fails == 1) ? "" : "s");
	return fails ? 1 : 0;
}
