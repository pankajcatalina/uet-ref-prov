/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * Exercises the SIX transport functions only. No UET stack, no libfabric,
 * no provider - this builds with -I. and nothing else.
 *
 * That isolation is the point: if this hangs, the fault is ivshmem or
 * share=on, not the shim. Run it before anything else.
 *
 *   guest:  ./xport_test guest      (re-accepts, so it serves many runs)
 *   host:   ./xport_test host
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "uet_shim.h"

#define N 20000

static double us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

int main(int argc, char **argv)
{
	static char pay[SHIM_MAX_PAYLOAD];
	struct shim_hdr h;
	int fd, i;

	if ((argc < 2) ||
	    (strcmp(argv[1], "guest") && strcmp(argv[1], "host"))) {
		fprintf(stderr, "usage: %s guest|host\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "guest") == 0) {
		int lfd = shim_xport_listen();
		int session = 0;

		if (lfd < 0)
			return 1;

		/*
		 * Re-accept after each host disconnect, exactly as
		 * uet_shim_guest does. Without this only the FIRST host run
		 * has a peer, which once made three good reconnects look
		 * like three failures.
		 */
		for (;;) {
			unsigned long n = 0;

			fd = shim_xport_accept(lfd);
			if (fd < 0)
				return 1;
			printf("[guest] session %d: connected, echoing\n",
			       ++session);
			fflush(stdout);

			for (;;) {
				if (shim_recv_msg(fd, &h, pay,
						  sizeof(pay)) != 0)
					break;
				n++;
				/* prove we actually READ the header, not just
				 * that bytes moved */
				h.ret = (int64_t)h.a1 + 1;
				if (shim_send_msg(fd, &h, pay) != 0)
					break;
			}
			shim_xport_close(fd);
			printf("[guest] session %d: peer gone after %lu "
			       "messages\n", session, n);
			fflush(stdout);
		}
	}

	fd = shim_xport_connect();
	if (fd < 0)
		return 1;

	/* 1. correctness: header fields and payload must survive intact */
	memset(&h, 0, sizeof(h));
	h.op = SHIM_INITIALIZE;
	h.a1 = 41;
	h.payload_len = 64;
	strcpy(pay, "payload across the vm boundary");
	if (shim_send_msg(fd, &h, pay) != 0)
		return 1;
	memset(pay, 0, sizeof(pay));
	if (shim_recv_msg(fd, &h, pay, sizeof(pay)) != 0)
		return 1;
	printf("[host]  ret=%lld (want 42)  echo=\"%s\"\n",
	       (long long)h.ret, pay);

	/* 2. latency, 64-byte messages */
	{
		double t0 = us();

		for (i = 0; i < N; i++) {
			h.a1 = i;
			h.payload_len = 64;
			if (shim_send_msg(fd, &h, pay) != 0)
				break;
			if (shim_recv_msg(fd, &h, pay, sizeof(pay)) != 0)
				break;
		}
		printf("[host]  %d round trips, mean %.3f us\n",
		       i, (us() - t0) / i);
	}

	/* 3. throughput at the inline cap - this is the copy cost the MR
	 * arena will later remove */
	{
		double t0;

		h.payload_len = SHIM_MAX_PAYLOAD;
		t0 = us();
		for (i = 0; i < 2000; i++) {
			if (shim_send_msg(fd, &h, pay) != 0)
				break;
			if (shim_recv_msg(fd, &h, pay, sizeof(pay)) != 0)
				break;
		}
		printf("[host]  %u KiB messages: mean %.2f us (%.1f GB/s)\n",
		       SHIM_MAX_PAYLOAD >> 10, (us() - t0) / i,
		       (2.0 * i * SHIM_MAX_PAYLOAD) / ((us() - t0) * 1e3));
	}

	shim_xport_close(fd);
	return 0;
}
