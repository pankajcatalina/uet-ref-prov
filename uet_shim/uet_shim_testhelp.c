/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * uet_shim_testhelp - the three util helpers uet.c needs that are not part
 * of the uet_api.h boundary.
 *
 * uet.c is the stack's own test program, and linking it against
 * libuet_shim_host.so is what lets its whole suite - tagged, RMA, atomics,
 * unexpected messages, deferred sends, 100 iterations each with built-in
 * payload validation - run against the stack inside the guest. That is a far
 * better test than anything hand-written, because a native baseline exists
 * from the identical binary.
 *
 * But uet.c also calls uet_gettime(), uet_ip_addr_to_str() and
 * uet_print_uet_addr(), which live in util/uet_util.c. Copying that file
 * into the container would put stack sources where the whole design says
 * there are none, and "stack sources included: 0" would stop being true.
 *
 * So they are reimplemented here. All three are pure formatting and clock
 * reads with no UET state, so there is nothing to keep in sync beyond the
 * struct layouts, which uet_addr.h already pins.
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "uet_addr.h"

#define TH_MSEC_PER_SEC   1000L
#define TH_NSEC_PER_MSEC  1000000L

int uet_gettime(time_t *time_ms)
{
	struct timespec s;

	if (clock_gettime(CLOCK_REALTIME, &s) != 0) {
		*time_ms = 0;
		return -1;
	}

	*time_ms = ((time_t)(s.tv_sec * TH_MSEC_PER_SEC)) +
		   ((time_t)(s.tv_nsec / TH_NSEC_PER_MSEC));
	return 0;
}

void uet_ip_addr_to_str(const struct uet_fa *fa, bool is_ipv6, char *str)
{
	if (is_ipv6) {
		inet_ntop(AF_INET6, fa->v6, str, INET6_ADDRSTRLEN);
	} else {
		/* uet_fa.v4 is in HOST order throughout the stack - every
		 * caller does ntohl() on the way in - so it has to be put
		 * back before inet_ntop reads it as network order. */
		struct in_addr a;

		a.s_addr = htonl(fa->v4);
		inet_ntop(AF_INET, &a, str, INET_ADDRSTRLEN);
	}
}

void uet_print_uet_addr(struct uet_addr *uet_addr)
{
	char ip_addr_str[INET6_ADDRSTRLEN];

	uet_ip_addr_to_str(&uet_addr->fa, uet_addr_is_ipv6(uet_addr),
			   ip_addr_str);

	printf("UET Address\n");
	printf("  IP Address:      %s\n", ip_addr_str);
	printf("  PIDonFEP:        %u\n", uet_addr->pid_on_fep);
	printf("  Index:           %u\n", uet_addr->start_index);
	printf("  Initiator ID:    %u\n", uet_addr->initiator_id);
	printf("  Profiles:      ");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_MIN)
		printf("  AI Min");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_FULL)
		printf("  AI Full");
	if (uet_addr->fep_cap & UET_FEP_CAP_HPC)
		printf("  HPC");
	printf("\n");
}
