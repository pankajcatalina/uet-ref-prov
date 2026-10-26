/*
 * Copyright (c) 2026 Broadcom. All rights reserved.
 *
 * shim_smoke - drives the shim from the host exactly as uet_provider does,
 * using only the 25 functions it imports.
 *
 * Links uet_shim_host.o and NEVER libuet_fabric.so, which is what proves
 * the host side needs no SES or PDS code at all.
 *
 * The call order mirrors uet_provider.c:
 *   fi_fabric     -> uet_initialize
 *   fi_getinfo    -> uet_getinfo
 *   fi_domain     -> uet_domain          (eq callbacks NULL, as it passes)
 *   fi_endpoint   -> uet_endpoint, uet_getname
 *   fi_mr_regattr -> uet_mr_reg, uet_mr_key
 *   fi_ep_bind    -> uet_ep_bind_cq x2, uet_ep_bind_mr, uet_mr_enable
 *   fi_enable     -> uet_ep_enable
 *   fi_av_insert  -> uet_av_insert
 *   fi_send       -> uet_send        /  fi_recv -> uet_recv
 *   fi_cq_read    -> uet_cq_read
 *
 *   ./shim_smoke                  control plane only
 *   ./shim_smoke <peer-ipv4>      client: also send to that peer
 *   ./shim_smoke server           server: post a receive and wait
 *
 * Two-node use, container to container through both guests:
 *   node6 container:  ./shim_smoke server
 *   node5 container:  ./shim_smoke 192.168.100.60
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "uet_api.h"

#define STEP(n, fmt, ...) \
	printf("\n[%2d] " fmt "\n", n, ##__VA_ARGS__)

#define CHECK(rc, what)                                           \
	do {                                                      \
		if ((long)(rc) < 0) {                             \
			printf("     FAILED: %s -> %ld\n",        \
			       what, (long)(rc));                 \
			goto out;                                 \
		}                                                 \
		printf("     ok: %s\n", what);                    \
	} while (0)

int main(int argc, char **argv)
{
	uet_handle_t        uet  = NULL;
	uet_domain_handle_t dom  = NULL;
	uet_ep_handle_t     ep   = NULL;
	uet_cq_handle_t     txcq = NULL, rxcq = NULL;
	uet_mr_handle_t     mr   = NULL;
	uet_addr_handle_t   peer = NULL;
	struct fi_info     *info = NULL;
	struct uet_addr     myaddr, peeraddr;
	struct fi_cq_attr   cqattr;
	static char         buf[4096];
	uint64_t            key;
	int                 rc, step = 0;
	int                 is_server = (argc > 1) &&
					 (strcmp(argv[1], "server") == 0);

	memset(&cqattr, 0, sizeof(cqattr));
	cqattr.format = FI_CQ_FORMAT_TAGGED;
	cqattr.size = 64;

	printf("=== shim_smoke (%s): driving the guest's UET stack "
	       "from the host ===\n", is_server ? "server" : "client");

	STEP(++step, "uet_initialize()        [fi_fabric]");
	rc = uet_initialize(&uet);
	CHECK(rc, "uet_initialize");
	printf("     handle = %p\n", uet);

	STEP(++step, "uet_getinfo()           [fi_getinfo]");
	rc = uet_getinfo(uet, NULL, NULL, &info);
	CHECK(rc, "uet_getinfo");
	printf("     caps=0x%llx  mr_mode=0x%x  mr_cnt=%zu\n",
	       (unsigned long long)info->caps,
	       info->domain_attr->mr_mode,
	       info->domain_attr->mr_cnt);
	printf("     max_msg=%zu  tx_size=%zu  msg_order=0x%llx\n",
	       info->ep_attr->max_msg_size, info->tx_attr->size,
	       (unsigned long long)info->tx_attr->msg_order);

	/*
	 * uet_getinfo() leaves the queue depths at ZERO, and uet_endpoint()
	 * sizes its descriptor pools straight from them:
	 *
	 *     uet_ep->num_tx_desc = info->tx_attr->size;
	 *     for (i = 0; i < uet_ep->num_tx_desc; i++)
	 *             uet_tx_desc_list_insert(&uet_ep->tx_desc[i]);
	 *
	 * so a zero means NO descriptors are ever inserted and uet_send()
	 * returns -FI_EAGAIN. uet_provider.c:69-72 patches the same two
	 * fields for the same reason; this mirrors it.
	 */
	if (info->rx_attr->size == 0)
		info->rx_attr->size = 64;
	if (info->tx_attr->size == 0)
		info->tx_attr->size = 64;

	/* FI_ORDER_SAS is what uet_get_pds_mode() tests to select ROD;
	 * leaving msg_order at 0 gives RUD instead. */
	info->tx_attr->msg_order = FI_ORDER_SAS;

	printf("     patched: tx_size=%zu rx_size=%zu msg_order=0x%llx (ROD)\n",
	       info->tx_attr->size, info->rx_attr->size,
	       (unsigned long long)info->tx_attr->msg_order);

	STEP(++step, "uet_domain()            [fi_domain]");
	/* fabric/domain are libfabric objects the stack stores but never
	 * dereferences; the provider passes NULL for both eq callbacks */
	rc = uet_domain(uet, NULL, info, NULL, NULL, NULL, NULL, &dom);
	CHECK(rc, "uet_domain");
	printf("     domain = %p\n", dom);

	STEP(++step, "uet_endpoint()          [fi_endpoint]");
	rc = uet_endpoint(dom, info, NULL, NULL, &ep);
	CHECK(rc, "uet_endpoint");
	printf("     ep = %p\n", ep);

	STEP(++step, "uet_getname()           [fi_getname]");
	rc = uet_getname(ep, &myaddr);
	CHECK(rc, "uet_getname");
	{
		struct in_addr a;

		a.s_addr = htonl(myaddr.fa.v4);
		printf("     guest fabric addr: %s  pid_on_fep=%u "
		       "index=%u initiator=%u\n",
		       inet_ntoa(a), myaddr.pid_on_fep,
		       myaddr.start_index, myaddr.initiator_id);
	}

	STEP(++step, "uet_mr_reg()            [fi_mr_regattr]");
	memset(buf, 0xA5, sizeof(buf));       /* a recognisable fill pattern */
	rc = uet_mr_reg(dom, buf, sizeof(buf),
			FI_SEND | FI_RECV | FI_READ | FI_WRITE |
			FI_REMOTE_READ | FI_REMOTE_WRITE,
			0, 0, NULL, &mr);
	CHECK(rc, "uet_mr_reg");
	printf("     mr = %p\n", mr);

	STEP(++step, "uet_mr_key()");
	key = uet_mr_key(mr);
	printf("     key = 0x%llx\n", (unsigned long long)key);

	STEP(++step, "uet_ep_bind_cq() x2     [fi_ep_bind FI_SEND/FI_RECV]");
	rc = uet_ep_bind_cq(ep, &cqattr, NULL, FI_SEND, NULL, &txcq);
	CHECK(rc, "uet_ep_bind_cq(FI_SEND)");
	rc = uet_ep_bind_cq(ep, &cqattr, NULL, FI_RECV, NULL, &rxcq);
	CHECK(rc, "uet_ep_bind_cq(FI_RECV)");
	printf("     txcq=%p rxcq=%p\n", txcq, rxcq);

	STEP(++step, "uet_ep_bind_mr()");
	rc = uet_ep_bind_mr(ep, mr, 0);
	CHECK(rc, "uet_ep_bind_mr");

	STEP(++step, "uet_mr_enable()");
	rc = uet_mr_enable(mr);
	CHECK(rc, "uet_mr_enable");

	STEP(++step, "uet_ep_enable()         [fi_enable]");
	rc = uet_ep_enable(ep);
	CHECK(rc, "uet_ep_enable");

	printf("\n=========================================================\n");
	printf(" CONTROL PLANE COMPLETE - the host drove SES/PDS setup\n");
	printf(" inside the guest over shared memory.\n");
	printf("=========================================================\n");

	if (is_server) {
		/*
		 * Post a receive and wait. Mirrors uet.c:1435 - no MR and no
		 * source filter, so the stack accepts from anyone.
		 *
		 * This is the first real exercise of the shim's RECEIVE path:
		 * the host records buf against the context id and
		 * uet_cq_read() copies the bytes back out of the reply.
		 */
		STEP(++step, "uet_recv() posted, waiting for a peer");
		memset(buf, 0, sizeof(buf));
		rc = (int)uet_recv(ep, UET_JOB_ID_ANY, buf, sizeof(buf),
				   UET_NULL_HANDLE, UET_NULL_HANDLE,
				   (void *)0xBEEF2);
		CHECK(rc, "uet_recv");

		STEP(++step, "uet_cq_read() on the rx cq");
		{
			struct fi_cq_tagged_entry e[8];
			const char *w = getenv("UET_SMOKE_WAIT");
			time_t deadline;
			int got = 0;

			/* A fixed poll count is a timeout in disguise: every
			 * uet_cq_read() here is one shared-memory round trip
			 * (~1.1 us), so 2e6 polls was only ~2 s - less than the
			 * time it takes to start the client in another terminal,
			 * and it reported "nothing arrived" for a healthy path.
			 * Bound it by the wall clock, overridable for scripts. */
			deadline = time(NULL) + (w ? atoi(w) : 60);
			printf("     waiting up to %lds (UET_SMOKE_WAIT)\n",
			       (long)(w ? atoi(w) : 60));

			while (time(NULL) < deadline) {
				ssize_t n = uet_cq_read(rxcq, e, 8);

				if (n > 0) {
					size_t j, show = (e[0].len < 32) ?
							 e[0].len : 32;

					printf("     RECEIVED %zu bytes, "
					       "ctx=%p flags=0x%llx\n",
					       e[0].len, e[0].op_context,
					       (unsigned long long)e[0].flags);
					printf("     first bytes:");
					for (j = 0; j < show; j++)
						printf(" %02x",
						       (unsigned char)buf[j]);
					printf("\n");
					got = 1;
					break;
				}
				if ((n < 0) && (n != -FI_EAGAIN)) {
					struct fi_cq_err_entry ee;

					printf("     cq_read -> %zd\n", n);
					if (uet_cq_readerr(rxcq, &ee) > 0)
						printf("     cq err: err=%d "
						       "prov_errno=%d\n",
						       ee.err, ee.prov_errno);
					got = 1;   /* an error is still an outcome */
					break;
				}
			}
			if (!got)
				printf("     nothing arrived\n");
		}
		goto teardown;
	}

	if (argc < 2) {
		printf("\n(pass a peer IPv4 to send, or \"server\" to "
		       "receive)\n");
		goto teardown;
	}

	STEP(++step, "uet_av_insert()         [fi_av_insert] peer %s", argv[1]);
	memset(&peeraddr, 0, sizeof(peeraddr));
	peeraddr.ver = 0;
	peeraddr.flags = UET_ADDR_FEP_CAP_V | UET_ADDR_FA_V |
			 UET_ADDR_PID_ON_FEP_V | UET_ADDR_INDEX_V |
			 UET_ADDR_INITIATOR_V | UET_ADDR_RELATIVE_MODE |
			 UET_ADDR_IPV4 | UET_ADDR_BIG_MSG_SIZE;
	peeraddr.fep_cap = UET_FEP_CAP_AI_FULL | UET_FEP_CAP_HPC;
	peeraddr.fa.v4 = ntohl(inet_addr(argv[1]));
	peeraddr.pid_on_fep = myaddr.pid_on_fep;
	peeraddr.num_indices = 1;
	peeraddr.start_index = myaddr.start_index;
	peeraddr.initiator_id = myaddr.initiator_id;

	rc = uet_av_insert(dom, &peeraddr, &peer);
	CHECK(rc, "uet_av_insert");

	STEP(++step, "uet_send() 256 bytes");
	memset(buf, 0xA5, sizeof(buf));
	rc = (int)uet_send(ep, 0, buf, 256, mr, peer, (void *)0xBEEF);
	CHECK(rc, "uet_send");

	STEP(++step, "uet_cq_read() poll");
	{
		struct fi_cq_tagged_entry e[8];
		int i;

		/* generous: with ROD the PDC runs a SYN handshake first, and
		 * the PDS retransmit timer is 5 ms - a few hundred polls at
		 * sub-microsecond each is nowhere near long enough */
		for (i = 0; i < 2000000; i++) {
			ssize_t n = uet_cq_read(txcq, e, 8);

			if (n > 0) {
				printf("     completion: ctx=%p len=%zu "
				       "flags=0x%llx\n", e[0].op_context,
				       e[0].len,
				       (unsigned long long)e[0].flags);
				break;
			}
			if ((n < 0) && (n != -FI_EAGAIN)) {
				struct fi_cq_err_entry ee;

				printf("     cq_read -> %zd\n", n);
				if (uet_cq_readerr(txcq, &ee) > 0)
					printf("     cq err: err=%d "
					       "prov_errno=%d\n",
					       ee.err, ee.prov_errno);
				break;
			}
		}
		if (i == 2000000)
			printf("     no completion\n");
	}

teardown:
	/* close in reverse order of creation, as the provider does */
	printf("\n--- teardown ---\n");
	if (peer) uet_av_remove(peer);
	if (mr)   { uet_mr_disable(mr); uet_mr_close(mr); }
	if (ep)   uet_ep_close(ep);
	if (dom)  uet_domain_close(dom);
	if (uet)  uet_finalize(uet);
	printf("done\n");
	return 0;

out:
	printf("\nstopped at step %d\n", step);
	return 1;
}
