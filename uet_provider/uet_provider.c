/* Referenced from libfabric providers prov/tcp/src/xnet_init.c, xnet_fabric.c, prov/verbs/src/verbs_init.c, verbs_domain.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "uet_api_private.h" 
#include <rdma/fabric.h>
#include <rdma/providers/fi_prov.h>
#include <rdma/fi_eq.h> 
//#include <ofi_enosys.h>	/* NEW (AV): fi_no_* stubs for AV ops we skip */

#include "uet_api.h"
 
#define UET_PROV_NAME "uet"
#define UET_MAJOR_VERSION 0
#define UET_MINOR_VERSION 1
#define UET_PROV_VERSION FI_VERSION(UET_MAJOR_VERSION, UET_MINOR_VERSION)
#define UET_FI_VERSION FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION)

/* uet's endpoint struct defaults job_id to 0. Using same here for now. Will be replaced with 
a real value one the SLURM interation on how job id is generated is defined */
#define UET_PROV_JOB_ID_PLACEHOLDER UET_DEF_JOB_ID

static int uet_prov_getinfo(uint32_t version, const char *node,
			     const char *service, uint64_t flags,
			     const struct fi_info *hints,
			     struct fi_info **info)
{
	uet_handle_t handle;
	int ret;
 
	(void) node;
	(void) service;
	(void) flags;

	// change 1
	/* make only RDM endpoints to execute by avoid other ep types */
	if (hints && hints->ep_attr &&
	    hints->ep_attr->type != FI_EP_UNSPEC &&
	    hints->ep_attr->type != FI_EP_RDM)
		return -FI_ENODATA;
 
	ret = uet_initialize(&handle);
	if (ret)
		return ret;
 
	ret = uet_getinfo(handle, NULL, hints, info);
	if (ret) {
		uet_finalize(handle);
		return ret;
	}
 
	/* libfabric’s internal code calls stdrup on fabric attr without null checks. 
	This patch avoids the crash. (found while debugging)*/
	{
		struct fi_info *cur;
		for (cur = *info; cur; cur = cur->next) {
			if (cur->fabric_attr && !cur->fabric_attr->name) {
				cur->fabric_attr->name =strdup(UET_PROV_NAME);
			}
			if(cur->domain_attr && !cur->domain_attr->name) {
				cur->domain_attr->name = strdup(UET_PROV_NAME);
			}

			/* while testing the data plane, found that other providers set default sizes, 
			but uet doesn't set default sizes, here setting them (if not set, fails since size is 0) */
			if(cur->rx_attr && cur->rx_attr->size == 0)
				cur->rx_attr->size = 64;
			if(cur->tx_attr && cur->tx_attr->size ==0)
				cur->tx_attr->size = 64;
			if(cur->tx_attr)
				cur->tx_attr->msg_order = FI_ORDER_SAS;
			if(cur->rx_attr)
				cur->rx_attr->msg_order = FI_ORDER_SAS;

			if(cur->ep_attr && cur->ep_attr->type ==FI_EP_UNSPEC){
                                cur->ep_attr->type = FI_EP_RDM;
                        }
			if(cur->ep_attr && cur->ep_attr->mem_tag_format==0)
				cur->ep_attr->mem_tag_format=FI_TAG_GENERIC;
			if(cur->nic && !cur->nic->bus_attr)
				cur->nic=NULL;
		}
	}
 
	uet_finalize(handle);
	return ret;
}

/* fid_fabric: holds uet_handle_t */
struct uet_prov_fabric{
	struct  fid_fabric fid;
	uet_handle_t uet_handle;
};

static int uet_prov_fabric_close(struct fid *fid)
{
	struct uet_prov_fabric *fab = container_of(fid, struct uet_prov_fabric, fid.fid);
	int ret = uet_finalize(fab->uet_handle);
	free(fab);
	return ret;
}

static struct fi_ops uet_prov_fabric_fi_ops = {
	.size=sizeof(struct fi_ops),
	.close=uet_prov_fabric_close,
};

/* fid_domain: holds uet_domain_handle_t */
struct uet_prov_domain{
	struct fid_domain fid;
	uet_domain_handle_t domain_handle;
};

static int uet_prov_domain_close(struct fid *fid)
{
	struct uet_prov_domain *dom=container_of(fid, struct uet_prov_domain, fid.fid);
	int ret = uet_domain_close(dom->domain_handle);
	free(dom);
	return ret;
}

static int uet_prov_domain_ops_open(struct fid *fid, const char *name, uint64_t flags, void **ops, void *context)
{
	(void)fid;
	(void)name;
	(void)flags;
	(void)ops;
	(void)context;
	return -FI_ENOSYS;
}

static struct fi_ops uet_prov_domain_fi_ops = {
	.size=sizeof(struct fi_ops),
	.close=uet_prov_domain_close,
	.ops_open=uet_prov_domain_ops_open,
};



/* fid_cq wrapper. UET creates CQ later (during fi_ep_bind) via
 uet_ep_bind_cq() (basically creates cq and binds at the same call)*/
#define UET_PROV_CQ_BINDS 32
struct uet_prov_cq {
	struct fid_cq fid;
	struct fi_cq_attr attr;	     		//used later
	/* each CQ (tx/rx) has its own handle (debugged when caused cq error from uet-ref-prov)*/
	uet_cq_handle_t tx_cq_handle[UET_PROV_CQ_BINDS];		//empty until cq is bound with endpoint
	uet_cq_handle_t rx_cq_handle[UET_PROV_CQ_BINDS];
	int num_tx_bound;						/*can be used to track the state (bound or not), 
										when we call uet_cq_bind we can assign bound=1*/
	int num_rx_bound;
	int rx_pos;
	int tx_pos;
};

static int uet_prov_cq_close(struct fid *fid)
{
	struct uet_prov_cq *cq = container_of(fid, struct uet_prov_cq, fid.fid);
	free(cq);
	return 0;
}

static struct fi_ops uet_prov_cq_fi_ops = {
	.size=sizeof(struct fi_ops),
	.close=uet_prov_cq_close,
};

/*Forward to uet_cq_read()/uet_cq_readerr() - fns in uet-ref-prov. Before CQ
is bound to endpoint, there is nothing to read. So -FI_EAGAIN(modified 
while debugging)*/
static ssize_t uet_prov_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
//	fprintf(stderr,"provider: %s\n",__func__);
	struct uet_prov_cq *ucq = container_of(cq, struct uet_prov_cq, fid);
	ssize_t ret=-FI_EAGAIN;
//	fprintf(stderr, "CQ POLL: cq=%p rx_cq_handle=%p tx_cq_handle=%p\n",(void*)ucq,(void*)ucq->rx_cq_handle,
//											(void*)ucq->tx_cq_handle);
	int i,idx;
	for(i=0;i<ucq->num_rx_bound;i++){
	//	if(ucq->rx_bound){
		idx = (ucq->rx_pos+i)%ucq->num_rx_bound;
		ret = uet_cq_read(ucq->rx_cq_handle[idx], buf, count);
//		fprintf(stderr, "CQ READ rx:ret=%zd\n",ret);
		if(ret>0) {
			ucq->rx_pos=(idx+1)%ucq->num_rx_bound;
			return ret;
		}
		if(ret<0) return ret;
	}
	for(i=0;i<ucq->num_tx_bound;i++){
//	if(ucq->tx_bound){
		idx=(ucq->tx_pos+i)%ucq->num_tx_bound;
		ret= uet_cq_read(ucq->tx_cq_handle[idx], buf, count);
//		fprintf(stderr, "CQ READ tx:ret=%zd\n",ret);
		if(ret!=0) {
			ucq->tx_pos=(idx+1)%ucq->num_tx_bound;
			return ret;
		}
	}
	return -FI_EAGAIN;
}

static ssize_t uet_prov_cq_readerr(struct fid_cq *cq, 
				struct fi_cq_err_entry *buf, uint64_t flags)
{
	struct uet_prov_cq *ucq = container_of(cq, struct uet_prov_cq, fid);
	ssize_t ret;
	(void)flags;
	int i;
	for(i=0;i<ucq->num_rx_bound;i++){
//	if(ucq->rx_bound){
                ret= uet_cq_readerr(ucq->rx_cq_handle[i], buf);
		if(ret!=0) return ret;
	}
	for(i=0;i<ucq->num_tx_bound;i++){
//        if(ucq->tx_bound){ 
                ret= uet_cq_readerr(ucq->tx_cq_handle[i], buf);
		if(ret!=0) return ret;
	}
        return -FI_EAGAIN;

}

/* there seems to be no sread implementation in uet-ref-prov (need to be verified once)*/
static ssize_t uet_prov_cq_sread(struct fid_cq *cq, void *buf, size_t count,
			const void *cond, int timeout)
{
	(void)cq;
	(void)buf;
	(void)count;
	(void)cond;
	(void)timeout;
	return -FI_ENOSYS;
}

static const char *uet_prov_cq_strerror(struct fid_cq *cq, int prov_errno, 
				const void *err_data, char *buf, size_t len)
{
	const char *str = fi_strerror(prov_errno);
	(void)cq;
	(void)err_data;
	if(buf &&len){
		strncpy(buf,str,len-1);
		buf[len-1]='\0';
		return buf;
	}
	return str;
}

static struct fi_ops_cq uet_prov_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = uet_prov_cq_read,
	.readerr = uet_prov_cq_readerr,
	.sread = uet_prov_cq_sread,
	.strerror = uet_prov_cq_strerror,
};

/* since uet-ref-prov doesn't have direct CQ support and cq is created during fi_ep_bind */
static int uet_prov_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
			struct fid_cq **cq, void *context)
{
	struct uet_prov_cq *ucq;
	(void)domain;

	ucq = calloc(1,sizeof(*ucq));
	if(!ucq)
		return -FI_ENOMEM;
	if(attr)
		ucq->attr = *attr;
	ucq->fid.fid.fclass = FI_CLASS_CQ;
	ucq->fid.fid.context = context;
	ucq->fid.fid.ops = &uet_prov_cq_fi_ops;
	ucq->fid.ops = &uet_prov_cq_ops;

	*cq = &ucq->fid;
	return 0;
}

// new code 
/*
 * uet-ref-prov has no AV object. It only has uet_av_insert(), which
 * takes ONE peer address and returns a handle.
 *  So our AV is a simple table:
 *     fi_addr_t (number the app uses) = index into table[]
 *     table[index].handle             = what uet-ref-prov needs
 */
#define UET_PROV_AV_DEF_SIZE 64

struct uet_prov_av_entry {
	struct uet_addr addr;		
	uet_addr_handle_t handle;	
	int used;
};

struct uet_prov_av {
	struct fid_av fid;		
	struct uet_prov_domain *dom;	
	struct uet_prov_av_entry *table;	
	size_t count;			
	size_t size;			
};

// fi_av_insert() 
static int uet_prov_av_insert(struct fid_av *av_fid, const void *addr,
			      size_t count, fi_addr_t *fi_addr,
			      uint64_t flags, void *context)
{
	struct uet_prov_av *av = container_of(av_fid, struct uet_prov_av, fid);
	const struct uet_addr *addrs = addr;
	struct uet_prov_av_entry *e;
	fi_addr_t idx;
	int inserted = 0;
	size_t i,j;

	(void)flags;
	(void)context;

	for (i = 0; i < count; i++) {
	    int found=0;
	    	for(j=0;j<av->count;j++){
			if(av->table[j].used && memcmp(&av->table[j].addr, &addrs[i], sizeof(struct uet_addr))==0){
				if(fi_addr) fi_addr[i]=j;
				found=1;
				inserted++;
				break;
			}
		}
		if(found) continue;

		if (av->count >= av->size) {		/* table full */
			if (fi_addr)
				fi_addr[i] = FI_ADDR_NOTAVAIL;
			continue;
		}

		idx = av->count++;			
		e = &av->table[idx];
		e->addr = addrs[i];			

		if (uet_av_insert(av->dom->domain_handle, &e->addr, &e->handle)) {
			if (fi_addr)
				fi_addr[i] = FI_ADDR_NOTAVAIL;
			continue;
		}

		e->used = 1;
		if (fi_addr)
			fi_addr[i] = idx;		
		inserted++;
	}
	return inserted;			
}

/*fi_av_remove -> uet_av_remove */
static int uet_prov_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr, size_t count,
				uint64_t flags)
{
	struct uet_prov_av *av = container_of(av_fid, struct uet_prov_av, fid);
	size_t i;
	(void)flags;
	for(i=0;i<count;i++){
		size_t idx=(size_t) fi_addr[i];
		if(idx>=av->count || !av->table[idx].used)
			continue;
		if(uet_av_remove(av->table[idx].handle)==0)
			av->table[idx].used=0;
	}
	return 0;
}

/* fi_close(av): remove every peer from uet-ref-prov, then free */
static int uet_prov_av_close(struct fid *fid)
{
	struct uet_prov_av *av = container_of(fid, struct uet_prov_av, fid.fid);
	size_t i;
	int ret;

	for (i = 0; i < av->count; i++) {
		if (!av->table[i].used)
			continue;
		ret = uet_av_remove(av->table[i].handle);
		if (ret)
			return ret;	/* still in use (sends in flight), try again later */
		av->table[i].used = 0;
	}
	free(av->table);
	free(av);
	return 0;
}

static struct fi_ops uet_prov_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = uet_prov_av_close,
//	.bind = fi_no_bind,
//	.control = fi_no_control,
//	.ops_open = fi_no_ops_open,
};

static struct fi_ops_av uet_prov_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = uet_prov_av_insert,
//	.insertsvc = fi_no_av_insertsvc,	
//	.insertsym = fi_no_av_insertsym,
	.remove = uet_prov_av_remove,
//	.lookup = fi_no_av_lookup,
//	.straddr = fi_no_av_straddr,
};

/* fi_av_open(): create the AV and its table */
static int uet_prov_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
			    struct fid_av **av_fid, void *context)
{
	struct uet_prov_domain *dom = container_of(domain, struct uet_prov_domain, fid);
	struct uet_prov_av *av;

	av = calloc(1, sizeof(*av));
	if (!av)
		return -FI_ENOMEM;

	av->size = (attr && attr->count) ? attr->count : UET_PROV_AV_DEF_SIZE;
	av->table = calloc(av->size, sizeof(*av->table));
	if (!av->table) {
		free(av);
		return -FI_ENOMEM;
	}
	av->dom = dom;

	av->fid.fid.fclass = FI_CLASS_AV;
	av->fid.fid.context = context;
	av->fid.fid.ops = &uet_prov_av_fi_ops;
	av->fid.ops = &uet_prov_av_ops;

	*av_fid = &av->fid;
	return 0;
}


/* fi_endpoint - wrapper */
struct uet_prov_ep {
	struct fid_ep fid;
	uet_ep_handle_t ep_handle;
	struct uet_prov_av *av;
};

/*
 * The AV lookup is the only way the four send paths can fail before they
 * reach uet-ref-prov, and a bare -FI_EINVAL from here is indistinguishable
 * from one raised deeper in the stack. Say which of the three conditions
 * fired, because they have completely different causes: no AV bound to the
 * endpoint, an index past what this AV holds, or a slot whose uet_av_insert()
 * failed and left used == 0.
 */
static void uet_prov_av_lookup_failed(const char *who, struct uet_prov_ep *uep,
				      fi_addr_t addr)
{
	fprintf(stderr,
		"[uet_prov] %s refused: ep=%p av=%p addr=%lu count=%zu used=%d\n",
		who, (void *)uep, (void *)(uep ? uep->av : NULL),
		(unsigned long)addr,
		(uep && uep->av) ? uep->av->count : (size_t)0,
		(uep && uep->av && addr < uep->av->count) ?
			uep->av->table[addr].used : -1);
}

/* uet_prov_ep_close() -> uet_ep_close() */
static int uet_prov_ep_close(struct fid *fid)
{
	struct uet_prov_ep *ep = container_of(fid, struct uet_prov_ep, fid.fid);
	int ret = uet_ep_close(ep->ep_handle);
	free(ep);
	return ret;
}

static int uet_prov_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct uet_prov_ep *ep = container_of(fid, struct uet_prov_ep, fid.fid);
	/* uet assigns cq separately for tx and rx. Bind both to ep*/
	if(bfid->fclass == FI_CLASS_CQ) {
		struct uet_prov_cq *cq = container_of(bfid, struct uet_prov_cq, fid.fid);
		int ret;

		// bind the CQ to the endpoint for send and/or receive, depending on the flags
		if(flags & FI_SEND){
			if(cq->num_tx_bound>=UET_PROV_CQ_BINDS)
				return -FI_ENOSPC;
			ret = uet_ep_bind_cq(ep->ep_handle, &cq->attr, &cq->fid, FI_SEND, NULL,
                                        &cq->tx_cq_handle[cq->num_tx_bound]);
			if(ret)	return ret;
			cq->num_tx_bound++;
		}
		if(flags & FI_RECV){
			if(cq->num_rx_bound>=UET_PROV_CQ_BINDS)
                                return -FI_ENOSPC;
			ret = uet_ep_bind_cq(ep->ep_handle, &cq->attr, &cq->fid, FI_RECV, NULL,
                                        &cq->rx_cq_handle[cq->num_rx_bound]);
			if(ret)	return ret;
			cq->num_rx_bound++;
		}
		return 0;
	}
	if(bfid->fclass == FI_CLASS_EQ)
		return 0;
	if(bfid->fclass == FI_CLASS_AV)
		ep->av = container_of(bfid, struct uet_prov_av, fid.fid);
		return 0;
	return -FI_ENOSYS;
}

static int uet_prov_ep_control(struct fid *fid, int command, void *arg)
{
	struct uet_prov_ep *ep = container_of(fid, struct uet_prov_ep, fid.fid);
	(void)arg;
	if(command == FI_ENABLE)
		return uet_ep_enable(ep->ep_handle);
	return -FI_ENOSYS;
}

static struct fi_ops uet_prov_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = uet_prov_ep_close,
	.bind = uet_prov_ep_bind,
	.control = uet_prov_ep_control,
};

static int uet_prov_ep_setopt(fid_t fid, int level, int optname, const void *optval, size_t optlen)
{
	(void)fid;
	(void)level;
	(void)optname;
	(void)optval;
	(void)optlen;
	return -FI_ENOPROTOOPT;
}
static int uet_prov_ep_getopt(fid_t fid, int level, int optname, void *optval, size_t *optlen)
{
        (void)fid;
        (void)level;
        (void)optname;
        (void)optval;
        (void)optlen;
        return -FI_ENOPROTOOPT;
}

static struct fi_ops_ep uet_prov_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.setopt= uet_prov_ep_setopt,
	.getopt= uet_prov_ep_getopt,
};

/* fid_mr wrapper. uet_mr_regattr() is a stub in uet-ref-prov. uet_mr_reg->uet_mr_regv*/
struct uet_prov_mr {
	struct fid_mr fid;
	uet_mr_handle_t mr_handle;
	int enabled;
};
static int uet_prov_mr_close(struct fid *fid)
{
	struct uet_prov_mr *mr = container_of(fid,struct uet_prov_mr, fid.fid);
	int ret;
	if(mr->enabled){ 
		ret = uet_mr_disable(mr->mr_handle);
		if(ret)
			return ret;
		mr->enabled=0;
	}
	ret = uet_mr_close(mr->mr_handle);
	if(ret)	return ret;
	free(mr);
	return 0;
}

static int uet_prov_mr_bind(struct fid *fid,struct fid *bfid, uint64_t flags)
{
	struct uet_prov_mr *mr = container_of(fid,struct uet_prov_mr, fid.fid);
        struct uet_prov_ep *ep;
//	int ret;
        if(bfid->fclass!=FI_CLASS_EP)
                return -FI_ENOSYS;
        ep=container_of(bfid, struct uet_prov_ep, fid.fid);
        return uet_ep_bind_mr(ep->ep_handle,mr->mr_handle,flags);
//	if(ret)	return ret;
//	return uet_mr_enable(mr->mr_handle);
}

static int uet_prov_mr_control(struct fid *fid,int command, void *arg)
{
	struct uet_prov_mr *mr = container_of(fid, struct uet_prov_mr, fid.fid);
	(void)arg;
	int ret;
	if(command!=FI_ENABLE)
		return -FI_ENOSYS;
	ret= uet_mr_enable(mr->mr_handle);
	if(!ret)
		mr->enabled=1;
	return ret;
}

static struct fi_ops uet_prov_mr_fi_ops = {
	.size=sizeof(struct fi_ops),
	.close=uet_prov_mr_close,
	.bind = uet_prov_mr_bind,
	.control = uet_prov_mr_control,
};

static int uet_prov_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr, uint64_t flags,
				struct fid_mr **mr){
	struct uet_prov_domain *dom=container_of(fid, struct uet_prov_domain, fid.fid);
	struct uet_prov_mr *umr;
	int ret;
	
	if(attr->iov_count!=1) return -FI_ENOSYS;
	umr = calloc(1,sizeof(*umr));
	if(!umr) return -FI_ENOMEM;

//	fprintf(stderr,"MR regattr: iface=%d base=%p len=%zu\n",attr->iface,attr->mr_iov[0].iov_base,attr->mr_iov[0].iov_len);
	ret = uet_mr_reg(dom->domain_handle,attr->mr_iov[0].iov_base, attr->mr_iov[0].iov_len,
			attr->access, attr->requested_key, flags, attr->context, &umr->mr_handle);
	if(ret){
		free(umr);
		return ret;
	}

	umr->fid.fid.fclass = FI_CLASS_MR;
	umr->fid.fid.context = attr->context;
	umr->fid.fid.ops = &uet_prov_mr_fi_ops;
	umr->fid.mem_desc = umr->mr_handle;
	umr->fid.key = uet_mr_key(umr->mr_handle);

	*mr = &umr->fid;
	return 0;
}
static struct fi_ops_mr uet_prov_mr_ops = {
	.size=sizeof(struct fi_ops_mr),
	.regattr=uet_prov_mr_regattr,
};



/*
 * fi_getname(ep) -> here.
 * Returns this endpoint's own address (struct uet_addr); the peer then passes these bytes to
 * fi_av_insert().
 *
 * uet-ref-prov fills ep->uet_addr inside uet_endpoint() (fi_endpoint),
 * so this works right after fi_endpoint, even before fi_enable.
 */
static int uet_prov_ep_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct uet_prov_ep *ep = container_of(fid, struct uet_prov_ep, fid.fid);
	struct uet_addr ua;
	size_t have;
	int ret;

	if (!addrlen)
		return -FI_EINVAL;

	ret = uet_getname(ep->ep_handle, &ua);
	if (ret)
		return ret;

	have = *addrlen;
	*addrlen = sizeof(ua);	

	if (addr && have)
		memcpy(addr, &ua, have < sizeof(ua) ? have : sizeof(ua));

	return have < sizeof(ua) ? -FI_ETOOSMALL : 0;
}

static int uet_prov_no_setname(fid_t fid, void *addr, size_t addrlen)
{
	(void)fid; (void)addr; (void)addrlen;
	return -FI_ENOSYS;
}

static int uet_prov_no_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	(void)ep; (void)addr; (void)addrlen;
	return -FI_ENOSYS;
}

static int uet_prov_no_connect(struct fid_ep *ep, const void *addr,
			       const void *param, size_t paramlen)
{
	(void)ep; (void)addr; (void)param; (void)paramlen;
	return -FI_ENOSYS;
}

static int uet_prov_no_listen(struct fid_pep *pep)
{
	(void)pep;
	return -FI_ENOSYS;
}

static int uet_prov_no_accept(struct fid_ep *ep, const void *param,
			      size_t paramlen)
{
	(void)ep; (void)param; (void)paramlen;
	return -FI_ENOSYS;
}

static int uet_prov_no_reject(struct fid_pep *pep, fid_t handle,
			      const void *param, size_t paramlen)
{
	(void)pep; (void)handle; (void)param; (void)paramlen;
	return -FI_ENOSYS;
}

static int uet_prov_no_shutdown(struct fid_ep *ep, uint64_t flags)
{
	(void)ep; (void)flags;
	return -FI_ENOSYS;
}

static struct fi_ops_cm uet_prov_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = uet_prov_no_setname,
	.getname = uet_prov_ep_getname,
	.getpeer = uet_prov_no_getpeer,
	.connect = uet_prov_no_connect,
	.listen = uet_prov_no_listen,
	.accept = uet_prov_no_accept,
	.reject = uet_prov_no_reject,
	.shutdown = uet_prov_no_shutdown,
	/* .join left NULL: fi_join() checks it with FI_CHECK_OP -> -FI_ENOSYS */
};


static ssize_t uet_prov_msg_recv(struct fid_ep *ep, void *buf, size_t len, void *desc, 
			fi_addr_t src_addr, void *context)
{
	struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
	uet_addr_handle_t src;
	/* doesn't know who is sending yet, so accept from any src.*/
	if(src_addr == FI_ADDR_UNSPEC){
//		fprintf(stderr, "DEBUG WILDCARD CHECK: av=%p count=%zu table0_used=%d\n",
//		(void *)uep->av,
//		uep->av ? uep->av->count : 0,
//		(uep->av && uep->av->count > 0) ? uep->av->table[0].used : -1);
		if(uep->av && uep->av->count>0 && uep->av->table[0].used){
			src = uep->av->table[0].handle;
		}else{
			src=UET_NULL_HANDLE;
		}
	}else{
	/*App gives a real peer address, convert it back to real pointer. */
		src = (uet_addr_handle_t)(uintptr_t)src_addr;
	}
	return uet_recv(uep->ep_handle, UET_JOB_ID_ANY, buf, len,
					(uet_mr_handle_t)desc, src, context);
}

static ssize_t uet_prov_msg_send(struct fid_ep *ep, const void *buf, size_t len,
			void *desc, fi_addr_t dest_addr, void *context)
{
struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
        /* send has a destination address */
        uet_addr_handle_t dest; 
        // = (uet_addr_handle_t)(uintptr_t)dest_addr;
        if(!uep->av || dest_addr >= uep->av->count || !uep->av->table[dest_addr].used) {
                uet_prov_av_lookup_failed(__func__, uep, dest_addr);
                return -FI_EINVAL;
        }
        dest = uep->av->table[dest_addr].handle;
	ssize_t ret;
        return uet_send(uep->ep_handle, UET_PROV_JOB_ID_PLACEHOLDER, (void *)buf, len,
                                        (uet_mr_handle_t)desc, dest, context);
}


static ssize_t uet_prov_msg_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
                                uint64_t flags)
{
        struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
                uet_addr_handle_t dest;

        (void) flags;   

        /* msg->addr is an AV index, not a handle: look it up, same as tagged_send */
        if (!uep->av || msg->addr >= uep->av->count ||
            !uep->av->table[msg->addr].used) {
                uet_prov_av_lookup_failed(__func__, uep, msg->addr);
                return -FI_EINVAL;
        }
        dest = uep->av->table[msg->addr].handle;

        /* uet_sendmsg() in uet-ref-prov is only a stub (returns -FI_ENOSYS),
         * so send through uet_sendv(), which is implemented */
        return uet_sendv(uep->ep_handle, UET_PROV_JOB_ID_PLACEHOLDER,
                          msg->msg_iov, msg->iov_count,
                          msg->desc ? (uet_mr_handle_t)msg->desc[0] : UET_NULL_HANDLE,
                          dest, msg->context);
}



static ssize_t uet_prov_tagged_recv(struct fid_ep *ep, void *buf, size_t len, void *desc, 
                        fi_addr_t src_addr,uint64_t tag, uint64_t ignore, void *context)
{
//	fprintf(stderr,"provider: %s\n",__func__);
	struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
	uet_addr_handle_t src;
	struct iovec iov;
	/* doesn't know who is sending yet, so accept from any src.*/
        if(src_addr == FI_ADDR_UNSPEC){
                if(uep->av && uep->av->count>0 && uep->av->table[0].used){
                        src = uep->av->table[0].handle;
                }else{
                        src=UET_NULL_HANDLE;
		}
        }else{
        /*App gives a real peer address, convert it back to real pointer. */
                src = (uet_addr_handle_t)(uintptr_t)src_addr;
	}
//	fprintf(stderr,
//        "UET BRIDGE TRECV: ep=%p src=%p tag=0x%lx ignore=0x%lx len=%zu ctx=%p\n",
//        (void *)uep->ep_handle,
//        (void *)src,
//        (unsigned long)tag,
//        (unsigned long)ignore,
//        len,
//        context);

	iov.iov_base = buf;
	iov.iov_len = len;
        ssize_t ret= uet_trecvv(uep->ep_handle, UET_JOB_ID_ANY, &iov, 1,
                                        (uet_mr_handle_t)desc, src,tag,ignore, context);
//	fprintf(stderr, "TRECV on ep=%p ret=%zd\n",(void*)uep->ep_handle,ret);
	return ret;
}

static int first_send_count=0;
static ssize_t uet_prov_tagged_send(struct fid_ep *ep, const void *buf, size_t len,
                        void *desc, fi_addr_t dest_addr,uint64_t tag, void *context)
{
//	fprintf(stderr,"provider: %s\n",__func__);
        struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
	uet_addr_handle_t dest; 
	struct iovec iov;

        // = (uet_addr_handle_t)(uintptr_t)dest_addr;
        if(!uep->av || dest_addr >= uep->av->count || !uep->av->table[dest_addr].used) {
                uet_prov_av_lookup_failed(__func__, uep, dest_addr);
                return -FI_EINVAL;
        }
        dest = uep->av->table[dest_addr].handle;
//	if(first_send_count<4){
//		first_send_count++;
//		sleep(1);
//	}
//	ssize_t ret;
//	fprintf(stderr,
//        "UET BRIDGE TSEND: ep=%p dest=%p tag=0x%lx len=%zu ctx=%p\n",
//        (void *)uep->ep_handle,
//        (void *)dest,
//        (unsigned long)tag,
//        len,
//        context);
	
	iov.iov_base=(void*)buf;
	iov.iov_len=len;
        ssize_t ret= uet_tsendv(uep->ep_handle, UET_PROV_JOB_ID_PLACEHOLDER, &iov, 1,
                                        (uet_mr_handle_t)desc, dest,tag, context);
//	fprintf(stderr, "TSEND on ep=%p ret=%zd\n",(void*)uep->ep_handle,ret);
//	fprintf(stderr,"SEND context passed in=%p\n",context);
	return ret;
}


// uet_sendmsg() is a stub in uet-ref-prov, so we implement fi_sendmsg() by calling uet_tsendv() instead.
static ssize_t uet_prov_tagged_sendmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
				uint64_t flags)
{
	struct uet_prov_ep *uep = container_of(ep, struct uet_prov_ep, fid);
		uet_addr_handle_t dest;

	(void) flags;	

	/* msg->addr is an AV index, not a handle: look it up, same as tagged_send */
	if (!uep->av || msg->addr >= uep->av->count ||
	    !uep->av->table[msg->addr].used) {
		uet_prov_av_lookup_failed(__func__, uep, msg->addr);
		return -FI_EINVAL;
	}
	dest = uep->av->table[msg->addr].handle;

	/* uet_tsendmsg() in uet-ref-prov is only a stub (returns -FI_ENOSYS),
	 * so send through uet_tsendv(), which is implemented */
	return uet_tsendv(uep->ep_handle, UET_PROV_JOB_ID_PLACEHOLDER,
			  msg->msg_iov, msg->iov_count,
			  msg->desc ? (uet_mr_handle_t)msg->desc[0] : UET_NULL_HANDLE,
			  dest, msg->tag, msg->context);
}

static struct fi_ops_tagged uet_prov_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = uet_prov_tagged_recv,
	.send = uet_prov_tagged_send,
	.sendmsg = uet_prov_tagged_sendmsg,
};



static struct fi_ops_msg uet_prov_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = uet_prov_msg_recv,
	.send = uet_prov_msg_send,
	.sendmsg = uet_prov_msg_sendmsg,
};



static int uet_prov_endpoint_open(struct fid_domain *domain, struct fi_info *info,
			struct fid_ep **ep, void *context)
{
	struct uet_prov_domain *dom = container_of(domain, struct uet_prov_domain, fid);
	struct uet_prov_ep *uep;
	int ret;
	uep=calloc(1,sizeof(*uep));
	if(!uep)
		return -FI_ENOMEM;

	uep->fid.fid.fclass = FI_CLASS_EP;
	uep->fid.fid.context = context;
	uep->fid.fid.ops = &uet_prov_ep_fi_ops;
	uep->fid.ops = &uet_prov_ep_ops;
	uep->fid.msg = &uet_prov_msg_ops;
	uep->fid.cm = &uet_prov_ep_cm_ops;	/* fi_getname() */
	uep->fid.tagged = &uet_prov_tagged_ops;
	ret = uet_endpoint(dom->domain_handle, info, &uep->fid, context, &uep->ep_handle);
	if(ret){
		free(uep);
		return ret;
	}
//	fprintf(stderr, "EP CREATE: uet_ep=%p context=%p\n",(void*)uep->ep_handle,context);

	*ep=&uep->fid;
	return 0;
}

static struct fi_ops_domain uet_prov_domain_ops = {
	.size=sizeof(struct fi_ops_domain),
	.av_open = uet_prov_av_open,		/* NEW: fi_av_open() comes here */
	.cq_open = uet_prov_cq_open,
	.endpoint = uet_prov_endpoint_open,
};

/* fi_domain() -> uet_domain() */
static int uet_prov_domain_open(struct fid_fabric *fabric, struct fi_info *info, 
			struct fid_domain **domain, void *context)
{
	struct uet_prov_fabric *fab = container_of(fabric, struct uet_prov_fabric, fid);
	struct uet_prov_domain *dom;
	int ret;

	dom = calloc(1, sizeof(*dom));
	if(!dom)
		return -FI_ENOMEM;

	dom->fid.fid.fclass = FI_CLASS_DOMAIN;
	dom->fid.fid.context = context;
	dom->fid.fid.ops = &uet_prov_domain_fi_ops;
	dom->fid.ops = &uet_prov_domain_ops;
	dom->fid.mr = &uet_prov_mr_ops;

	ret = uet_domain(fab->uet_handle, fabric, info, &dom->fid, context, NULL, NULL, 
		&dom->domain_handle);
	if(ret) {
		free(dom);
		return ret;
	}
	*domain = &dom->fid;
	return 0;
}

/* fi_eq wrapper - Since uet-ref-prov doesn't have eq support, all parameter is set to void, 
return failure (FI_EAGAIN) Stub implementations*/
struct uet_prov_eq{
        struct fid_eq fid;
};

static int uet_prov_eq_close(struct fid *fid)
{
        struct uet_prov_eq *eq=container_of(fid, struct uet_prov_eq, fid.fid);
        free(eq);
        return 0;
}

static struct fi_ops uet_prov_eq_fi_ops = {
        .size = sizeof(struct fi_ops),
        .close = uet_prov_eq_close,
};

static ssize_t uet_prov_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
                        size_t len, uint64_t flags)
{
        (void)eq;
        (void) event;
        (void) buf;
        (void) len;
        (void) flags;
        return -FI_EAGAIN;
}

static ssize_t uet_prov_eq_readerr(struct fid_eq *eq, 
                                struct fi_eq_err_entry *buf, uint64_t flags)
{
        (void)eq;
        (void)buf;
        (void)flags;
        return -FI_EAGAIN;
}

static ssize_t uet_prov_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
                        size_t len, int timeout, uint64_t flags)
{
        (void)eq;
        (void)event;
        (void)buf;
        (void)len;
        (void)timeout;
        (void) flags;
        return -FI_EAGAIN;
}

static struct fi_ops_eq uet_prov_eq_ops = {
        .size=sizeof(struct fi_ops_eq),
        .read=uet_prov_eq_read,
        .readerr=uet_prov_eq_readerr,
        .sread=uet_prov_eq_sread,
};

static int uet_prov_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
                        struct fid_eq **eq, void *context)
{
        struct uet_prov_eq *ueq;
        (void)fabric;
        (void)attr;
        ueq=calloc(1,sizeof(*ueq));
        if(!ueq)
                return -FI_ENOMEM;

        ueq->fid.fid.fclass = FI_CLASS_EQ;
        ueq->fid.fid.ops = &uet_prov_eq_fi_ops;
        ueq->fid.ops = &uet_prov_eq_ops;
		ueq->fid.fid.context = context;
        *eq = &ueq->fid;
        return 0;
}

static struct fi_ops_fabric uet_prov_fabric_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = uet_prov_domain_open,
	.eq_open = uet_prov_eq_open,
};



/* fi_fabric() -> uet_initialize() */
static int uet_prov_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric, void *context)
{
	struct uet_prov_fabric *fab;
	int ret;

	fab=calloc(1,sizeof(*fab));
	if(!fab)
		return -FI_ENOMEM;
	ret = uet_initialize(&fab->uet_handle);

	if(ret){
		free(fab);
		return ret;
	}

	fab->fid.fid.fclass=FI_CLASS_FABRIC;
	fab->fid.fid.context=context;
	fab->fid.fid.ops=&uet_prov_fabric_fi_ops;
	fab->fid.ops=&uet_prov_fabric_ops;

	// can cause seg fault if attribute is null!
	if(attr)
		fab->fid.api_version=attr->api_version;
	else
		fab->fid.api_version=UET_FI_VERSION;
	//fab->fid.api_version=attr->api_version;

	*fabric = &fab->fid;
	return 0;
}

static void uet_prov_cleanup(void)
{
}

struct fi_provider uet_prov = {
	// changes made here to use UET_MAJOR_VERSION and UET_MINOR_VERSION for fi_version
	.version = UET_PROV_VERSION,
	.fi_version = UET_FI_VERSION,
	.name = UET_PROV_NAME,
	.getinfo = uet_prov_getinfo,
	.fabric = uet_prov_fabric,
	.cleanup = uet_prov_cleanup,
};

FI_EXT_INI
{
	return &uet_prov;
}
