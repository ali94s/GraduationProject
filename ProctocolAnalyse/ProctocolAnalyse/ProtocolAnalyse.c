#include"ProtocolAnalyse.h"


#define HASH_SIZE 64
#define NUM_ROOTS 512
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define IPFRAG_HIGH_THRESH            (256*1024)
#define IPFRAG_LOW_THRESH            (192*1024)
#define IP_FRAG_TIME     (30 * 1000)   /* fragment lifetime */
//memory counters
u_int32_t current_ndpi_memory=0,max_ndpi_memory=0;

//declare main flow
struct ndpi_workflow *main_workflow;

//hashtable
struct hostfrags **fragtable;
int hash_flag = 0;
struct hostfrags *this_host;
static int numpacket =0;
static int timenow;
static u_int32_t time0;
static struct timer_list *timer_head = 0,*timer_tail=0;



/* ******************************************* */
/*             create thread                   */
/* ******************************************* */
void do_timeout()
{
	//  use main_workflow->ndpi_flow_root  
	printf("do timeout\n");
}

void init_sigaction()
{
	struct sigaction tact;
	tact.sa_handler=do_timeout;
	tact.sa_flags=0;

	sigemptyset(&tact.sa_mask);

	sigaction(SIGALRM,&tact,NULL);
}

void init_time()
{
	struct itimerval value;
	value.it_value.tv_sec =2;
	value.it_value.tv_usec=0;
	//gettimeofday(&(value.it_interval));
	value.it_interval=value.it_value;
	setitimer(ITIMER_REAL,&value,NULL);
}

void thread_fun(void *arg)
{
	init_sigaction();
	init_time();
	while(1);
}

void thread_create()
{
	pthread_t pid;
	int ret;
	if((ret=pthread_create(&pid,NULL,thread_fun,main_workflow->ndpi_flow_root))==-1)
	{
		perror("pthread failed");
		exit(EXIT_FAILURE);
	}
}












/* ******************************************* */
/*             open pcap device                */
/* ******************************************* */
struct pcap_t* open_pcapdevice()
{
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	devStr = "eth2";

	struct pcap_t *handle = NULL;
	/*char file[]="3.pcap";
	if(handle=pcap_open_offline(file,errBuf)==NULL)
	{
		printf("error\n");
		return 0;
	}*/
	handle = pcap_open_live(devStr, 65535, 1, 0, errBuf);
	if (handle)
	{
		printf("open sucess\n");
	}
	else
	{
		printf("open failed\n");
		exit(0);
	}
	
	return handle;
}


/* ******************************************* */
/*      set ndpi protocol and arguments        */
/* ******************************************* */
void setup_detection(struct pcap_t *handle)
{
	NDPI_PROTOCOL_BITMASK all;
	ndpi_workflow_init(handle);
	main_workflow->ndpi_struct->http_dont_dissect_response=0;
	main_workflow->ndpi_struct->dns_dissect_response=0;
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(main_workflow->ndpi_struct,&all);
}



/* ******************************************* */
/*                  RunPcapLoop                */
/* ******************************************* */
void run_pcaploop(struct pcap_t *handle)
{
	pcap_loop(handle, -1, packet_analyse,(u_char*)handle);
}


/* ******************************************* */
/*     call back packet analyse                */
/* ******************************************* */
void packet_analyse(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	int i =0;
	/*for(i=0;i<hdr->len;++i)
	{
		printf("%02x ",packet[i]);
	}
	printf("\n");*/
	


	//only deal with DLT_EN10MB
	const struct ndpi_ethhdr *ethernet;
	//llc header
	const struct ndpi_llc_header *llc;
	//ip header
	struct ndpi_iphdr *iph;

	u_int16_t eth_offset = 0;
	u_int16_t ip_offset = 0;
	u_int16_t type = 0;
	int pyld_eth_len = 0;
	int check = 0;
	int flag = 0;
	ndpi_protocol  protocol;
	//u_char *packet_check=malloc(hdr->caplen);
	//memcpy(packet_check,packet,hdr->caplen);
	//system("pause");
	const int eth_type = pcap_datalink((struct pcap*)user);
	switch(eth_type)
	{
		/* IEEE 802.3 Ethernet */
		case DLT_EN10MB:
			ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;


			check = ntohs(ethernet->h_proto);
			/* debug print */
			//printf("%d\n",check);
			if(check <= 1500)  //length of data frame
				pyld_eth_len = check;

			else if(check >= 1536) //type
				type = check;
			if(pyld_eth_len != 0)
				{
				if(packet[ip_offset] == SNAP)
					{
						printf("llc\n");
						llc = (struct ndpi_llc_header*)&(packet[ip_offset]);
						//type = llc->snap.proto_ID;
						ip_offset += 8;
					}
				}
		break;
		default:
			printf("Unknow link type\n");
		break;
	}
	printf("type=%d\n",type);
	/* already get ip packet*/
	iph = (struct ndpi_iphdr*)&(packet[ip_offset]);
	/*if(iph->protocol == IPPROTO_UDP)
	{
		printf("UDP\n");
	}*/
	flag = ntohs(iph->frag_off);

//	printf("TOT_LEN = %d ",ntohs(iph->tot_len));
//	printf("DF = %d ",flag & 0x4000);
//	printf("MF = %d ",flag & IP_MF);
//	printf("OFFSET = %d\n",flag & IP_OFFSET);

	//not ip fragments
	if(((flag & IP_MF) == 0) && ((flag & IP_OFFSET) == 0))
	{
		get_protocol(iph,ip_offset,hdr->len-ip_offset);
		//printf("is not fragments\n");
		//if(protocol.master_protocol!=0)
		//printf("%d\n",protocol.master_protocol);
	}
	else
	{
		//iph = get_whole_ip_packet(iph);
		if(iph)
		{
		}
		else
		{
			return ;
		}
	}
	return ;
}






/* ******************************************* */
/*             ndpi_node_com                   */
/* ******************************************* */
int ndpi_node_com(const void *a,const void *b)
{
	struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
	struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;
	if(fa->src < fb->src)
		return (-1);
	else
	{
		if(fa->src > fb->src)
			return (1);
	}
	if(fa->dst < fb->dst)
		return (-1);
	else
	{
		if(fa->dst > fb->dst)
			return (1);
	}
	if(fa->sport < fb->sport)
		return (-1);
	else
	{
		if(fa->sport > fb->sport)
			return (1);
	}
	if(fa->dport < fb->dport)
		return (-1);
	else
	{
		if(fa->dport > fb->dport)
			return (1);
	}
	if(fa->protocol < fb->protocol)
		return (-1);
	else
	{
		if(fa->protocol > fb->protocol)
			return (1);
	}
	return 0;
}




/* ******************************************* */
/*          get_ndpi_flow_info                */
/* ******************************************* */
struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_iphdr *iph,u_int16_t ip_offset,struct ndpi_id_struct **src,struct ndpi_id_struct **dst)
{
	struct ndpi_tcphdr *tcph;
	struct ndpi_udphdr *udph;
	u_int32_t saddr,daddr,addr_tmp;
	u_int16_t sport,dport,port_tmp;
	u_int32_t ip_header_len;
	u_int8_t protocol;
	u_int32_t idx;
	struct ndpi_flow_info flow;
	void *ret;

	
	protocol = iph->protocol;
	ip_header_len = (iph->ihl)*4;
	saddr = iph->saddr;
	daddr = iph->daddr;

	//TCP
	if(protocol == IPPROTO_TCP)
	{
		tcph = (struct ndpi_tcphdr*)&(iph[ip_header_len]);
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
	}
	//UDP
	else if(protocol == IPPROTO_UDP)
	{
		udph = (struct ndpi_udphdr*)&(iph[ip_header_len]);
		sport = ntohs(udph->source);
		dport = ntohs(udph->dest);
	}
	else
	{
		sport = 0;
		dport = 0;
	}
	//use lower 
	if(saddr > daddr)
	{
		addr_tmp = saddr;
		saddr = daddr;
		daddr = addr_tmp;
		port_tmp = sport;
		sport = dport;
		dport = port_tmp;
	}


	flow.src = saddr;
	flow.dst = daddr;
	flow.sport = sport;
	flow.dport = dport;
	flow.protocol = protocol;

	idx = (saddr + daddr + sport + dport + protocol)%NUM_ROOTS;
	
	printf("idx=%d\n",idx);

	ret = ndpi_tfind(&flow,&main_workflow->ndpi_flow_root[idx],ndpi_node_com);
	if(ret == NULL)
	{
		struct ndpi_flow_info *newflow = (struct ndpi_flow_info *)malloc(sizeof(struct ndpi_flow_info));
		if(newflow == NULL)
		{
			printf("memory failed!\n");
			return 0;
		}
		memset(newflow,0,sizeof(struct ndpi_flow_info));
		newflow->src=saddr;
		newflow->dst=daddr;
		newflow->sport=sport;
		newflow->dport=dport;
		newflow->protocol=protocol;
		newflow->data_len=iph->tot_len-ip_header_len;

		if((newflow->ndpi_flow = ndpi_malloc(SIZEOF_FLOW_STRUCT)) == NULL)
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->ndpi_flow,0,SIZEOF_FLOW_STRUCT);
		if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) 
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->src_id,0,SIZEOF_ID_STRUCT);
		if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL)
		{
			free(newflow);
			return NULL;
		}
		else
			memset(newflow->dst_id,0,SIZEOF_ID_STRUCT);
		ndpi_tsearch(newflow, &main_workflow->ndpi_flow_root[idx], ndpi_node_com);
		*src = newflow->src_id;
		*dst = newflow->dst_id;
		return newflow;
	}
	else
	{
		struct ndpi_flow_info *tmpflow = *(struct ndpi_flow_info**)ret;
		if(tmpflow->src == saddr && tmpflow->dst == daddr && tmpflow->sport == sport && tmpflow->dport == dport && tmpflow->protocol == protocol)
		{
			*src = tmpflow->src_id;
			*dst = tmpflow->dst_id;
		}
		else
		{
			*src = tmpflow->dst_id;
			*dst = tmpflow->src_id;
		}
		tmpflow->data_len+=(iph->tot_len-ip_header_len);
		return tmpflow;
	}
}



/* ******************************************* */
/*            get protocol func                */
/* ******************************************* */
void get_protocol(struct ndpi_iphdr *iph,u_int16_t ip_offset,u_int32_t ip_size)
{
	struct ndpi_flow_info *flow = NULL;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	struct ndpi_id_struct *src, *dst;
	if(iph)
	{
		flow = get_ndpi_flow_info(iph,ip_offset,&src,&dst);
	}
	else
	{
		//ipv6
	}
	if(flow != NULL)
	{
		flow->packets++;
		ndpi_flow = flow->ndpi_flow;
	}
	else
		return;
	if(flow->detection_completed)
		return 0;
	flow->detected_protocol= ndpi_detection_process_packet(main_workflow->ndpi_struct,ndpi_flow,(u_char *)iph,ip_size,1000,src,dst);
	if((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) || ((flow->protocol == IPPROTO_UDP) && (flow->packets > 8)) || ((flow->protocol==IPPROTO_TCP) && (flow->packets > 10)))
	{
		flow->detection_completed=1;
	}
	if(flow->detection_completed)
	{
		if(flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		{
			flow->detected_protocol=ndpi_detection_giveup(main_workflow->ndpi_struct,flow->ndpi_flow);
		}
	}
	printf("%d\n",flow->detected_protocol.master_protocol);
}





/* ******************************************* */
/*            get_whole_ip_packet              */
/* ******************************************* */

void ip_frag_init()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	time0=tv.tv_sec;
	fragtable =(struct hostfrags **)calloc(HASH_SIZE,sizeof(struct hostfrags*));
	if(!fragtable)
	{
		printf("hashtable init failed\n");
		exit(0);
	}
	hash_flag =1;
}


int frag_index(struct ndpi_iphdr *iph)
{
	u_int32_t saddr=ntohs(iph->daddr);
	return saddr%HASH_SIZE;
}


int hostfrag_find(struct ndpi_iphdr *iph)
{
	int hash_index = frag_index(iph);
	struct hostfrags *hf;
	this_host = 0;
	for(hf=fragtable[hash_index];hf;hf=hf->next)
	{
		if(hf->ip == iph->saddr)
		{
			this_host=hf;
			break;
		}
	}
	if(!this_host)
		return 0;
	else
		return 1;
}

void hostfrag_create(struct ndpi_iphdr* iph)
{
	struct hostfrags *hf = (struct hostfrags*)malloc(sizeof(struct hostfrags));
	int hash_index = frag_index(iph);
	hf->prev = 0;
	hf->next = fragtable[hash_index];
	if (hf->next)
		hf->next->prev = hf;
	fragtable[hash_index] = hf;
	hf->ip = iph->daddr;
	hf->ipqueue = 0;
	hf->ip_frag_mem = 0;
	hf->hash_index = hash_index;
	this_host = hf;
}


void del_timer(struct timer_list * x)
{
	if (x->prev)
		x->prev->next = x->next;
	else
		timer_head = x->next;
	if (x->next)
		x->next->prev = x->prev;
	else
		timer_tail = x->prev;
}

static void
rmthis_host()
{
	int hash_index = this_host->hash_index;
	if (this_host->prev) 
	{
		this_host->prev->next = this_host->next;
		if (this_host->next)
			this_host->next->prev = this_host->prev;
	}
	else 
	{
		fragtable[hash_index] = this_host->next;
		if (this_host->next)
			this_host->next->prev = 0;
	}
	free(this_host);
	this_host = 0;
}

void frag_kfree_skb(struct sk_buff * skb)
{
	if (this_host)
		atomic_sub(skb->truesize, &this_host->ip_frag_mem);
	kfree_skb(skb);
}

void kfree_skb(struct sk_buff * skb)
{
	free(skb);
}


void frag_kfree_s(void *ptr, int len)
{
	if (this_host)
		atomic_sub(len, &this_host->ip_frag_mem);
	free(ptr);
}


void atomic_sub(int ile, int *co)
{
	 *co -= ile;
}

void ip_free(struct ipq * qp)
{

	struct ipfrag *fp;
	struct ipfrag *xp;
	/* Stop the timer for this entry. */
	del_timer(&qp->timer);
	/* Remove this entry from the "incomplete datagrams" queue. */
	if (qp->prev == NULL)
	{
		this_host->ipqueue = qp->next;
		if (this_host->ipqueue != NULL)
			this_host->ipqueue->prev = NULL;
		else
			rmthis_host();
	}
	else
	{
		qp->prev->next = qp->next;
		if (qp->next != NULL)
			qp->next->prev = qp->prev;
	}
	/* Release all fragment data. */
	fp = qp->fragments;
	while (fp != NULL) 
	{
		xp = fp->next;
		frag_kfree_skb(fp->skb);
		frag_kfree_s(fp, sizeof(struct ipfrag));
		fp = xp;
	}
	/* Release the IP header. */
	frag_kfree_s(qp->iph, 64 + 8);
	/* Finally, release the queue descriptor itself. */
	frag_kfree_s(qp, sizeof(struct ipq));
}




void ip_evictor(void)
{
	while (this_host->ip_frag_mem > IPFRAG_LOW_THRESH) 
	{
		if (!this_host->ipqueue)
			ip_free(this_host->ipqueue);
	}
}

struct ipq *ip_find(struct ndpi_iphdr*iph)
{
	struct ipq *qp;
	struct ipq *qplast;
	qplast = NULL;
	for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next) 
	{
		if (iph->id == qp->iph->id &&iph->saddr == qp->iph->saddr &&iph->daddr == qp->iph->daddr &&iph->protocol == qp->iph->protocol)
		{
			del_timer(&qp->timer);
			return (qp);
		}
	}
	return (NULL);
}



int jiffies()
{
	struct timeval tv;
	if (timenow)
		return timenow;
	gettimeofday(&tv, 0);
	timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;
	return timenow;
}



void ip_expire(unsigned long arg)
{
	struct ipq *qp;	   
	qp = (struct ipq *) arg;
	/* Nuke the fragment queue. */
	ip_free(qp);
}




void add_timer(struct timer_list * x)
{
	if (timer_tail) 
	{
		timer_tail->next = x;
		x->prev = timer_tail;
		x->next = 0;
		timer_tail = x;
	}
	else 
	{
		x->prev = 0;
		x->next = 0;
		timer_tail = timer_head = x;
	}
}


void atomic_add(int ile, int *co)
{
	  *co += ile;
}

void *frag_kmalloc(int size)
{
	void *vp = (void *) malloc(size);
	if (!vp)
		return NULL;
	atomic_add(size, &this_host->ip_frag_mem);
	return vp;
}

struct ipq* ip_create(struct ndpi_iphdr *iph)
{
	struct ipq *qp;
	int ihlen;
	qp = (struct ipq *) frag_kmalloc(sizeof(struct ipq));
	if (qp == NULL) 
	{
		//nids_params.no_mem("ip_create");
		return (NULL);
	}
	memset(qp, 0, sizeof(struct ipq));
	/* Allocate memory for the IP header (plus 8 octets for ICMP). */
	ihlen = iph->ihl * 4;
	//64bytes for ipheader 8bytes for icmp
	qp->iph = (struct ip *) frag_kmalloc(64 + 8);
	if (qp->iph == NULL) 
	{
		//NETDEBUG(printk("IP: create: no memory left !/n"));
		//nids_params.no_mem("ip_create");
		frag_kfree_s(qp, sizeof(struct ipq));
		return (NULL);
	}
	
	memcpy(qp->iph, iph, ihlen + 8);
	qp->len = 0;
	qp->iplen = ihlen;
	qp->fragments = NULL;
	qp->hf = this_host;
	/* Start a timer for this entry. */
	qp->timer.expires = jiffies() + IP_FRAG_TIME;  /* about 30 seconds     */
	qp->timer.data = (unsigned long) qp;  /* pointer to queue     */
	qp->timer.function = ip_expire;     /* expire function      */
	add_timer(&qp->timer);
	qp->prev = NULL;
	qp->next = this_host->ipqueue;
	if (qp->next != NULL)
		qp->next->prev = qp;
	this_host->ipqueue = qp;
	return (qp);
}

struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr)
{
	struct ipfrag *fp;
	fp = (struct ipfrag *) frag_kmalloc(sizeof(struct ipfrag));
	if (fp == NULL) 
	{
		//NETDEBUG(printk("IP: frag_create: no memory left !/n"));
		//nids_params.no_mem("ip_frag_create");
		return (NULL);
	}
	memset(fp, 0, sizeof(struct ipfrag));
	/* Fill in the structure. */
	fp->offset = offset;
	fp->end = end;
	fp->len = end - offset;
	fp->skb = skb;
	fp->ptr = ptr;
	/* Charge for the SKB as well. */
	this_host->ip_frag_mem += skb->truesize;
	return (fp);
}
				                                     
int ip_done(struct ipq * qp)
{
	struct ipfrag *fp;
	int offset;
	//zeq_final_frag
	/* Only possible if we received the final fragment. */
	if (qp->len == 0)
		return (0);
	/* Check all fragment offsets to see if they connect. */
	fp = qp->fragments;
	offset = 0;
	while (fp != NULL) {
		if (fp->offset > offset)
			return (0);         /* fragment(s) missing */
		offset = fp->end;
		fp = fp->next;
	}
	/* All fragments are present. */
	return (1);	
}

char *ip_glue(struct ipq * qp)
{
	char *skb;
	struct ndpi_iphdr *iph;
	struct ipfrag *fp;
	unsigned char *ptr;
	int count, len;
	/* Allocate a new buffer for the datagram. */
	len = qp->iplen + qp->len;
	if (len > 65535) 
	{
		//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
		ip_free(qp);
		return NULL;		
	}
	if ((skb = (char *) malloc(len)) == NULL) 
	{
		//nids_params.no_mem("ip_glue");
		ip_free(qp);
		return (NULL);
	}
	/* Fill in the basic details. */
	ptr = skb;
	memcpy(ptr, ((unsigned char *) qp->iph), qp->iplen);
	ptr += qp->iplen;
	count = 0;
	/* Copy the data portions of all fragments into the new buffer. */
	fp = qp->fragments;
	while (fp != NULL) 
	{
		if (fp->len < 0 || fp->offset + qp->iplen + fp->len > len) {
			//NETDEBUG(printk("Invalid fragment list: Fragment over size./n"));
			//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
			ip_free(qp);
			//kfree_skb(skb, FREE_WRITE);
			//ip_statistics.IpReasmFails++;
			free(skb);
			return NULL;
		}
		memcpy((ptr + fp->offset), fp->ptr, fp->len);
		count += fp->len;
		fp = fp->next;
	}
	/* We glued together all fragments, so remove the queue entry. */
	ip_free(qp);
	/* Done with all fragments. Fixup the new IP header. */
	iph = (struct ip *) skb;
	iph->frag_off = 0;
	iph->tot_len = htons((iph->ihl * 4) + count);
	// skb->ip_hdr = iph;
	//zeq_skb_2
	return (skb);
	
}






char *ip_defrag(struct ndpi_iphdr *iph,struct sk_buff *skb)
{
	struct ipfrag *prev, *next, *tmp;
	struct ipfrag *tfp;
	struct ipq *qp;
	char *skb2;
	unsigned char *ptr;
	int flags, offset;
	int i, ihl, end;
	if (!hostfrag_find(iph) && skb)
		hostfrag_create(iph);
	if(this_host)
		 if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)
			 ip_evictor();
	if(this_host)   
		qp = ip_find(iph);
	else
		qp = 0;
	offset = ntohs(iph->frag_off); //offset  lower3->frag heigh13->offset 
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	
	if (((flags & IP_MF) == 0) && (offset == 0)) 
	{
		if (qp != NULL)
			ip_free(qp);             /* Fragmented frame replaced by full
										unfragmented copy */
		return 0;
	}
	offset <<= 3;                   /* offset is in 8-byte chunks */
	ihl = iph->ihl * 4;

	if(qp!=NULL)
	{
		if (offset == 0) 
		{
		 //更新IP包头信息
			qp->iplen = ihl;
			memcpy(qp->iph, iph, ihl + 8);
		}
		//更新该ipq所对应分片包的失效期限
		del_timer(&qp->timer);
		qp->timer.expires = jiffies() + IP_FRAG_TIME;/* about 30 seconds */
		qp->timer.data = (unsigned long) qp;     /* pointer to queue */
		qp->timer.function = ip_expire; /* expire function */
		add_timer(&qp->timer);	
	}
	else
	{
		/*4.25....................................*/
		if ((qp = ip_create(iph)) == NULL) 
		{
			kfree_skb(skb);
			return NULL;
		}
	}
	 if (ntohs(iph->tot_len) + (int) offset > 65535) 
	 { 
		//nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);	
		 kfree_skb(skb);
		 return NULL;
	 }
	 end = offset+ntohs(iph->tot_len)-ihl;

	 
	 ptr = skb->data+ihl;

	 if((flags & IP_MF)==0)
		 qp->len=end;
	 prev = NULL;
	 for(next=qp->fragments;next!=NULL;next=next->next)
	 {
		 if(next->offset>=offset)
			 break;
		 prev=next;
	 }
	if(prev != NULL && offset < prev->end)
	{
		i=prev->end-offset;
		offset+=i;
		ptr+=i;
	}

	for(tmp=next;tmp!=NULL;tmp=tfp)
	{
		tfp=tmp->next;
		if(tmp->offset>=end)
			break;

		i=end-next->offset;
		tmp->len-=i;
		tmp->offset+=i;
		tmp->ptr+=i;
		if(tmp->len<=0)
		{
			if(tmp->prev!=NULL)
			{
				tmp->prev->next=tmp->next;
			}
			else
			{
				qp->fragments = tmp->next;
			}

			if(tmp->next!=NULL)
			{
				tmp->next->prev=tmp->prev;
			}
			next=tfp;
			frag_kfree_skb(tmp->skb);
			frag_kfree_s(tmp,sizeof(struct ipfrag));
		}
	}
	tfp = NULL; 
	tfp = ip_frag_create(offset, end, skb, ptr);
	if (!tfp)
	{
		//nids_params.no_mem("ip_defrag");
		kfree_skb(skb);	
		return NULL;
	}
		//将当前分片加入到prev和tem之间
		/* From now on our buffer is charged to the queues. */
	tfp->prev = prev;
	tfp->next = next;
	if (prev != NULL)
		prev->next = tfp;
	else
		qp->fragments = tfp;
	if (next != NULL)
		next->prev = tfp;
	//该分片所属的IP包是否可重组？
	if (ip_done(qp))
	{
		skb2 = ip_glue(qp);            /* glue together the fragments */
		//zeq_skb_3
		//继续将重建的ip 包首地址返回给调用函数ip_defrag_stub
		return (skb2);
	}
		return (NULL);
}




struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph)
{
	struct sk_buff *sk;
	if(hash_flag == 0)
		ip_frag_init();
	sk = (struct sk_buff *)malloc(iph->tot_len+sizeof(struct sk_buff));
	if(!sk)
	{
		//printf("sk memory failed\n");
		//nids_params.no_mem("ip_defrag_stub");
		return NULL;
	}
	sk->data = (char*)(sk+1);
	memcpy(sk->data,iph,iph->tot_len);
	return (struct ndpi_iphdr*)ip_defrag((struct ndpi_iphdr*)(sk->data),sk);

}

/* ******************************************* */
/*           ndpi_workflow_init                */
/* ******************************************* */
static void *malloc_wrapper(size_t size)
{
	current_ndpi_memory +=size;
	if(current_ndpi_memory > max_ndpi_memory)
		max_ndpi_memory = current_ndpi_memory;
	return malloc(size);
}

static void free_wrapper(void *freeable)
{
	free(freeable);
}

void ndpi_workflow_init(pcap_t *handle)
{
	set_ndpi_malloc(malloc_wrapper),set_ndpi_free(free_wrapper);
	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();
	main_workflow = calloc(1,sizeof(struct ndpi_workflow));
	main_workflow->handle = handle;
	main_workflow->ndpi_struct = module;
	main_workflow->ndpi_flow_root = calloc(NUM_ROOTS,sizeof(void*));
	if(main_workflow->ndpi_struct == NULL)
	{
		exit(-1);
	}
}

