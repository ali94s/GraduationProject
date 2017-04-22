#include"ProtocolAnalyse.h"
#define NUM_ROOTS 512
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
//memory counters
u_int32_t current_ndpi_memory=0,max_ndpi_memory=0;

//main struct 
struct ndpi_workflow
{
	//u_int32_t last time;
	pcap_t *handle;
	struct ndpi_detection_module_struct *ndpi_struct;
	void **ndpi_flow_root; 
};
//declare main flow
struct ndpi_workflow *main_workflow;


/* ******************************************* */
/*             open pcap device                */
/* ******************************************* */
struct pcap_t* open_pcapdevice()
{
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	devStr = "eth2";

	struct pcap_t *handle = NULL;
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

	/*for(i=0;i<hdr->len;++i)
	{
		printf("%02x ",packet[i]);
	}
	printf("\n");
    */
	/* already get ip packet*/
	iph = (struct ndpi_iphdr*)&(packet[ip_offset]);
	flag = ntohs(iph->frag_off);

//	printf("TOT_LEN = %d ",ntohs(iph->tot_len));
//	printf("DF = %d ",flag & 0x4000);
//	printf("MF = %d ",flag & IP_MF);
//	printf("OFFSET = %d\n",flag & IP_OFFSET);

	//not ip fragments
	if(((flag & IP_MF) == 0) && ((flag & IP_OFFSET) == 0))
	{
		protocol = get_protocol(iph,ip_offset,hdr->len-ip_offset);
		//printf("is not fragments\n");
		printf("%d\n",protocol.master_protocol);
	}
	else
	{
		iph = get_whole_ip_packet(iph);
		if(iph)
		{
			//get a whole ip packet
		}
		else
		{
			return ;
		}
	}
}




/* ******************************************* */
/*             regroup ip packets              */
/* ******************************************* */
struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph)
{
	
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
		sport = tcph->source;
		dport = tcph->dest;
	}
	//UDP
	else if(protocol == IPPROTO_UDP)
	{
		udph = (struct ndpi_udphdr*)&(iph[ip_header_len]);
		sport = udph->source;
		dport = udph->dest;
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
		return tmpflow;
	}
}



/* ******************************************* */
/*            get protocol func                */
/* ******************************************* */
ndpi_protocol  get_protocol(struct ndpi_iphdr *iph,u_int16_t ip_offset,u_int32_t ip_size)
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
		ndpi_flow = flow->ndpi_flow;
		//if(flow->detection_completed)
		//{
		//	return 0;
		//}
		//else
		//	{
		flow->detected_protocol= ndpi_detection_process_packet(main_workflow->ndpi_struct,ndpi_flow,iph,ip_size,1000,src,dst);
				//if(flow->detected_protocol.master_protocol == )
			//}
		return flow->detected_protocol;
	}
}





/* ******************************************* */
/*            get_whole_ip_packet              */
/* ******************************************* */

/*
struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph)
{
	struct ip_id_node* ret = find_node(iph);
	if(!ret)
	{
		add_node(iph);
	}

}
*/

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

