#include"ProtocolAnalyse.h"

//memory counters
u_int32_t current_ndpi_memory=0,max_ndpi_memory=0;

//main struct 
struct ndpi_workflow
{
	//u_int32_t last time;
	pcap_t *handle;
	struct ndpi_detection_module_struct *ndpi_struct;
};
//declare main flow
struct ndpi_workflow *main_workflow;


/* ******************************************* */
/*             open pcap device                */
/* ******************************************* */
struct pcap_t* OpenPcapDevice()
{
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	devStr = "eth2";

	struct pcap_t *handle = NULL;
	handle = pcap_open_live(devStr, 65535, 1, 0, errBuf);
	if (handle)
	{
		printf("open success\n");
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
void SetupDetection(struct pcap_t *handle)
{
	NDPI_PROTOCOL_BITMASK all;
	main_workflow = ndpi_workflow_init(handle);
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(main_workflow->ndpi_struct,&all);
}



/* ******************************************* */
/*                  RunPcapLoop                */
/* ******************************************* */
void RunPcapLoop(struct pcap_t *handle)
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
		printf("gg\n");
		protocol = get_protocol(iph);
		printf("is not fragments\n");
		printf("%d\n",protocol.master_protocol);
	}
	else
	{
	//	get_whole_ip_packet(iph);
		//printf("is fragments\n");
		//return;
	}

//	get_whole_ip_packet(iph);

	//printf("protocol num = :%d\n",iph->protocol);
	//if(iph->frag_off & 0x1fff == )
	//printf("frag:%d\n",iph->frag_off);
	
}


/* ******************************************* */
/*            get protocol func                */
/* ******************************************* */
ndpi_protocol  get_protocol(struct ndpi_iphdr *iph)
{
	ndpi_protocol protocol={NDPI_PROTOCOL_UNKNOWN,NDPI_PROTOCOL_UNKNOWN};
//	protocol.app_protocol=NDPI_PROTOCOL_UNKNOWN;

	struct ndpi_flow_struct *ndpi_flow = (struct ndpi_flow_struct*)malloc(sizeof(struct ndpi_flow_struct));
	if(ndpi_flow==NULL)
	{
		printf("malloc failed\n");
		return protocol;
	}
	memset(ndpi_flow,0,sizeof(struct ndpi_flow_struct));
	//ndpi = get_ndpi_flow_info();
	protocol= ndpi_detection_process_packet(main_workflow->ndpi_struct,ndpi_flow,iph,iph->tot_len,1000,NULL,NULL);
	free(ndpi_flow);
	return protocol;
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

struct ndpi_workflow *ndpi_workflow_init(pcap_t *handle)
{
	set_ndpi_malloc(malloc_wrapper),set_ndpi_free(free_wrapper);
	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();
	struct ndpi_workflow *workflow = ndpi_calloc(1,sizeof(struct ndpi_workflow));
	workflow->handle = handle;
	workflow->ndpi_struct = module;
	if(workflow->ndpi_struct == NULL)
	{
		exit(-1);
	}
	return workflow;
}

