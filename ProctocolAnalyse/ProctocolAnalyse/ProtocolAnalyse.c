#include"ProtocolAnalyse.h"
#include"mysql.h"
#include"trace.h"
//#include<sys/types.h>
#include<sys/syscall.h>
//#include"regroup.h"


#define FIN_TIMEOUT 40
#define TIMEOUT 101
#define INTERVAL 20   //time lag 
#define HASH_SIZE 64
#define NUM_ROOTS 512
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))
#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define IPFRAG_HIGH_THRESH            (256*1024)
#define IPFRAG_LOW_THRESH            (192*1024)
#define IP_FRAG_TIME     (30 * 1000)   /* fragment lifetime */



pid_t gettid()
{
	return syscall(SYS_gettid);
}



extern pthread_mutex_t lock;
extern MYSQL* mysql;
extern FILE* fd;
//memory counters
u_int32_t current_ndpi_memory=0,max_ndpi_memory=0;

//declare main flow
struct ndpi_workflow *main_workflow;
/*
char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_mod,ndpi_protocol proto, char *buf, u_int buf_len) 
{
	
	if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (proto.master_protocol != proto.app_protocol)) 
	{
		snprintf(buf, buf_len, "%s",ndpi_get_proto_name(ndpi_mod, proto.master_protocol));		    
	} else
		snprintf(buf, buf_len, "%s",ndpi_get_proto_name(ndpi_mod, proto.app_protocol));
	return(buf);
}
*/
void get_and_insert_mysql(struct ndpi_flow_info *tmpnode)
{
	//Trace("begin:sec=%d,usec=%d\n",tmpnode->begin.tv_sec,tmpnode->begin.tv_usec);
	//Trace("end:sec=%d,usec=%d\n",tmpnode->end.tv_sec,tmpnode->end.tv_usec);
	char buf[48];
	char data[512];
	char trans[30];
	if(tmpnode->protocol==6)
	{
		sprintf(trans,"%s","TCP");
	}
	else if(tmpnode->protocol==17)
		sprintf(trans,"%s","UDP");
	else if(tmpnode->protocol==1)
		sprintf(trans,"%s","ICMP");
	else
		sprintf(trans,"%s","other");
	snprintf(buf,sizeof(buf),"%s",ndpi_get_proto_name(main_workflow->ndpi_struct,(tmpnode->detected_protocol).master_protocol));
	if(tmpnode->begin.tv_sec!=tmpnode->end.tv_sec || tmpnode->begin.tv_usec!=tmpnode->end.tv_usec)
	{
		sprintf(data,"insert into FlowAnalyse(PriIP,ExIP,PriPort,ExPort,Trans,App,BeginTime,EndTime,Flow,Packets)values('%s','%s',%d,%d,'%s','%s',%d,%d,%d,%d)",tmpnode->saddr,tmpnode->daddr,\
		tmpnode->sport,tmpnode->dport,trans,buf,tmpnode->begin.tv_sec,\
		tmpnode->end.tv_sec,tmpnode->data_len,tmpnode->packets);
		insert_mysql(mysql,data);
	}

}


void check_node(ndpi_node *root)
{
	struct ndpi_flow_info *tmpnode;
	tmpnode=(struct ndpi_flow_info*)(root->key);
	int node_timeout;
	int fin_timeout;
	struct timeval com_time;
	//char buf[64];
	//ndpi_protocol2name(main_workflow->ndpi_struct,tmpnode->detected_protocol,buf,sizeof(buf));
	gettimeofday(&com_time,NULL);
	
	node_timeout=com_time.tv_sec-tmpnode->end.tv_sec;
	if(tmpnode->outnode!=1)
	{
		//TCP
		if(tmpnode->protocol==IPPROTO_TCP)
		{
			if(tmpnode->detection_completed==1)    //get protocol already
			{
				if(tmpnode->status==1)
				{
					fin_timeout=node_timeout;
					if(fin_timeout>=FIN_TIMEOUT)
					{
						get_and_insert_mysql(tmpnode);
						tmpnode->outnode=1;
					}
				}
				else
				{
					if(node_timeout>=TIMEOUT)
					{
						get_and_insert_mysql(tmpnode);
						tmpnode->outnode=1;
					}
				}
			}
			else  //not get protocol
			{
				if(node_timeout>=TIMEOUT)
				{
					tmpnode->outnode=1;
				}
			}
		}
		//UDP or either
		else
		{
			if(tmpnode->detection_completed==1)
			{
				if(node_timeout>=TIMEOUT)
				{
					get_and_insert_mysql(tmpnode);
					tmpnode->outnode=1;
				}
			}
			else
			{
				if(node_timeout>=TIMEOUT)
					{
						tmpnode->outnode=1;
					}
			}
		}
	}
}


void prevorder_tree(ndpi_node *root)
{
	if(root!=(ndpi_node*)0)
	{
		check_node(root);
		prevorder_tree(root->left);
		prevorder_tree(root->right);
	}
}

void do_timeout()
{
	//  use main_workflow->ndpi_flow_root  
	Trace("do timeout\n");
	pthread_mutex_lock(&lock);
	int i=0;
	struct ndpi_node** root;
	for(;i<NUM_ROOTS;i++)
	{
		root =((ndpi_node**)(&(main_workflow->ndpi_flow_root[i])));
		if(root==(ndpi_node**)0)
			continue;
		if(*root != (ndpi_node*)0)
		{
		//	printf("%x\n",root);
		//	printf("idx(i)=%d\n",i);
			prevorder_tree(*root);
		}
	}
	pthread_mutex_unlock(&lock);
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
	value.it_value.tv_sec = INTERVAL;
	value.it_value.tv_usec=0;
	//gettimeofday(&(value.it_interval));
	value.it_interval=value.it_value;
	setitimer(ITIMER_REAL,&value,NULL);
}

void thread_fun(void *arg)
{
	//Trace("%d\n",gettid());
	init_sigaction();
	init_time();
	while(1)
		;
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
	//only deal with DLT_EN10MB
	const struct ndpi_ethhdr *ethernet;
	//llc header
	//const struct ndpi_llc_header *llc;
	//ip header
	struct ndpi_iphdr *iph;

	u_int16_t eth_offset = 0;
	u_int16_t ip_offset = 0;
//	u_int16_t type = 0;
//	int pyld_eth_len = 0;
//	int check = 0;
	int flag = 0;
	struct ndpi_iphdr **defrag;
	
	ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
	ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;

//	const int eth_type = pcap_datalink((struct pcap*)user);
	/*switch(eth_type)
	{
		// IEEE 802.3 Ethernet 
		case DLT_EN10MB:
			ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;


			check = ntohs(ethernet->h_proto);
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
						ip_offset += 8;
					}
				}
		break;
		default:
			printf("Unknow link type\n");
		break;
	}*/
	iph = (struct ndpi_iphdr*)&(packet[ip_offset]);
	flag = ntohs(iph->frag_off);

	Trace("rec data\n");
	//not ip fragments
	if(((flag & IP_MF) == 0) && ((flag & IP_OFFSET) == 0))
	{
		get_protocol(iph,ip_offset,hdr->len-ip_offset);
	}
	else
	{
		//iph = get_whole_ip_packet(iph);
		if(iph)
		{
			/*Trace("is frag\n");
			if(ip_defrag_stub(iph,defrag)==1)
			{
				Trace("yes\n");
				return ;
			}
			else
			{
				Trace("\n");
				return ;
			}*/
		 	if(ip_defrag_stub(iph,defrag)==1)
			{
				get_protocol((struct ndpi_iphdr*)*defrag,0,(struct ndpi_iphdr*)(*defrag)->tot_len);
			}
			
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
	if(fa->lower_src < fb->lower_src)
		return (-1);
	else
	{
		if(fa->lower_src > fb->lower_src)
			return (1);
	}
	if(fa->lower_dst < fb->lower_dst)
		return (-1);
	else
	{
		if(fa->lower_dst > fb->lower_dst)
			return (1);
	}
	if(fa->lower_sport < fb->lower_sport)
		return (-1);
	else
	{
		if(fa->lower_sport > fb->lower_sport)
			return (1);
	}
	if(fa->lower_dport < fb->lower_dport)
		return (-1);
	else
	{
		if(fa->lower_dport > fb->lower_dport)
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
	struct timeval write_time;
	int data_len;

	gettimeofday(&write_time,NULL);
	protocol = iph->protocol;
	Trace("protocol=%d\n",protocol);
	ip_header_len = (iph->ihl)*4;
	saddr = iph->saddr;
	daddr = iph->daddr;
	
	//TCP
	if(protocol == IPPROTO_TCP)
	{
		tcph = (struct ndpi_tcphdr*)((char *)iph+ip_header_len);
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		Trace("sport=%d,dport=%d\n",sport,dport);
		data_len=ntohs(iph->tot_len)-ip_header_len-(tcph->doff)*4;
	}
	//UDP
	else if(protocol == IPPROTO_UDP)
	{
		udph = (struct ndpi_udphdr*)((char *)iph+ip_header_len);
		sport = ntohs(udph->source);
		dport = ntohs(udph->dest);
		data_len=ntohs(iph->tot_len)-ip_header_len-8;
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


	flow.lower_src = saddr;
	flow.lower_dst = daddr;
	flow.lower_sport = sport;
	flow.lower_dport = dport;
	flow.protocol = protocol;

	idx = (saddr + daddr + sport + dport + protocol)%NUM_ROOTS;
	//printf("result=%ld\n",saddr+daddr+sport+dport+protocol);	
	//printf("nodeidx=%d\n",idx);
get_node:
	ret = ndpi_tfind(&flow,&main_workflow->ndpi_flow_root[idx],ndpi_node_com);
	//Trace("ndpi_tfind\n");
	if(ret == NULL)
	{
		if(protocol == IPPROTO_TCP)
		{
			if(tcph->syn!=1 || tcph->ack!=0)
			{
				return 0;
			}
		}
	//	printf("ret==NULL\n");
		struct ndpi_flow_info *newflow = (struct ndpi_flow_info *)malloc(sizeof(struct ndpi_flow_info));
		if(newflow == NULL)
		{
			printf("memory failed!\n");
			return 0;
		}
		memset(newflow,0,sizeof(struct ndpi_flow_info));
		newflow->lower_src=saddr;
		newflow->lower_dst=daddr;
		newflow->lower_sport=sport;
		newflow->lower_dport=dport;
		newflow->protocol=protocol;
		newflow->data_len=data_len;
		newflow->begin=write_time;
		newflow->end=write_time;
		if(iph->protocol==IPPROTO_TCP)
		{
			
			if(tcph->fin==1)
			{
				newflow->status=1;   //end
			}
			else
			{
				newflow->status=-1;  //not end
			}
		}
		//printf("beginwrite:%d\n",newflow->begin.tv_sec);
		//printf("endwrite:%d\n",newflow->end.tv_sec);
		
		
		//set ip addr and port
		inet_ntop(AF_INET,&(iph->saddr),newflow->saddr,sizeof(newflow->saddr));
		inet_ntop(AF_INET,&(iph->daddr),newflow->daddr,sizeof(newflow->daddr));
		if(iph->protocol==IPPROTO_TCP)
		{
			newflow->sport=ntohs(tcph->source);
			newflow->dport=ntohs(tcph->dest);
		}
		if(iph->protocol==IPPROTO_UDP)
		{
			newflow->sport=ntohs(udph->source);
			newflow->dport=ntohs(udph->dest);
		}

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
		if(tmpflow->outnode==1)
		{
			//Trace("DELETE\n");
			ndpi_tdelete(tmpflow,&main_workflow->ndpi_flow_root[idx],ndpi_node_com);
			goto get_node;
		}
		if(iph->protocol==IPPROTO_TCP)
		{
			if(tcph->fin==1)
			{
				tmpflow->status=1;
			}
		}
		if(tmpflow->lower_src == saddr && tmpflow->lower_dst == daddr && tmpflow->lower_sport == sport && tmpflow->lower_dport == dport && tmpflow->protocol == protocol)
		{
			*src = tmpflow->src_id;
			*dst = tmpflow->dst_id;
		}
		else
		{
			*src = tmpflow->dst_id;
			*dst = tmpflow->src_id;
		}
		tmpflow->data_len+=data_len;
		tmpflow->end=write_time;
		//printf("%x\n",&tmpflow);
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
		pthread_mutex_lock(&lock);
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
	{
		pthread_mutex_unlock(&lock);
		return;
	}
	if(flow->detection_completed)
	{
		pthread_mutex_unlock(&lock);
		return;
	}
	flow->detected_protocol= ndpi_detection_process_packet(main_workflow->ndpi_struct,ndpi_flow,(u_char *)iph,ip_size,1000,src,dst);
	if((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) || ((flow->protocol == IPPROTO_UDP) && (flow->packets > 8)) || ((flow->protocol==IPPROTO_TCP) && (flow->packets > 10)))
	{
		flow->detection_completed=1;
	}
	if(flow->detection_completed)
	{
		if(flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		{
			//flow->detected_protocol=ndpi_detection_giveup(main_workflow->ndpi_struct,flow->ndpi_flow);
			flow->outnode=1;  //if next packet come get new node
		}
	}
	pthread_mutex_unlock(&lock);
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
	//memset(&(main_workflow->ndpi_flow_root),0,sizeof(void*)*NUM_ROOTS);
}

