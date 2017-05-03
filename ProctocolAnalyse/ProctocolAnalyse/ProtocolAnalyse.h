#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#include<signal.h>
#include<sys/time.h>
#include<pthread.h>


#define IP_MF 0x2000     //0010 0000 0000 0000
#define IP_OFFSET 0x1fff    //offset part
#define SNAP 0xaa

//main struct 
struct ndpi_workflow
{
	//u_int32_t last time;
	pcap_t *handle;
	struct ndpi_detection_module_struct *ndpi_struct;
	void **ndpi_flow_root; 
};


//ndpi flow infstruct
struct ndpi_flow_info
{
	u_int32_t src;
	u_int32_t dst;
	u_int16_t sport;
	u_int16_t dport;
	u_int8_t detection_completed, protocol;
	struct ndpi_flow_struct *ndpi_flow;
	ndpi_protocol detected_protocol;
	void *src_id,*dst_id;
	u_int32_t packets;
	int data_len;
	struct timeval begin,end;
};




//some struct for ip regroup
struct sk_buff
{
	char *data;
	int truesize;
};


struct hostfrags
{
	struct ipq *ipqueue;  //ip fragments queue
	int ip_frag_mem;
	u_int ip;
	int hash_index;
	struct hostfrags *prev;
	struct hostfrags *next;
};

struct ipfrag
{
	int offset;
	int end;
	int len;
	struct sk_buff *skb;
	unsigned char *ptr;
	struct ipfrag *prev;
	struct ipfrag *next;
};

struct timer_list
{
	struct timer_list *prev;
	struct timer_list *next;
	int expires;
	void (*function)();
	unsigned long data;
};


struct ipq
{
	u_char *mac;
	struct ndpi_iphdr *iph;
	int32_t len;
	int16_t iplen;
	int16_t maclen;
	struct timer_list timer;
	struct ipfrag *fragments;
	struct hostfrag *hf;
	struct ipq *prev;
	struct ipq *next;
};





/*
struct ip_id_node
{
	u__int16_t id;
	//bool if_correct;
	struct ndpi_iphdr *next;
	struct ndpi_iphdr *prev;
};
void ip_node_init(struct ip_id_node *node)
{
	node->ip=-1;
	node->next = NULL;
	node->prev = NULL;
}
list<struct ip_id_node> ip_node_list;

struct ip_id_node* find_node(struct ndpi_iphdr* hdr);

void add_node(struct ndpi_iphdr* hdr);

void add_node(struct ndpi_iphdr* hdr)
{
	struct ip_id_node *new_node =(struct ip_id_node*)malloc(sizeof(hdr->tot_len));
	memcpy(new_node,iph,iph->tot_len);
}

struct ip_id_node* find_node(struct ndpi_iphdr* hdr)
{
	if(ip_node_list.empty())
	{
		return NULL;
	}
	list<struct	ip_id_node>::iterator it = ip_node_list.begin();
	for(;it!=ip_node_list.end();it++)
	{
		if(it->id == hdr->id)
			return &(*it);
	}
	return NULL;
}
*/

//Open Device
struct pcap_t* open_pcapdevice();

//Setup the ndpi arguments
void setup_detection(struct pcap_t *handle);

//Run pcap_loop
void run_pcaploop(struct pcap_t *device);

//pcap_loop call back
void packet_analyse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);

//get protocol func
void get_protocol(struct ndpi_iphdr *hdr,u_int16_t ip_offset,u_int32_t ip_size);

//init workflow
void ndpi_workflow_init(pcap_t *handle);

//get_ndpi_flow_info
struct get_ndpi_flow_info *get_nepi_flow_info(struct ndpi_iphdr *iph,u_int16_t ip_offset,struct ndpi_id_struct **src,struct ndpi_id_struct **dst);

//ndpi_node_com
int ndpi_node_com(const void *a,const void *b);




//regroup ip fragments
struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph);

//ip_defrag 
char* ip_defrag(struct ndpi_iphdr *iph,struct sk_buff *skb);

//hostfrag_find
int hostfrag_find(struct ndpi_iphdr* iph);

//calc hash index
int frag_index(struct ndpi_iphdr *iph);


//creat hostfrag
void hostfrag_create(struct ndpi_iphdr* iph);

void ip_evictor(void);
void kfree_skb(struct sk_buff *skb);
void ip_free(struct ipq * qp);
void del_timer(struct timer_list * x);
void frag_kfree_skb(struct sk_buff * skb);
void frag_kfree_s(void *ptr, int len);
void atomic_sub(int ile, int *co);
struct ipq *ip_find(struct ndpi_iphdr*iph);
int jiffies();
void ip_expire(unsigned long arg);
void add_timer(struct timer_list * x);
struct ipq* ip_create(struct ndpi_iphdr *iph);
void *frag_kmalloc(int size);
void atomic_add(int ile, int *co);
struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr);
int ip_done(struct ipq * qp);
char *ip_glue(struct ipq * qp);



//pthread
void init_time();
void init_sigaction();
void thread_fun(void *arg);
void do_timeout();


