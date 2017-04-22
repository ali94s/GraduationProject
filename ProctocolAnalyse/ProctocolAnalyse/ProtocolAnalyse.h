#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#define IP_MF 0x2000     //0010 0000 0000 0000
#define IP_OFFSET 0x1fff    //offset part
#define SNAP 0xaa


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
ndpi_protocol  get_protocol(struct ndpi_iphdr *hdr,u_int16_t ip_offset,u_int32_t ip_size);

//init workflow
void ndpi_workflow_init(pcap_t *handle);

//get_ndpi_flow_info
struct get_ndpi_flow_info *get_nepi_flow_info(struct ndpi_iphdr *iph,u_int16_t ip_offset,struct ndpi_id_struct **src,struct ndpi_id_struct **dst);

//ndpi_node_com
int ndpi_node_com(const void *a,const void *b);




//regroup ip fragments
struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph);
