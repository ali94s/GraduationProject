#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#define IP_MF 0x2000     //0010 0000 0000 0000
#define IP_OFFSET 0x1fff    //offset part
#define SNAP 0xaa


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
struct pcap_t* OpenPcapDevice();

//Setup the ndpi arguments
void SetupDetection(struct pcap_t *handle);

//Run pcap_loop
void RunPcapLoop(struct pcap_t *device);

//pcap_loop call back
void packet_analyse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);

//get protocol func
ndpi_protocol  get_protocol(struct ndpi_iphdr *hdr);

//init workflow
struct ndpi_workflow *ndpi_workflow_init(pcap_t *handle);




//regroup ip fragments
//struct ndpi_iphdr* get_whole_ip_packet(struct ndpi_iphdr* iph);
