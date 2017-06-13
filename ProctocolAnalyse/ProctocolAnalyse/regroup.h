#include<sys/types.h>
#include<sys/time.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"
#include<stdlib.h>

#define IP_CE             0x8000   /* Flag: "Congestion" */
#define IP_DF             0x4000   /* Flag: "Don't Fragment" */
#define IP_MF            0x2000   /* Flag: "More Fragments" */
#define IP_OFFSET   0x1FFF  /* "Fragment Offset" part */
#define IPF_NEW 1
#define IPF_ISF 0
#define IPF_NOTF -1
#define HASH_SIZE 64
#define IPFRAG_HIGH_THRESH            (256*1024)
#define IPFRAG_LOW_THRESH            (192*1024)
#define IP_FRAG_TIME     (30 * 1000)   /* fragment lifetime */
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
	char *ptr;
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
	struct hostfrags *hf;
	struct ipq *prev;
	struct ipq *next;
};
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
struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff * skb,char *ptr);
int ip_done(struct ipq * qp);
char *ip_glue(struct ipq * qp);

