#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include"libndpi-1.8.0/libndpi/ndpi_main.h"
#include"libndpi-1.8.0/libndpi/ndpi_api.h"


#define SNAP 0xaa
//Open Device
struct pcap_t* OpenPcapDevice();

//Setup the ndpi arguments
static void SetupDetection(struct pcap_t *device);

//Run pcap_loop
static void RunPcapLoop(struct pcap_t *device);

//pcap_loop call back
void packet_analyse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet);

/* ******************************************* */
/*                  RunPcapLoop                */
/* ******************************************* */
static void RunPcapLoop(struct pcap_t *device)
{
	pcap_loop(device, -1, packet_analyse,(u_char*)device);
}

/* ******************************************* */
/*     call back packet analyse                */
/* ******************************************* */
void packet_analyse(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet)
{
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
	const int ret = pcap_datalink((struct pcap*)user);

	switch(ret)
	{
		/* IEEE 802.3 Ethernet */
		case DLT_EN10MB:
			ethernet = (struct ndpi_ethhdr*)&packet[eth_offset];
			ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
			check = ntohs(ethernet->h_proto);
			/* debug print */
			printf("%d\n",check);
			if(check <= 1500)
				pyld_eth_len = check;
			else if(check >= 1536)
				type = check;
			if(pyld_eth_len != 0)
				{
					if(packet[ip_offset] == SNAP)
					{
						llc = (struct ndpi_llc_header*)&(packet[ip_offset]);
						//type = llc->snap.proto_ID;
						ip_offset += 8;
					}
				}
		break;
		default:
			printf("Unknow link type\n");
		break;
		/* already get ip packet*/
		

	}

}


/* ******************************************* */
/*             open pcap device                */
/* ******************************************* */
struct pcap_t* OpenPcapDevice()
{
	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	devStr = "eth2";

	struct pcap_t *device = NULL;
	device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
	if (device)
	{
		printf("open success\n");
	}
	else
	{
		printf("open failed\n");
		exit(0);
	}
	return device;
}


/* ******************************************* */
/*      set ndpi protocol and arguments        */
/* ******************************************* */
static void SetupDetection(struct pcap_t *device)
{
	NDPI_PROTOCOL_BITMASK all;
	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(module,&all);
}


int main()
{
	struct pcap_t *device = OpenPcapDevice();
	
	//init ndpi struct
	SetupDetection(device);

	//run pcap_loop
	RunPcapLoop(device);
	
	return 0;
}
