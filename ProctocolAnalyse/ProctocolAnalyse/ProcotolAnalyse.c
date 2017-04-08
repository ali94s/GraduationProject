#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include "ndpi_main.h" 

void ip_analyse(u_char *device, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int ret = pcap_datalink((pcap_t*)bytes);
	//printf("%d\n",ret);
	switch (ret)
	{
	case DLT_NULL:
		break;
	case DLT_PPP_SERIAL:
		break;
	case DLT_C_HDLC:
		break;
	case DLT_EN10MB:
		break;
#ifdef __linux__
	case DLT_LINUX_SLL:
		break;
#endif
	case DLT_IEEE802_11_RADIO:
		break;
	case DLT_RAW:
		break;
	default:
		printf("%d\n", ret);
		return;
	}
}


int main()
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

	pcap_loop(device, -1, ip_analyse, NULL);

	return 0;
}
