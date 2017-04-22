#include"ProtocolAnalyse.h"
//#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
//struct ndpi_flow_struct *ndpi_flow;
//void *src,*dst;
int main()
{
/*	
	ndpi_flow = (struct ndpi_flow_struct*)malloc(sizeof(struct ndpi_flow_struct));
	if(ndpi_flow==NULL)
	{
		printf("malloc failed\n");
		return 0;
	}
	memset(ndpi_flow,0,sizeof(struct ndpi_flow_struct));
	src = ndpi_malloc(SIZEOF_ID_STRUCT);
	if(src == NULL)
	{
		return 0;
	}
	memset(src,0,SIZEOF_ID_STRUCT);
	dst = ndpi_malloc(SIZEOF_ID_STRUCT);
	if(dst == NULL)
	{
		return 0;
	}
	memset(dst,0,SIZEOF_ID_STRUCT);
*/	
	
	struct pcap_t *device = open_pcapdevice();
	
	//init ndpi struct
	setup_detection(device);

	//run pcap_loop
	run_pcaploop(device);
	
	return 0;
}
