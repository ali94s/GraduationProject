#include"ProtocolAnalyse.h"
//#include<signal.h>
//#include<sys/time.h>
//#include<unistd.h>

//#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
//struct ndpi_flow_struct *ndpi_flow;
//void *src,*dst;




int main()
{
	

	struct pcap_t *device = open_pcapdevice();
	
	//init ndpi struct
	setup_detection(device);

	//timeout system
	//init_sigaction();
	//init_time();
	thread_create();
	
	//run pcap_loop
	run_pcaploop(device);
	
	return 0;
}
