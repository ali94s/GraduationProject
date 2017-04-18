#include"ProtocolAnalyse.h"

int main()
{
	struct pcap_t *device = OpenPcapDevice();
	
	//init ndpi struct
	SetupDetection(device);

	//run pcap_loop
	RunPcapLoop(device);
	
	return 0;
}
