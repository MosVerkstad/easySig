/**********************************************************************
* file:   dev_if.cpp
* date:   Wed Oct 12 22:24:18 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to provide the function to get the first active device.
*
*
**********************************************************************/
#include "dev_if.h"

void getActiveDev(char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int i = 0;
    bool getFirst = false;
	
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    } else {
        printf("easySig: list all of available devices in the system:\n");
        for(d = alldevs; d ; d = d->next) {
            printf("\t%d,\t%s\t", ++i, d->name);
        
            pcap_addr_t *dev_addr; //interface address that used by pcap_findalldevs()
        
            for (dev_addr = d->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
                if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask && !getFirst) {
                    strcpy(dev, d->name);
                    getFirst = true;
                    printf(" <- which is selected.");
                }
            }
            printf("\n");
        }
        pcap_freealldevs(alldevs);
    }
}