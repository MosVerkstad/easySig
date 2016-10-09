/**********************************************************************
* file:   dec_icmp.cpp
* date:   Fri Apr 06 21:15:43 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to decode the ICMP header.
*
*
**********************************************************************/

#include "easySig.h"

void decode_ICMP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet, char *print)
{
    const struct moniSig_icmp_header *icmp;
    
    icmp = (const struct moniSig_icmp_header *)(packet + sizeof(struct moniSig_ether_header) + sizeof(struct moniSig_ip_header));
    sprintf(print, "%s\tICMP type: %d", print, icmp->icmp_type);
}