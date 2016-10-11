/**********************************************************************
* file:   dec_ethernet.cpp
* date:   Mon Mar 05 14:39:46 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to decode the ethernet header.
*
*
**********************************************************************/

#include "easySig.h"

u_int16_t decode_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet,char *print)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct moniSig_ether_header *eptr;
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct moniSig_ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    /*
    sprintf(print,"ETH: ");
    sprintf(print,"%s%s ->"
            ,print,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    sprintf(print,"%s%s ;"
            ,print,ether_ntoa((struct ether_addr*)eptr->ether_dhost));
    sprintf(print, "%stype: %04x", print, ether_type);

    */
    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        sprintf(print,"%s IP: ", print);
    }else  if (ether_type == ETHERTYPE_ARP)
    {
        //fprintf(stdout,"(ARP)");
    }else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        //fprintf(stdout,"(RARP)");
    }else {
        //fprintf(stdout,"(?)");
    }
    
    return ether_type;
}

