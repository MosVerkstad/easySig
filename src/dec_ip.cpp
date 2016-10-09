/**********************************************************************
* file:   dec_ip.cpp
* date:   Tue Mar 06 10:53:28 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to decode the IP header.
*
*
**********************************************************************/

#include "easySig.h"

u_int8_t decode_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet,char *print)
{
    const struct moniSig_ip_header* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int len;

    /* jump pass the ethernet header */
    ip = (struct moniSig_ip_header*)(packet + sizeof(struct moniSig_ether_header));
    length -= sizeof(struct moniSig_ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct moniSig_ip_header))
    {
        printf("truncated ip %d",length);
        return 0;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return 0;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        sprintf(print,"%s%s->", print,
                inet_ntoa(ip->ip_src));
        sprintf(print,"%s%s\ttos: 0x%02x\theaderLen: %d\tbodyLen: %d\tprotocol: 0x%02x ", print,
                inet_ntoa(ip->ip_dst),ip->ip_tos,
                hlen,len, ip->ip_p);
    }

    return ip->ip_p;
}