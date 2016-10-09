/**********************************************************************
* file:   prt_ip.h
* date:   Fri Mar 09 10:02:56 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   protocol IP header.
*
*
**********************************************************************/

#ifndef PRT_IP_H
#define PRT_IP_H

#include <netinet/ip.h>

struct moniSig_ip_header {
    u_int8_t    ip_vhl;        /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)    ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;        /* type of service */
    u_int16_t    ip_len;        /* total length */
    u_int16_t    ip_id;        /* identification */
    u_int16_t    ip_off;        /* fragment offset field */
#define    IP_DF 0x4000            /* dont fragment flag */
#define    IP_MF 0x2000            /* more fragments flag */
#define    IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
    u_int8_t    ip_ttl;        /* time to live */
    u_int8_t    ip_p;        /* protocol */
    u_int16_t    ip_sum;        /* checksum */
    struct    in_addr ip_src,ip_dst;    /* source and dest address */
};

/* IP protocol ID's */
#define    IPTYPE_ICMP        0x01          /* ICMP */
#define    IPTYPE_TCP        0x06          /* TCP */
#define    IPTYPE_UDP        0x11          /* UDP */

/* decode_ip defined in dec_ip.cpp*/
extern u_int8_t decode_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet, char *print);

#endif