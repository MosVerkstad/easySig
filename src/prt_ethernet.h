/**********************************************************************
* file:   prt_ethernet.h
* date:   Thu Mar 01 10:23:26 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   protocol ethernet header.
*
*
**********************************************************************/

#ifndef PRT_ETHERNET_H
#define PRT_ETHERNET_H

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

/* ETHER_HDRLEN defined in netinet/ether.h */
struct moniSig_ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];    /* destination eth addr    */
  u_int8_t  ether_shost[ETH_ALEN];    /* source ether addr    */
  u_int16_t ether_type;                /* packet type ID field    */
};


#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

/* Ethernet protocol ID's */
#define    ETHERTYPE_PUP        0x0200      /* Xerox PUP */
#define ETHERTYPE_SPRITE    0x0500        /* Sprite */
#define    ETHERTYPE_IP        0x0800        /* IP */
#define    ETHERTYPE_ARP        0x0806        /* Address resolution */
#define    ETHERTYPE_REVARP    0x8035        /* Reverse ARP */
#define ETHERTYPE_AT        0x809B        /* AppleTalk protocol */
#define ETHERTYPE_AARP        0x80F3        /* AppleTalk ARP */
#define    ETHERTYPE_VLAN        0x8100        /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX        0x8137        /* IPX */
#define    ETHERTYPE_IPV6        0x86dd        /* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK    0x9000        /* used to test interfaces */

/* decode_ethernet defined in dec_ethernet.cpp */
extern u_int16_t decode_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet, char *print);

#endif