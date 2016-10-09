/**********************************************************************
* file:   prt_icmp.h
* date:   Mon Apr 09 09:15:34 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   protocol ICMP header.
*
*
**********************************************************************/

#ifndef PRT_ICMP_H
#define PRT_ICMP_H

#include <netinet/ip.h>

struct moniSig_icmp_header {
    uint8_t  icmp_type;        /* type of message, see below */
    uint8_t  icmp_code;        /* type sub code */
    uint16_t icmp_cksum;        /* ones complement cksum of struct */
    union {
        uint8_t ih_pptr;            /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;    /* ICMP_REDIRECT */
        struct ih_idseq {
            uint16_t icd_id;
            uint16_t icd_seq;
        } ih_idseq;
        uint32_t ih_void;
    } icmp_hun;
#define    icmp_pptr    icmp_hun.ih_pptr
#define    icmp_gwaddr    icmp_hun.ih_gwaddr
#define    icmp_id        icmp_hun.ih_idseq.icd_id
#define    icmp_seq    icmp_hun.ih_idseq.icd_seq
#define    icmp_void    icmp_hun.ih_void
    union {
        struct id_ts {
            uint32_t its_otime;
            uint32_t its_rtime;
            uint32_t its_ttime;
        } id_ts;
        struct id_ip  {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        uint32_t id_mask;
        uint8_t id_data[1];
    } icmp_dun;
#define    icmp_otime    icmp_dun.id_ts.its_otime
#define    icmp_rtime    icmp_dun.id_ts.its_rtime
#define    icmp_ttime    icmp_dun.id_ts.its_ttime
#define    icmp_ip        icmp_dun.id_ip.idi_ip
#define    icmp_mask    icmp_dun.id_mask
#define    icmp_data    icmp_dun.id_data
};

#define ICMP_ECHOREPLY        0    /* Echo Reply            */
#define ICMP_DEST_UNREACH    3    /* Destination Unreachable    */
#define ICMP_SOURCE_QUENCH    4    /* Source Quench        */
#define ICMP_REDIRECT        5    /* Redirect (change route)    */
#define ICMP_ECHO        8    /* Echo Request            */
#define ICMP_TIME_EXCEEDED    11    /* Time Exceeded        */
#define ICMP_PARAMETERPROB    12    /* Parameter Problem        */
#define ICMP_TIMESTAMP        13    /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY    14    /* Timestamp Reply        */
#define ICMP_INFO_REQUEST    15    /* Information Request        */
#define ICMP_INFO_REPLY        16    /* Information Reply        */
#define ICMP_ADDRESS        17    /* Address Mask Request        */
#define ICMP_ADDRESSREPLY    18    /* Address Mask Reply        */
#define NR_ICMP_TYPES        18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH    0    /* Network Unreachable        */
#define ICMP_HOST_UNREACH    1    /* Host Unreachable        */
#define ICMP_PROT_UNREACH    2    /* Protocol Unreachable        */
#define ICMP_PORT_UNREACH    3    /* Port Unreachable        */
#define ICMP_FRAG_NEEDED    4    /* Fragmentation Needed/DF set    */
#define ICMP_SR_FAILED        5    /* Source Route failed        */
#define ICMP_NET_UNKNOWN    6
#define ICMP_HOST_UNKNOWN    7
#define ICMP_HOST_ISOLATED    8
#define ICMP_NET_ANO        9
#define ICMP_HOST_ANO        10
#define ICMP_NET_UNR_TOS    11
#define ICMP_HOST_UNR_TOS    12
#define ICMP_PKT_FILTERED    13    /* Packet filtered */
#define ICMP_PREC_VIOLATION    14    /* Precedence violation */
#define ICMP_PREC_CUTOFF    15    /* Precedence cut off */
#define NR_ICMP_UNREACH        15    /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET        0    /* Redirect Net            */
#define ICMP_REDIR_HOST        1    /* Redirect Host        */
#define ICMP_REDIR_NETTOS    2    /* Redirect Net for TOS        */
#define ICMP_REDIR_HOSTTOS    3    /* Redirect Host for TOS    */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL        0    /* TTL count exceeded        */
#define ICMP_EXC_FRAGTIME    1    /* Fragment Reass time exceeded    */

/* decode_icmp defined in */
extern void decode_ICMP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet, char *print);


#endif