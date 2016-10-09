/**********************************************************************
* file:   easySig.h
* date:   Thu Mar 01 10:18:42 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   All of data structures and functions are defined.
*
*
**********************************************************************/

#ifndef EASYSIG_H
#define EASYSIG_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>

#include <signal.h>
#include <cstdlib>
#include <time.h>

#include "prt_ethernet.h"
#include "prt_ip.h"
#include "prt_icmp.h"

#ifndef MAX_PRINT_BUFF
#define MAX_PRINT_BUFF 240
#endif

#endif