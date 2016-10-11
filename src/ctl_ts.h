/**********************************************************************
* file:   ctl_time.h
* date:   Tue May 08 10:36:37 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   header of GMT time convert.
*
*
**********************************************************************/

#ifndef CTL_TIME_H
#define CTL_TIME_H

#include <pcap.h>
#include <time.h>
#include <stdio.h>

void printTimeStamp(const struct pcap_pkthdr* pkthdr, char* print);

#endif