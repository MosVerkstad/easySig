/**********************************************************************
* file:   dev_if.h
* date:   Wed Oct 12 22:24:15 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to provide the function to get the first active device.
*
*
**********************************************************************/
#ifndef DEV_IF_H
#define DEV_IF_H

#include <string.h>
#include <pcap.h>
#include <netinet/in.h>

void getActiveDev(char* dev);

#endif