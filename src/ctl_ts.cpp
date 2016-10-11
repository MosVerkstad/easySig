/**********************************************************************
* file:   ctl_time.cpp
* date:   Tue May 08 15:12:28 GMT+2 2012
* Author: Shirley
* Last Modified:
*
* Description:
*   to convert GMT time to local time.
*
*
**********************************************************************/
#include "ctl_ts.h"

int gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

    /*
     * If the year or julian day is different, we span 00:00 GMT
     * and must add or subtract a day. Check the year first to
     * avoid problems when the julian day wraps.
     */
    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    
    return (dt);
}

void printTimeStamp(const struct pcap_pkthdr* pkthdr, char* print) {
    int sec = (pkthdr->ts.tv_sec + gmt2local(0)) % 86400;
    sprintf(print, "%02d:%02d:%02d", sec / 3600, (sec % 3600) / 60, sec % 60);
}