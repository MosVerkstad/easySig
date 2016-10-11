/**********************************************************************
* file:   easySig.cpp
* date:   Wed Feb 21 14:05:02 GMT+2 2012
* Author: Shirley
* Last Modified: Fri May 06 20:55:48 GMT+2 2016
*
* Description:
*   The main entry function of easySig.
*   
* Dependency:
*   PCAP lib
*
* Compile with:
*   g++ -o easySig *.cpp -I. -lpcap -lrt -pthread
*
* Usage:
* easySig "device name" (# of packets) (seconds) "filter string"
* Note: "device name":   specified dev or "*" for any device.
*       (# of packets):  0 for unlimited packages to be monitored.
*       (seconds):       monitoring time window.
*       "filter string": see PCAP lib.
*
**********************************************************************/

#include "easySig.h"

pcap_t* descr;    /* global variant, for term sig handler. */

timer_t gTimerid;

void easySig_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    /* define the print buff, which will be used after decoding. */
    char print[MAX_PRINT_BUFF];
    printTimeStamp(pkthdr, print);
    
    /* start to decode ethernet header, and continue according to type. */
    switch (decode_ethernet(args,pkthdr,packet,print))
    {
        case ETHERTYPE_IP:
            /* handle IP packet */
            switch (decode_IP(args,pkthdr,packet,print))
            {
                case IPTYPE_ICMP:
                    decode_ICMP(args,pkthdr,packet,print);
                    break;
                case IPTYPE_TCP:
                    sprintf(print, "%s(TCP)", print);
                    break;
                case IPTYPE_UDP:
                    sprintf(print, "%s(UDP)", print);
                    break;
                default:
                    break;
            }
            break;
        case ETHERTYPE_ARP:
            break;
        case ETHERTYPE_REVARP:
            break;
        default:
            break;
    }
        
    fprintf(stdout,"%s\n", print);
}


void start_timer(int duration)
{
    struct itimerspec value;
    value.it_value.tv_sec = duration;  //waits ... before sending timer signal
    value.it_value.tv_nsec = 0;
    value.it_interval.tv_sec = 1;//sends timer signal every 60 seconds
    value.it_interval.tv_nsec = 0;

    timer_create (CLOCK_REALTIME, NULL, &gTimerid);
    timer_settime (gTimerid, 0, &value, NULL);
}

void stop_timer(void)
{
    struct itimerspec value;
    value.it_value.tv_sec = 0;
    value.it_value.tv_nsec = 0;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_nsec = 0;

    timer_settime (gTimerid, 0, &value, NULL);
}

void cleanup()
{
    fprintf(stdout, "Stop easySig.\n");
    (void)fflush(stdout);
    pcap_close(descr);
    exit(1);
}

void timer_callback(int sig)
{
    stop_timer();
    cleanup();
}

void termHandler_callback(int sig)
{
    cleanup();
}

int main(int argc,char **argv)
{
    char *dev;                  /* device name, from argv[1] */
    char errbuf[PCAP_ERRBUF_SIZE];
    /* pcap_t* descr; set it to global variant for signal*/
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;

    /* Options must be passed in as a string aligned with pcap */
    if(argc < 4){
        fprintf(stdout,
            "Usage: %s \"device name\" (# of packets) (seconds) \"filter string\".\n"
            ,argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    if (strcmp(argv[1], "*") == 0) { dev = pcap_lookupdev(errbuf); }
    else { dev = argv[1]; }
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(descr,&fp,argv[4],0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    (void)signal(SIGINT, termHandler_callback);
    (void)signal(SIGPIPE, termHandler_callback);
    (void)signal(SIGTERM, termHandler_callback);
    (void)signal(SIGALRM, timer_callback);
    (void)start_timer(atoi(argv[3]));
    
    /* ... and loop */
    fprintf(stdout, "easySig: start to monitor on device %s: \n", dev);
    pcap_loop(descr,atoi(argv[2]),easySig_callback,args);

    cleanup();
    return 0;
}