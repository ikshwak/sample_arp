#ifndef ARP_H_INCLUDE
#define ARP_H_INCLUDE

#include "constants.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
 
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>


typedef struct arpPacket_s{
        
        u_int8_t ethDstMAC[6];
        u_int8_t ethSrcMAC[6];
        uint16_t ethType;

        uint16_t arpHDR;
        uint16_t arpPT;
        u_int8_t arpHDL;
        u_int8_t arpPRL;
        uint16_t arpOP;
        u_int8_t arpSHA[6];
        u_int8_t arpSPA[4];
        u_int8_t arpDHA[6];
        u_int8_t arpDPA[4];

        int8_t   padding[18];
}arpPacket;


void processARPRequest(char *ipAddr);
void processARPReply();
#endif