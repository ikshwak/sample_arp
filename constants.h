#ifndef ARP_H_CONSTANTS
#define ARP_H_CONSTANTS

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

/************CONSTANTS************/
#define ARP_MAX_ARGUMENTS   3
#define ARP_MIN_ARGUMENTS   2  
#define TRUE                1
#define FALSE               0
#define PKT_BUF_SIZE        42
#define INTERFACE_NAME      "eth0"
#define ARP_HARDWARE_TYPE   1
#define ARP_PROTOCOL_TYPE   0x0800
#define ARP_HARDWARE_LENGTH 6
#define ARP_PROTOCOL_LENGTH 4
#define ARP_OPERATION_TYPE  1
#define ETH_MAC_LEN         ETH_ALEN
/*********************************/

typedef enum arp_mode_e{
    MODE_ARP_REQUEST = 1,
    MODE_ARP_RESPOND
}arp_mode;
#endif