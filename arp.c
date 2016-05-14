#include "arp.h"


int16_t main(int16_t argc, char **argv)
{
  int    opt, mode;
  char   *pIPaddr = NULL;

  while((opt = getopt(argc, argv, "m:i:")) != -1) {
    switch(opt){
      case 'm':
      {
        if(!optarg)
        {
          printf("%s", "Invalid Mode\n");
          exit(1);
        }
        else
        {
          mode = atoi(optarg);
        }
      }break;
      case 'i':
      {
        if(!optarg)
        {
          printf("%s", "Invalid IP address\n");
          exit(1);
        }
        else
        {
          pIPaddr = optarg;
        }
      }break;
    }
  }

  if(mode == MODE_ARP_REQUEST)
  {
    if(pIPaddr)
    {
      if(!is_ip_valid(pIPaddr))
      {
        printf("%s", "Invalid IP address \n");
        exit(1);
      }
      processARPRequest(pIPaddr);
    }
  }
  else if(mode == MODE_ARP_RESPOND)
  {
     processARPReply();
  }

  return 0;
}


void processARPRequest(char *argv)
{
  int16_t            sd = -1;
  arpPacket          ah;
  u_int8_t           src_mac[6];
  struct ifreq       ifReq;
  struct sockaddr_ll sockAddr;
  int                ifindex = 0;
  struct sockaddr_in *sin;
  uint32_t           ipAddr;

  printf("\n****Processing ARP REQUEST SEND****\n");
  /*open a RAW socket for ARP packets*/
  sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sd == -1) {
        perror("socket error:");
        exit(1);
  }

  /*Get the Ethernet Index*/
  strncpy(ifReq.ifr_name, INTERFACE_NAME, IFNAMSIZ);
  if (ioctl(sd, SIOCGIFINDEX, &ifReq) == -1) {
        perror("Eth Index: ");
        exit(1);
  }
  ifindex = ifReq.ifr_ifindex;

  /*Get the Ethernet MAC address*/
  if (ioctl(sd, SIOCGIFHWADDR, &ifReq) == -1) {
        perror("Eth HW address: ");
        exit(1);
  }
  memcpy (src_mac, ifReq.ifr_hwaddr.sa_data, 6 * sizeof (u_int8_t));

  /*Get device IP address*/
  if(ioctl(sd, SIOCGIFADDR, &ifReq, sizeof(ifReq)) == -1){
        perror("Device IP address: ");
        exit(1);
  }

  sin = (struct sockaddr_in *)&ifReq.ifr_addr;
  ipAddr = ntohl(sin->sin_addr.s_addr);

  memset (&sockAddr, 0, sizeof (sockAddr));
  sockAddr.sll_family = AF_PACKET;
  sockAddr.sll_ifindex = ifindex;
  sockAddr.sll_protocol = htons(ETH_P_ARP);


  //CREATE ETHERNET PACKET WITH ETH HEADER+ARP HEADER+ARP DATA + PADDING BYTES
  // Ethernet Header
  memset(ah.ethDstMAC, 0xFF, (6 * sizeof(u_int8_t)));
  memcpy(ah.ethSrcMAC, src_mac, 6 * sizeof(u_int8_t));
  ah.ethType = htons(ETH_P_ARP); 
  // ARP Header
  ah.arpHDR = htons(ARP_HARDWARE_TYPE);
  ah.arpPT = htons(ARP_PROTOCOL_TYPE);
  ah.arpHDL = ARP_HARDWARE_LENGTH;
  ah.arpPRL = ARP_PROTOCOL_LENGTH;
  ah.arpOP = htons(ARP_OPERATION_TYPE);
  memcpy(ah.arpSHA, ah.ethSrcMAC, (6 * sizeof(u_int8_t)));
  memcpy(ah.arpSPA, inet_ntoa(sin->sin_addr), (4 * sizeof(u_int8_t)));
  memset(ah.arpDHA, 0 , (6 * sizeof(u_int8_t)));
  memcpy(ah.arpDPA ,argv, (4 * sizeof(u_int8_t)));
  // Padding
  memset(ah.padding, 0 , 18 * sizeof(u_int8_t)); 

  printf("SENDER MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           ah.arpSHA[0],
           ah.arpSHA[1],
           ah.arpSHA[2],
           ah.arpSHA[3],
           ah.arpSHA[4],
           ah.arpSHA[5]
           );
  printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           ah.arpDHA[0],
           ah.arpDHA[1],
           ah.arpDHA[2],
           ah.arpDHA[3],
           ah.arpDHA[4],
           ah.arpDHA[5]
           );
  if(sendto(sd, &ah, sizeof(ah), 0,(struct sockaddr *)&sockAddr, sizeof(sockAddr)) == -1)
  {
      perror("Socket send: ");
      close(sd);
      exit(1);
  }
  close(sd);
}

void processARPReply(void) 
{
    int16_t            sd = -1;
    unsigned char      src_mac[6];
    struct ifreq       ifr;
    struct sockaddr_ll sockAddr;
    int                ifindex = 0;
    arpPacket          *ah;
    void               *buffer = (void*)malloc(PKT_BUF_SIZE);
    unsigned char      *etherhead = buffer;
    struct ethhdr      *eh = (struct ethhdr *)etherhead;
    unsigned char*     arphead = buffer;
    int                i;
    int                length;
    int                sent;
    void*              sharedMem;
    int                shmFlag = TRUE;

    /*open socket*/
    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd == -1) {
            perror("Socket open:");
            exit(1);
    }

    /*retrieve ethernet interface index*/
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
            perror("SIOCGIFINDEX");
            exit(1);
    }
    ifindex = ifr.ifr_ifindex;

    /*retrieve corresponding MAC*/
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("SIOCGIFINDEX");
            exit(1);
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, (6*sizeof(u_int8_t)));

    /*prepare sockaddr_ll*/
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);
    sockAddr.sll_ifindex = ifindex;
    sockAddr.sll_hatype = ARPHRD_ETHER;
    sockAddr.sll_pkttype = 0;
    sockAddr.sll_halen = 0;
    sockAddr.sll_addr[6] = 0x00;
    sockAddr.sll_addr[7] = 0x00;

    while (1)
    {
        /*Blocking socket operation waitng for incoming ETHERNET packets*/
        length = recvfrom(sd, buffer, PKT_BUF_SIZE, 0, NULL, NULL);
        if (length == -1)
        {
            perror("socket recvfrom:");
            exit(1);
        }
        if(ntohs(eh->h_proto) == ETH_P_ARP)
        {
            unsigned char buf_arp_dha[6];
            unsigned char buf_arp_dpa[4];

            ah = (arpPacket *)arphead;
            if(ntohs(ah->arpOP) == ARPOP_REQUEST)
            {
                printf("\n****Processing ARP REQUEST RECEIVE****\n");
                memcpy( (void*)etherhead, (const void*)(etherhead+ETH_MAC_LEN),ETH_MAC_LEN);
                memcpy( (void*)(etherhead+ETH_MAC_LEN), (const void*)src_mac,ETH_MAC_LEN);
                eh->h_proto = htons(ETH_P_ARP);
                
                ah->arpOP = htons(ARPOP_REPLY);
                memcpy(buf_arp_dpa, ah->arpDPA, (4*sizeof(u_int8_t)));
                memcpy(ah->arpDHA, ah->arpSHA, (6*sizeof(u_int8_t)));
                memcpy(ah->arpDPA, ah->arpSPA, (4*sizeof(u_int8_t)));
                memcpy(ah->arpSPA, buf_arp_dpa, (4*sizeof(u_int8_t)));
                memcpy(sockAddr.sll_addr, eh->h_dest, (6*sizeof(u_int8_t)));
                printf("SENDER MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ah->arpSHA[0],
                       ah->arpSHA[1],
                       ah->arpSHA[2],
                       ah->arpSHA[3],
                       ah->arpSHA[4],
                       ah->arpSHA[5]
                       );
                printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ah->arpDHA[0],
                       ah->arpDHA[1],
                       ah->arpDHA[2],
                       ah->arpDHA[3],
                       ah->arpDHA[4],
                       ah->arpDHA[5]
                       );
                
                sent = sendto(sd, buffer, PKT_BUF_SIZE, 0, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
                if (sent == -1)
                {
                        perror("Socket sendto:");
                        exit(1);
                }
            }
            else if(ntohs(ah->arpOP) == ARPOP_REPLY)
            {
                printf("\n****Processing ARP RESPONSE****\n");
                printf("SENDER MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ah->arpSHA[0],
                       ah->arpSHA[1],
                       ah->arpSHA[2],
                       ah->arpSHA[3],
                       ah->arpSHA[4],
                       ah->arpSHA[5]
                       );
               printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ah->arpDHA[0],
                       ah->arpDHA[1],
                       ah->arpDHA[2],
                       ah->arpDHA[3],
                       ah->arpDHA[4],
                       ah->arpDHA[5]
                       );
            }
        }
    }
}