#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>


int main(int argc, char **argv) {
  int sd;
  struct sockaddr_ll sin;
  char buffer[1024]; // You can change the buffer size

  /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
  * tells the sytem that the IP header is already included;
  * this prevents the OS from adding another IP header. */
  sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if(sd < 0) {
    perror("socket() error"); exit(-1);
  }

  /* This data structure is needed when sending the packets
  * using sockets. Normally, we need to fill out several
  * fields, but for raw sockets, we only need to fill out
  * this one field */
  struct ifreq *index = malloc(sizeof(struct ifreq)); /* the unique interface index for Ethernet device */
  strncpy(index->ifr_name, "eth14", strlen("eth14")); /* set name of interface to Ethernet */
  if (ioctl(sd, SIOCGIFINDEX, index) < 0) { /* get interface index */
    perror("ioctl() error"); exit(-1);
  }
  sin.sll_ifindex = index->ifr_ifindex; /* interface number */
  sin.sll_halen   = ETH_ALEN; /* length of address */


  // Here you can construct the IP packet using buffer[]
  // - construct the IP header ...
  // - construct the TCP/UDP/ICMP header ...
  // - fill in the data part if needed ...
  // Note: you should pay attention to the network/host byte order.

  struct ethhdr *eth = (struct ethhdr *) buffer;
  // set dest address to FF:FF:FF:FF:FF:FF (broadcase)
  eth->h_dest[0] = 0xff;
  eth->h_dest[1] = 0xff;
  eth->h_dest[2] = 0xff;
  eth->h_dest[3] = 0xff;
  eth->h_dest[4] = 0xff;
  eth->h_dest[5] = 0xff;
  // set src address to 01:02:03:04:05:06
  eth->h_source[0] = 0x01;
  eth->h_source[1] = 0x02;
  eth->h_source[2] = 0x03;
  eth->h_source[3] = 0x04;
  eth->h_source[4] = 0x05;
  eth->h_source[5] = 0x06;
  // set packet type ID field as IPv4
  eth->h_proto = htons(ETH_P_IP);

  /* Send out the IP packet.
  * ip_len is the actual size of the packet. */
  if (sendto(sd, buffer, 1024, 0, (struct sockaddr *)&sin,
    sizeof(sin)) < 0) {
    perror("sendto() error"); exit(-1);
  }
  printf("Success!\n");
  return 0;
}
