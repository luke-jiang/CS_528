#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// #include <if_ether.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

// convert MAC address from string to bytes
#define mac_addr(a, mac)                \
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &a[0],&a[1],&a[2],&a[3],&a[4],&a[5])


int main(int argc, char **argv) {
  struct ifreq       ifidx = { 0 };     // interface index
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
  // sin.sin_family = AF_PACKET;

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

  // mac_addr(eth->h_dest, "FF:FF:FF:FF:FF:FF");
  // mac_addr(eth->h_source, "01:02:03:04:05:06");
  // set packet type ID field as IPv4
  eth->h_proto = htons(ETH_P_IP);

  strncpy(ifidx.ifr_name, "eth14", strlen("eth14"));      // set interface name
  if (ioctl(sd, SIOCGIFINDEX, &ifidx) < 0 ) {         // get interface index
    perror("[-] Error! Cannot get interface index");
    return -1;
  }

  sin.sll_ifindex = ifidx.ifr_ifindex;           // interface index
  sin.sll_halen   = ETH_ALEN;                    // address length
  
  mac_addr(sin.sll_addr, "FF:FF:FF:FF:FF:FF");                   // set target MAC address


  /* Send out the IP packet.
  * ip_len is the actual size of the packet. */
  if (sendto(sd, buffer, 1024, 0, (struct sockaddr *)&sin,
    sizeof(sin)) < 0) {
    perror("sendto() error"); exit(-1);
  }
  printf("Success!\n");
  return 0;
}
