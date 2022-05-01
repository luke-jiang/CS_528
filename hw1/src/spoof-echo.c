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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main(int argc, char **argv) {
  int sd;
  struct sockaddr_in sin;
  char buffer[1024]; // You can change the buffer size

  /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
  * tells the sytem that the IP header is already included;
  * this prevents the OS from adding another IP header. */
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(sd < 0) {
    perror("socket() error"); exit(-1);
  }

  /* This data structure is needed when sending the packets
  * using sockets. Normally, we need to fill out several
  * fields, but for raw sockets, we only need to fill out
  * this one field */
  sin.sin_family = AF_INET;

  // Here you can construct the IP packet using buffer[]
  // - construct the IP header ...
  // - construct the TCP/UDP/ICMP header ...
  // - fill in the data part if needed ...
  // Note: you should pay attention to the network/host byte order.

  // Construct the IP header
  struct ip *ip = (struct ip *) buffer;
  ip->ip_hl = 5; /* header length in 4 bytes */
  ip->ip_v = 4; /* version, use IPv4 */
  ip->ip_tos = 0; /* type of service */
  ip->ip_len = 1024; /* total length in bytes */
  ip->ip_id = 0; /* identification */
  ip->ip_off = 0; /* fragment offset field */
  ip->ip_ttl = 64; /* time to live */
  ip->ip_p = IPPROTO_ICMP; /* protocol, use ICMP */
  ip->ip_src.s_addr = inet_addr("172.217.1.110"); /* source address, spoofed as Google */
  ip->ip_dst.s_addr = inet_addr("192.168.15.5"); /* dest address, the second VM */

  // Construct the ICMP header
  struct icmp *icmp = (struct icmp *) (buffer + sizeof (struct ip));
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;

  /* Send out the IP packet.
  * ip_len is the actual size of the packet. */
  if (sendto(sd, buffer, 1024, 0, (struct sockaddr *)&sin,
    sizeof(sin)) < 0) {
    perror("sendto() error"); exit(-1);
  }
  return 0;
}
