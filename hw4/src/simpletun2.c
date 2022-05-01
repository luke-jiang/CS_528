/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define HMAC_LENGTH 32

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){

  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){

  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){

  va_list argp;

  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      my_err("EVP_CIPHER_CTX_new\n");
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
      my_err("EVP_EncryptInit_ex\n");
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
      my_err("EVP_EncryptUpdate\n");
    }

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
      my_err("EVP_EncryptFinal_ex\n");
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      my_err("EVP_CIPHER_CTX_new\n");
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
      my_err("EVP_DecryptInit_ex\n");
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
      my_err("EVP_DecryptUpdate\n");
    }

    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
      my_err("EVP_DecryptFinal_ex\n");
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}



int main(int argc, char *argv[])
{

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  size_t length;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  socklen_t dest_len =0;

  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];


  struct sockaddr_in server, dest,sout;
  size_t soutlen = sizeof(sout);

  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd,net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  /*************Encryption Parameters***************/
  // 256-bit key
  unsigned char key[32] = "01234567890123456789012345678901";
  // 128-bit initialization vector
  unsigned char iv[16] = "0123456789012345";


  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uad")) > 0){
    switch(option) {
	case 'd':
         debug = 1;
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        break;
    }
  }

  argv += optind;
  argc -= optind;

  if(*if_name == '\0'){
   perror("Must specify interface name!\n");

  }else if(cliserv < 0){
    perror("Must specify dest or server mode!\n");
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    perror("Must specify server address!\n");
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket()");
    exit(1);
  }

  EVP_add_cipher(EVP_aes_256_cbc());

  if(cliserv==CLIENT){
     /* Client, try to connect to server */
     int i=0;
     unsigned char cred[128];
     for (i = 0; i < 128; i++) {
       cred[i] = 0;
     }

      printf("username :");
      fflush(stdout);
      scanf("%s",cred);

      printf("password :");
      fflush(stdout);
      scanf("%s",cred + 64);

      fflush(stdout);

      // printf("aaa");fflush(stdout);
      unsigned char ciphertext[128];
      int ciphertext_len = encrypt(cred, 128, key, iv, ciphertext);
      printf("%d\n", ciphertext_len);

      fflush(stdout);

      /* assign the destination address */
      memset(&dest, 0, sizeof(dest));
      dest.sin_family = AF_INET;
      dest.sin_addr.s_addr = inet_addr(remote_ip);
      dest.sin_port = htons(port);

      /* send credentials to server */
      if((nwrite=sendto(sock_fd,ciphertext,ciphertext_len,0,(struct sockaddr *)&dest,sizeof(dest))) < 0){
        perror("sendto error\n");
        exit(1);
      }
      net_fd=sock_fd;

} else {
  /* Server, wait for connections */

  /* avoid EADDRINUSE error on bind() */
 	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
	{
		perror("setsockopt()");
		exit(1);
	}
 	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);
  if (bind(sock_fd, (struct sockaddr*) &server, sizeof(server)) < 0){
		perror("bind()");
		exit(1);
  }

  if((nread=recvfrom(sock_fd,buffer,BUFSIZE,0,(struct sockaddr *)&dest,&dest_len)) <= 0){
      perror("recvfrom error\n");
      exit(1);
  }

  unsigned char decryptedtext[128];
  int decryptedtext_len = decrypt(buffer, 144 /* should not hardcode */, key, iv,
                          decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);


  printf("Packet received :%s\n",buffer);
  fflush(stdout);

  unsigned char username[64];
  unsigned char password[64];

    strncpy(username, decryptedtext, 64);
    strncpy(password, decryptedtext+64, 64);

    do_debug("username: %s\n", username);
    do_debug("password: %s\n", password);

    FILE *fp;
		if ((fp = fopen("users.txt", "r")) == NULL) {
			perror("No user database found\n");
			exit(1);
		}

    int found = 0;
    char r_name[64];
    char r_pass[64];
		while(!feof(fp)) {
			fscanf(fp,"%s %s", r_name, r_pass);
			if(strcmp(username,r_name) == 0 && strcmp(password,r_pass) == 0) {
        found = 1; break;
      }
		}
		fclose(fp);
    if (found == 0) {
      printf("SERVER: Credential not found.\n");
    } else {
      do_debug("SERVER: Client authenticated.\n");
    }
  }

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  dest_len = sizeof(dest);
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd+1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
        continue;
    }
    if (ret < 0) {
        perror("select()");
        exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
        /* data from tun/tap: just read it and write it to the network */

        nread = cread(tap_fd, buffer, BUFSIZE);

        tap2net++;
        do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

        /* write length + packet */
        if((nwrite=sendto(sock_fd,buffer,nread,0,(struct sockaddr *)&dest,sizeof(dest))) < 0){
            perror("sendto error\n");
            exit(1);
        }

        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)) {
        /* data from the network: read it, and write it to the tun/tap interface.
        * We need to read the length first, and then the packet */

        /* read packet */
        if((nread=recvfrom(sock_fd,buffer,BUFSIZE,0,(struct sockaddr *)&dest,&dest_len)) <= 0){
            perror("recvfrom error\n");
            exit(1);
        }
        net2tap++;
        do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

        /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
        nwrite = cwrite(tap_fd, buffer, nread);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  return(0);
}
