#pragma once

#include <net/ethernet.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

/**
 * The pcap processing and tcp parsing code has been rather shamelessly adapted(copied) from
 * ge0rg's work at https://github.com/ge0rg/tls-hello-dump. That is, itself, an adaptation of
 * Tim Carstens's "sniffer.c"
 */

// Ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14

// Ethernet header
struct sniff_ethernet {
	unsigned char ether_dhost[ETHER_ADDR_LEN];
	unsigned char ether_shost[ETHER_ADDR_LEN];
	unsigned short ether_type;
};

// IP
struct sniff_ip {
	unsigned char ip_vhl;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	unsigned char ip_ttl;
	unsigned char ip_p;
	unsigned short ip_sum;
	struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

// TCP header
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport;
	unsigned short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	unsigned char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short th_win;
	unsigned short th_sum;
	unsigned short th_urp;
};

#define SSL_MIN_GOOD_VERSION 0x002
#define SSL_MAX_GOOD_VERSION 0x304

#define TLS_HANDSHAKE    22
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2

#define OFFSET_HELLO_VERSION  9
#define OFFSET_SESSION_LENGTH 43
#define OFFSET_CIPHER_LIST    44

void process_packet(const unsigned char *packet, const struct pcap_pkthdr *header,
					struct timeval ts, unsigned int capture_len);
