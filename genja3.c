#define _GNU_SOURCE

#include <assert.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include "genja3.h"
#include "parser.h"
#include "util.h"

uint32_t options = 0;

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

static char *ssl_version(unsigned short version) {
	static char hex[7];
	switch (version) {
		case 0x002:
			return "SSLv2";
		case 0x300:
			return "SSLv3";
		case 0x301:
			return "TLSv1";
		case 0x302:
			return "TLSv1.1";
		case 0x303:
			return "TLSv1.2";
	}

	snprintf(hex, sizeof(hex), "0x%04hx", version);
	return hex;
}

// I stole this.
static void process_tcp(const unsigned char *packet, const struct pcap_pkthdr *header,
						const struct sniff_ip *ip, int size_ip) {
	const struct sniff_tcp *tcp;
	int size_tcp;

	// Define/compute tcp header offset
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		if (DEBUG) {
			printf("Invalid TCP header length: %u bytes\n", size_tcp);
		}
		return;
	}

	if (DEBUG) {
		printf("%hu\t", ntohs(tcp->th_sport));
		printf("%hu\t", ntohs(tcp->th_dport));
	}

	// compute tcp payload (segment) size
	int size_iptotal = ntohs(ip->ip_len);
	if (size_iptotal == 0 || size_iptotal > header->caplen) {
		// If TSO is used, ip_len is 0x0000; only process up to caplen bytes
		size_iptotal = header->caplen;
	}

	int size_payload = size_iptotal - (size_ip + size_tcp);

	if (size_payload < OFFSET_CIPHER_LIST + 3) { // at least on cipher + compression
		if (DEBUG) {
			printf("TLS handshake header too short: %d bytes\n", size_payload);
		}
		return;
	}

	// define/compute tcp payload (segment) offset
	const unsigned char *payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	if (payload[0] != TLS_HANDSHAKE) {
		if (DEBUG) {
			printf("Not a TSL handshake: 0x%02hhx\n", payload[0]);
		}
		return;
	}

	unsigned short proto_version = payload[1]*256 + payload[2];
	if (DEBUG) {
		printf("%s ", ssl_version(proto_version));
	}
	unsigned short hello_version = payload[OFFSET_HELLO_VERSION]*256 + payload[OFFSET_HELLO_VERSION+1];

	if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
		hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
		if (DEBUG) {
			printf("%s bad version(s)\n", ssl_version(hello_version));
		}
		return;
	}

	switch (payload[5]) {
		case TLS_CLIENT_HELLO:
			if (DEBUG) {
				printf("ClientHello %s ", ssl_version(hello_version));
			}
			if (OF(PRINT_SRC)) { // the lack of a colon here was a specific request from Coop
				printf("[%s %hu] ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			}
			if (OF(PRINT_DST) || OF(FORCE_DST)) { // colon for direct compatability with Salesforce' ja3
				printf("[%s:%hu] ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			}
			char *sni_buffer = NULL;
			char *hash = generate_ja3_hash(payload, &sni_buffer);
			if (OF(PRINT_SNI)) {
				printf(" [%s]", sni_buffer ? sni_buffer : "-");
			}
			free(hash);
			free(sni_buffer);
			printf("\n");
			break;
		case TLS_SERVER_HELLO:
			if (DEBUG) {
				printf("ServerHello %s ", ssl_version(hello_version));
				printf("\n");
			}
			break;
		default:
			if (DEBUG) {
				printf("Not a Hello\n");
			}
			return;
	}
}

// I stole this.
void process_packet(const unsigned char *packet, const struct pcap_pkthdr *header,
					struct timeval ts, unsigned int capture_len) {
	const struct sniff_ip *ip;

	int size_ip;

	// define/compute ip header offset
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		if (DEBUG) {
			printf("Invalid IP header length: %u bytes\n", size_ip);
		}
		return;
	}

	if (DEBUG) {
		printf("%s\t", inet_ntoa(ip->ip_src));
		printf("%s\t", inet_ntoa(ip->ip_dst));
	}

	// determine protocol
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			if (DEBUG)
				printf("TCP\n");
			process_tcp(packet, header, ip, size_ip);
			break;
		case IPPROTO_UDP:
			if (DEBUG)
				printf("UDP\n");
			return;
		case IPPROTO_ICMP:
			if (DEBUG)
				printf("ICMP\n");
			return;
		case IPPROTO_IP:
			if (DEBUG)
				printf("IP\n");
			return;
		default:
			if (DEBUG)
				printf("Protocol: unknown\n");
			return;
	}
}

void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options> <pcap file>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -c             Enable 'print client' mode, which prints source ip and\n"
                    "                   source port, rather than destination ip and port\n");
	fprintf(stderr, "    -e             Exclude JA3 buffer & hash output\n");
	fprintf(stderr, "    -h             Print this message and exit\n");
	fprintf(stderr, "    -s             Force the printing of server ip and port\n");
	fprintf(stderr, "    -S             Append SNI data if available\n");
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
	char *bin_name = argv[0];
	pcap_t *pcap;
	char *filename = NULL;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	// Enable default options, which are designed to output lines that can be diffed against
	// the Salesforce JA3 python script
	options |= (PRINT_JA3 | PRINT_DST);

	int c;
	while ((c = getopt(argc, argv, "cehsS")) != -1) {
		switch (c) {
			case 'c':
				OF_ON(PRINT_SRC);
				OF_OFF(PRINT_DST);
				break;
			case 'e':
				OF_OFF(PRINT_JA3);
				break;
			case 'h':
				print_usage(bin_name);
				return 0;
			case 's':
				OF_ON(FORCE_DST);
				break;
			case 'S':
				OF_ON(PRINT_SNI);
				break;
			default:
				print_usage(bin_name);
				return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		fprintf(stderr, "You must specify a filename to parse\n");
		print_usage(bin_name);
		return 1;
	}

	assert((filename = argv[0]));

	if (!(pcap = pcap_open_offline(filename, errbuf))) {
		fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
		return 1;
	}

	// Loop through extracting packets as long as we have any to read
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		process_packet(packet, &header, header.ts, header.caplen);
	}

	return 0;
}

