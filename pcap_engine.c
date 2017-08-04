#define _GNU_SOURCE

/**
 * The pcap processing and tcp parsing code has been rather shamelessly adapted(copied) from
 * ge0rg's work at https://github.com/ge0rg/tls-hello-dump. That is, itself, an adaptation of
 * Tim Carstens's "sniffer.c"
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "genja3.h"
#include "parser.h"
#include "pcap_engine.h"

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

