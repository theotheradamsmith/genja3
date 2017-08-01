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
#include <openssl/md5.h>
#include <sys/socket.h>

// Debugging parameters... except DEBUG_JA3 is currently the mechanism printing the hash data
#define DEBUG     0
#define DEBUG_JA3 1

// Globals to indicate running mode
static bool print_dst = true;
static bool print_src = false;
static bool print_sni = false;

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

/**
 * A Cipafilter library function by David Hinkle... it takes either NULL or a string
 * and handles memory reallocation when increasing the size of a string with formatted
 * input.
 */
static int cf_asprintf_cat(char **old_string, char *fmt, ...) {
	va_list args;
	int len;

	char *new_string;

	va_start(args, fmt);
	if ((len = vasprintf(&new_string, fmt, args)) < 1)
		abort();

	if (*old_string) {
		len = strlen(*old_string) + strlen(new_string);
		assert(len > 0);

		char *ret = malloc(len+1);

		strcpy(ret, *old_string);
		strcat(ret, new_string);

		free(*old_string);
		free(new_string);

		*old_string = ret;
	} else {
		*old_string = new_string;
	}

	return len;
}

/// Ridiculous functions that are in place because my code is intended to work inside Cipafilter
static unsigned int SSL_BYTE_OFFSET(unsigned char *p) {
	return ((*p)+1);
}

/// Ridiculous functions that are in place because my code is intended to work inside Cipafilter
static unsigned int SSL_WORD_OFFSET(unsigned char *p) {
	return (((*p) << 8)+(*(p+1))+2);
}

/// Converts a two octet hex to base 10
static unsigned int two_byte_hex_to_dec(unsigned char *p) {
	return (unsigned int)((*p) << 8) + (*(p+1));
}

/// Function to determine if given input n is a GREASE value
static bool is_in_grease_table(unsigned int n) {
	switch (n) {
		case 0x0a0a:
		case 0x1a1a:
		case 0x2a2a:
		case 0x3a3a:
		case 0x4a4a:
		case 0x5a5a:
		case 0x6a6a:
		case 0x7a7a:
		case 0x8a8a:
		case 0x9a9a:
		case 0xaaaa:
		case 0xbaba:
		case 0xcaca:
		case 0xdada:
		case 0xeaea:
		case 0xfafa:
			return true;
		default:
			return false;
	}
}

// Receives SNI extension starting just after the extension id field (i.e., at the length field)
static char *parse_sni(const unsigned char *ptr) {
	char *ret_buffer = NULL;

	unsigned int total_extension_len = two_byte_hex_to_dec((unsigned char *)ptr);
	unsigned int len_traversed = 0;
	ptr += 2;
	len_traversed += 2;

	//unsigned int server_name_list_len = two_byte_hex_to_dec((unsigned char *)ptr);
	ptr += 2;
	len_traversed += 2;

	while (len_traversed < total_extension_len) {
		//unsigned int server_name_type = *ptr;
		ptr += 1;
		len_traversed += 1;

		unsigned int server_name_len = two_byte_hex_to_dec((unsigned char *)ptr);
		ptr += 2;
		len_traversed += 2;

		for (int i = 0; i < server_name_len; i++) {
			cf_asprintf_cat(&ret_buffer, "%c", ptr[i]);
		}

		ptr += server_name_len;
		len_traversed += server_name_len;
	}

	return ret_buffer;
}

/**
 * Generate_ja3_hash operates on a ClientHello to generate an MD5 checksum of certain
 * fields in the stream as specified by the project at https://github.com/salesforce/ja3
 *
 * @param input The packet buffer containing the ClientHello data
 * @param sni If we are in SNI capture mode, fill this buffer with SNI data
 * @return Returns a strdup'd copy of the generated JA3 hash. This must be freed by the caller.
 */
static char *generate_ja3_hash(const unsigned char *input, char **sni_buffer) {
	unsigned char *ptr = (unsigned char *)input;

	unsigned char *max = ptr + SSL_WORD_OFFSET(ptr+3) + 3;
	char *buffer = NULL;

	// Version information is at indices 9 & 10
	ptr += 9;
	cf_asprintf_cat(&buffer, "%u,", two_byte_hex_to_dec(ptr));

	// Skip random fields & Session ID fields
	ptr += 34;
	ptr += SSL_BYTE_OFFSET(ptr);

	if (ptr+2 > max)
		return NULL;

	// Ciphers
	unsigned int cipher_suite_len = SSL_WORD_OFFSET(ptr);
	unsigned int num_ciphers = (cipher_suite_len - 2) / 2;
	int ciphers_added = 0;
	if (num_ciphers > 0) {
		unsigned char *tmp = ptr + 2; // advance to beginning of ciphers
		for (unsigned int cs_id = 0; cs_id < num_ciphers; cs_id++) {
			unsigned int cipher = two_byte_hex_to_dec(tmp+(2*cs_id));
			if (!is_in_grease_table(cipher)) {
				if (ciphers_added == 0) {
					cf_asprintf_cat(&buffer, "%u", cipher);
				} else {
					cf_asprintf_cat(&buffer, "-%u", cipher);
				}
				ciphers_added++;
			}
		}
	}

	// We put a comma between every JA3 component
	cf_asprintf_cat(&buffer, "%s", ",");

	ptr += cipher_suite_len;
	if (ptr + 1 > max)
		return NULL;

	ptr += SSL_BYTE_OFFSET(ptr); // Skip the compression method

	// Buffer to hold extensions
	char *e = NULL;
	int extension_count = 0;
	// Buffer to hold elliptic curve data
	char *ec = NULL;
	int ec_count = 0;
	// Buffer to hold elliptic curve point format data
	char *ecpf = NULL;
	int ecpf_count = 0;

	// Checking for extensions
	if (ptr != max) {
		// Process extensions
		unsigned int extensions_suite_len = SSL_WORD_OFFSET(ptr);

		ptr += 2; // Skip extensions length fields

		unsigned int extensions_bytes_added = 0;

		while (extensions_bytes_added < extensions_suite_len - 2 && ptr != max) {
			unsigned int extension_id = two_byte_hex_to_dec(ptr);

			// First, add the extension to the extensions buffer if it's not on the grease table
			if (!is_in_grease_table(extension_id)) {
				if (extension_count == 0) {
					cf_asprintf_cat(&e, "%u", extension_id);
				} else {
					cf_asprintf_cat(&e, "-%u", extension_id);
				}
				extension_count++;
			}

			// Advance the pointer from the id fields to the length fields
			ptr += 2;
			extensions_bytes_added += 2;

			// Second, check the extension to see if it contains either elliptic curve or elliptic
			// curve point format data; add the data fields to their respective buffers
			unsigned int data_suite_len = SSL_WORD_OFFSET(ptr);

			// Advance ptr to actual data (individual data suites also contain an additional len)
			ptr += 2;
			extensions_bytes_added += 2;

			// Special case extension processing
			if (extension_id == 0x0000 && print_sni) {
				*sni_buffer = parse_sni(ptr-2); // let's go back in time to catch the sni total len
			} else if (extension_id == 0x000a) {
				// Skip 2 octets for the supported groups list length (yeah, 2 len fields)
				unsigned char *tmp = ptr+2;
				int num_data_points = (data_suite_len - 4) / 2;

				for (int i = 0; i < num_data_points; i++) {
					unsigned int val = two_byte_hex_to_dec(tmp+(2*i));
					if (!is_in_grease_table(val)) {
						if (ec_count == 0) {
							cf_asprintf_cat(&ec, "%u", val);
						} else {
							cf_asprintf_cat(&ec, "-%u", val);
						}
						ec_count++;
					}
				}
			} else if (extension_id == 0x000b) {
				// Elliptic curve point format types contain one-byte data fields
				unsigned char *tmp = ptr+1; // Skip 1 octet for the ecpf len (yeah, 2 len fields)
				int num_data_points = (data_suite_len - 3);

				for (int i = 0; i < num_data_points; i++) {
					unsigned int val = *(tmp+i);
					if (!is_in_grease_table(val)) {
						if (ecpf_count == 0) {
							cf_asprintf_cat(&ecpf, "%u", *(tmp+i));
						} else {
							cf_asprintf_cat(&ecpf, "-%u", *(tmp+i));
						}
						ecpf_count++;
					}
				}
			}

			// Advance up to the next extension
			extensions_bytes_added += data_suite_len - 2;
			ptr += data_suite_len - 2;
		}
	}

	// We now have everything to complete our main JA3 buffer and calculate our MD5 sum
	if (extension_count)
		cf_asprintf_cat(&buffer, "%s", e);
	free (e);

	// We put a comma between every JA3 component
	cf_asprintf_cat(&buffer, "%s", ",");

	if (ec_count)
		cf_asprintf_cat(&buffer, "%s", ec);
	free (ec);

	cf_asprintf_cat(&buffer, "%s", ",");

	if (ecpf_count)
		cf_asprintf_cat(&buffer, "%s", ecpf);
	free (ecpf);

	// Generate an md5 checksum
	unsigned char md5digest[MD5_DIGEST_LENGTH];

	MD5((unsigned char *)buffer, strlen(buffer), md5digest);

	char readable_md5digest[MD5_DIGEST_LENGTH*2+1];
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(readable_md5digest+(i*2), "%02hhx", md5digest[i]);

	if (DEBUG_JA3) {
		printf("JA3: %s --> %s", buffer, readable_md5digest);
	}

	free(buffer);

	return strdup(readable_md5digest);
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
			if (print_dst) {
				printf("[%s:%hu] ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			}
			if (print_src) {
				printf("[%s %hu] ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			}
			char *sni_buffer = NULL;
			char *hash = generate_ja3_hash(payload, &sni_buffer);
			if (print_sni) {
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
	fprintf(stderr, "    -h             Print this message and exit\n");
	fprintf(stderr, "    -s             Enable 'print source' mode, which prints source ip and\n"
                    "                   source port, rather than destination ip and port\n");
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

	int c;
	while ((c = getopt(argc, argv, "hsS")) != -1) {
		switch (c) {
			case 'h':
				print_usage(bin_name);
				return 0;
			case 's':
				print_src = true;
				print_dst = false;
				break;
			case 'S':
				print_sni = true;
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
