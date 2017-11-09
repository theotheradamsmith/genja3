#define _GNU_SOURCE

#include <assert.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "genja3.h"
#include "parser.h"
#include "pcap_engine.h"
#include "util.h"

uint32_t options = 0;

void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options> <pcap file>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -A             Append application layer protocol data if available\n");
	fprintf(stderr, "    -c             Enable 'print client' mode, which prints source ip and\n"
                    "                   source port, rather than destination ip and port\n");
	fprintf(stderr, "    -e             Exclude JA3 buffer & hash output\n");
	fprintf(stderr, "    -h             Print this message and exit\n");
	fprintf(stderr, "    -r             Print the raw hex bytestream of the handshake\n");
	fprintf(stderr, "    -R             Print the hex bytestream {0x16}-style of the handshake\n");
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
	while ((c = getopt(argc, argv, "AcehrRsS")) != -1) {
		switch (c) {
			case 'A':
				OF_ON(PRINT_ALP);
				break;
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
			case 'r':
				OF_ON(PRINT_RAW);
				break;
			case 'R':
				OF_ON(CREATE_BYTE_ARRAY);
				break;
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

