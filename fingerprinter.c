#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "fingerprinter.h"
#include "ja3_hashmap.h"
#include "util.h"

static void print_usage(const char *bin_name) {
	fprintf(stderr, "Usage: %s <source file>\n\n", bin_name);
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
	const char *bin_name = argv[0];
	char *filename = NULL;

	if (argc != 2) {
		fprintf(stderr, "You must specify a filename to source\n");
		print_usage(bin_name);
		return 1;
	}

	filename = argv[1];
	assert(filename);

	const char *f = read_file(filename);
	parse_json_from_file(f);

	print_hash();

	free((char *)f);
	free_fingerprints_hash();

	return 0;
}
