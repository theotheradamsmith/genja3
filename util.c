#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "genja3.h"
#include "util.h"

unsigned int SSL_BYTE_OFFSET(unsigned char *p) {
	return ((*p)+1);
}

/// Ridiculous functions that are in place because my code is works inside Cipafilter
unsigned int SSL_WORD_OFFSET(unsigned char *p) {
	return (((*p) << 8)+(*(p+1))+2);
}

/// Converts a two octet hex to base 10
unsigned int two_byte_hex_to_dec(unsigned char *p) {
	return (unsigned int)((*p) << 8) + (*(p+1));
}

int cf_asprintf_cat(char **old_string, char *fmt, ...) {
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

/// Function to determine if given input n is a GREASE value
bool is_in_grease_table(unsigned int n) {
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

