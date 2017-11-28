#pragma once

#include <stdbool.h>

/// Ridiculous functions that are in place because my code is works inside Cipafilter
unsigned int SSL_BYTE_OFFSET(unsigned char *p);
/// Ridiculous functions that are in place because my code is works inside Cipafilter
unsigned int SSL_WORD_OFFSET(unsigned char *p);

/// Converts a two octet hex to base 10
unsigned int two_byte_hex_to_dec(unsigned char *p);

/**
 * A Cipafilter library function by David Hinkle... it takes either NULL or a string
 * and handles memory reallocation when increasing the size of a string with
 * formatted input.
 */
int cf_asprintf_cat(char **old_string, char *fmt, ...);

/**
 * Function to determine if given input n is a GREASE value
 */
bool is_in_grease_table(unsigned int n);

/**
 * Simple function to read a file and return an allocated buffer that must be freed
 */
const char *read_file(const char *filename);
