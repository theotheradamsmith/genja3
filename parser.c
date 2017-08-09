#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/md5.h>

#include "genja3.h"
#include "parser.h"
#include "util.h"

char *parse_alp(const unsigned char *ptr) {
	char *ret_buffer = NULL;

	unsigned int total_extension_len = two_byte_hex_to_dec((unsigned char *)ptr);
	unsigned int len_traversed = 0;
	ptr += 2;
	len_traversed += 2;

	// unsigned int alp_extension_len = two_byte_hex_to_dec((unsigned char *)ptr);
	ptr += 2;
	len_traversed += 2;

	while (len_traversed < total_extension_len) {
		unsigned int current_str_len = *ptr;
		ptr += 1;
		len_traversed += 1;

		for (int i = 0; i < current_str_len; i++) {
			cf_asprintf_cat(&ret_buffer, "%c", ptr[i]);
		}

		ptr += current_str_len;
		len_traversed += current_str_len;

		if (len_traversed < total_extension_len) {
			cf_asprintf_cat(&ret_buffer, ", ");
		}
	}

	return ret_buffer;
}

char *parse_sni(const unsigned char *ptr) {
	char *ret_buffer = NULL;

	unsigned int total_extension_len = two_byte_hex_to_dec((unsigned char *)ptr);
	unsigned int len_traversed = 0;
	ptr += 2;
	len_traversed += 2;

	// unsigned int server_name_list_len = two_byte_hex_to_dec((unsigned char *)ptr);
	ptr += 2;
	len_traversed += 2;

	while (len_traversed < total_extension_len) {
		// unsigned int server_name_type = *ptr;
		// skip over server name type
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

		if (len_traversed < total_extension_len) {
			cf_asprintf_cat(&ret_buffer, ", ");
		}
	}

	return ret_buffer;
}

char *generate_ja3_hash(const unsigned char *input, char **sni_buffer, char **alp_buffer) {
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
			if (extension_id == 0x0000 && OF(PRINT_SNI)) {
				*sni_buffer = parse_sni(ptr-2); // let's go back in time to catch the sni total len
			} else if (extension_id == 0x0010 && OF(PRINT_ALP)) {
				*alp_buffer = parse_alp(ptr-2); // going back in time to catch alp total len
			}else if (extension_id == 0x000a) {
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

	if (OF(PRINT_JA3)) {
		printf("JA3: %s --> %s", buffer, readable_md5digest);
	}

	free(buffer);

	return strdup(readable_md5digest);
}

