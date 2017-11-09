#define _GNU_SOURCE

#include <assert.h>
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

static int process_ciphers(const unsigned char *input, char **buffer) {
	unsigned char *ptr = (unsigned char *)input;
	unsigned int cipher_suite_len = SSL_WORD_OFFSET(ptr);
	unsigned int num_ciphers = (cipher_suite_len - 2) / 2;
	int ciphers_added = 0;
	if (num_ciphers > 0) {
		unsigned char *tmp = ptr + 2; // advance to beginning of ciphers
		for (unsigned int cs_id = 0; cs_id < num_ciphers; cs_id++) {
			unsigned int cipher = two_byte_hex_to_dec(tmp+(2*cs_id));
			if (!is_in_grease_table(cipher)) {
				if (ciphers_added == 0) {
					cf_asprintf_cat(buffer, "%u", cipher);
				} else {
					cf_asprintf_cat(buffer, "-%u", cipher);
				}
				ciphers_added++;
			}
		}
	}

	return cipher_suite_len;
}

static void process_extensions(const unsigned char *input, const unsigned char *max,
							   char **sni_buffer, char **alp_buffer, char **buffer) {
	unsigned char *ptr = (unsigned char *)input;
	// Buffer to hold extensions
	char *e = NULL;
	int extension_count = 0;
	// Buffer to hold elliptic curve data
	char *ec = NULL;
	int ec_count = 0;
	// Buffer to hold elliptic curve point format data
	char *ecpf = NULL;
	int ecpf_count = 0;

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

		unsigned char *tmp;
		int num_data_points;

		// Special case extension processing
		switch (extension_id) {
			case 0x0000:
				if (OF(PRINT_SNI)) {
					*sni_buffer = parse_sni(ptr-2); // go back to catch the sni total len
				}

				break;

			case 0x0010:
				if (OF(PRINT_SNI)) {
					*alp_buffer = parse_alp(ptr-2); // going back to catch alp total len
				}

				break;

			case 0x000a:
				// Skip 2 octets for the supported groups list length (yeah, 2 len fields)
				tmp = ptr+2;
				num_data_points = (data_suite_len - 4) / 2;

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

				break;

			case 0x000b:
				// Elliptic curve point format types contain one-byte data fields
				tmp = ptr+1; // Skip 1 octet for the ecpf len (2 len fields)
				num_data_points = (data_suite_len - 3);

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

				break;

			default:
				break;
		}

		// Advance up to the next extension
		extensions_bytes_added += data_suite_len - 2;
		ptr += data_suite_len - 2;
	}

	// We now have everything to complete our main JA3 buffer and calculate our MD5 sum
	if (extension_count)
		cf_asprintf_cat(buffer, "%s", e);
	free (e);

	// We put a comma between every JA3 component
	cf_asprintf_cat(buffer, "%s", ",");

	if (ec_count)
		cf_asprintf_cat(buffer, "%s", ec);
	free (ec);

	cf_asprintf_cat(buffer, "%s", ",");

	if (ecpf_count)
		cf_asprintf_cat(buffer, "%s", ecpf);
	free (ecpf);
}

static void fetch_raw_hex_bytestream(const unsigned char *input, char **raw_handshake) {
	unsigned char *ptr = (unsigned char *)input;

	char *raw = NULL;
	int raw_len = 0;
	const unsigned int client_hello_length = ((*(ptr+6))<<16)+((*(ptr+7))<<8)+(*(ptr+8));
	if (OF(CREATE_BYTE_ARRAY)) {
		raw_len = 6 * (client_hello_length + 9);
		raw = calloc(1, raw_len+1);
		for (int i = 0; i < client_hello_length+9; i++) {
			sprintf(raw+(i*6), "0x%02hhx, ", ptr[i]);
		}
	} else {
		raw_len = 2 * (client_hello_length + 9);
		raw = calloc(1, raw_len+1);
		for (int i = 0; i < client_hello_length+9; i++) {
			sprintf(raw+(i*2), "%02hhx", ptr[i]);
		}
	}

	raw[raw_len] = '\0';
	*raw_handshake = raw;
}

static char *generate_hashable_buffer(const unsigned char *input, char **sni_buffer,
									  char **alp_buffer, char **raw_handshake) {
	// Ain't nobody got time for that what ain't client hello handshakes
	assert(input && input[0] == 0x16 && input[1] == 0x03 && input[2] <= 0x03 && input[5] == 0x01);

	fetch_raw_hex_bytestream(input, raw_handshake);

	char *buffer = NULL;
	unsigned char *ptr = (unsigned char *)input;
	unsigned char *max = ptr + SSL_WORD_OFFSET(ptr+3) + 3;

	// Version information is at indices 9 & 10
	ptr += 9;
	cf_asprintf_cat(&buffer, "%u,", two_byte_hex_to_dec(ptr));

	// Skip random fields & Session ID fields
	ptr += 34;
	ptr += SSL_BYTE_OFFSET(ptr);

	if (ptr+2 > max) {
		free(buffer);
		return NULL;
	}

	// Ciphers
	unsigned int cipher_suite_len = process_ciphers(ptr, &buffer);

	ptr += cipher_suite_len;
	if (ptr + 1 > max) {
		free(buffer);
		return NULL;
	}

	// We put a comma between every JA3 component
	// @todo: verify that ja3 library always puts a comma here; pretty sure it does...
	cf_asprintf_cat(&buffer, "%s", ",");

	ptr += SSL_BYTE_OFFSET(ptr); // Skip the compression method

	// Checking for extensions
	if (ptr != max) {
		process_extensions(ptr, max, sni_buffer, alp_buffer, &buffer);
	}

	return buffer;
}

char *generate_ja3_hash(const unsigned char *input, char **sni_buffer, char **alp_buffer,
						char **raw_handshake) {
	char *buffer = generate_hashable_buffer(input, sni_buffer, alp_buffer, raw_handshake);

	if (!buffer) {
		return NULL;
	}

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

