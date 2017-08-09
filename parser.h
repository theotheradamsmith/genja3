#pragma once

// Receives SNI extension starting just after the extension id field (i.e., at the length field)
char *parse_sni(const unsigned char *ptr);

/**
 * Generate_ja3_hash operates on a ClientHello to generate an MD5 checksum of certain
 * fields in the stream as specified by https://github.com/salesforce/ja3
 *
 * @param input The packet buffer containing the ClientHello data
 * @param sni If we are in SNI capture mode, fill this buffer with SNI data
 * @param sni If we are in ALP capture mode, fill this buffer with ALP data
 * @return Returns a strdup'd copy of the generated JA3 hash. Must be freed by caller
 */
char *generate_ja3_hash(const unsigned char *input, char **sni_buffer, char **alp_buffer);

