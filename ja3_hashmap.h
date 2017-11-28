#pragma once

/**
 * Add a JA3_hash & description pair to the hash
 * return Returns 0 if a node is added to the hash, else 1 if node is already present
 */
int add_to_hash(const char *ja3_hash, const char *description);

/**
 * Checks the JA3 fingerprints hash map for a user-specified JA3 hash
 * return Returns a strdup'd copy or NULL; must be freed by caller
 */
char *get_hash_description(const char *ja3_hash);

/**
 * Read a string of JSON data and populate the JA3 hashmap with JA3 hashes and
 * descriptions. This function can accept multiple JSON strings simultaneously,
 * provided that each is separated by a newline character.
 */
void parse_json_from_file(const char *json_str);

void print_hash(void);
void free_fingerprints_hash(void);
