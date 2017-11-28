#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ja3_hashmap.h"
#include "ujson4c/src/ujdecode.h"
#include "uthash/src/uthash.h"

typedef struct fingerprints {
	char *ja3_hash;
	char *desc;
	UT_hash_handle hh;
} fingerprints;

static fingerprints *fingerprints_hash;
static pthread_mutex_t fingerprints_mutex = PTHREAD_MUTEX_INITIALIZER;

void free_fingerprints_hash(void) {
	fingerprints *hash_node, *tmp;
	HASH_ITER(hh, fingerprints_hash, hash_node, tmp) {
		HASH_DEL(fingerprints_hash, hash_node);
		free(hash_node->ja3_hash);
		free(hash_node->desc);
		free(hash_node);
	}
}

int add_to_hash(const char *ja3_hash, const char *description) {
	fingerprints *hash_node;

	pthread_mutex_lock(&fingerprints_mutex);

	HASH_FIND_STR(fingerprints_hash, ja3_hash, hash_node);

	if (hash_node) {
		// node already exists in hash
		pthread_mutex_unlock(&fingerprints_mutex);
		return 1;
	} else {
		hash_node = calloc(1, sizeof(fingerprints));
		hash_node->ja3_hash = (char *)ja3_hash;
		hash_node->desc = (char *)description;
		HASH_ADD_KEYPTR(hh, fingerprints_hash, hash_node->ja3_hash,
						strlen(hash_node->ja3_hash), hash_node);
	}

	pthread_mutex_unlock(&fingerprints_mutex);
	return 0;
}

char *get_hash_description(const char *ja3_hash) {
	char *ret = NULL;
	fingerprints *hash_node = NULL;

	pthread_mutex_lock(&fingerprints_mutex);
	HASH_FIND_STR(fingerprints_hash, ja3_hash, hash_node);
	if (hash_node) {
		ret = strdup(hash_node->desc);
	}

	pthread_mutex_unlock(&fingerprints_mutex);
	return ret;
}

void print_hash(void) {
	fingerprints *hash_node, *tmp;

	pthread_mutex_lock(&fingerprints_mutex);

	HASH_ITER(hh, fingerprints_hash, hash_node, tmp) {
		printf("%s => %s\n", hash_node->ja3_hash, hash_node->desc);
	}

	pthread_mutex_unlock(&fingerprints_mutex);
}

static void parse_json(const char *json_str, char **ja3_hash, char **description) {
	UJObject obj;
	void *state;
	size_t json_len = strlen(json_str);

	const wchar_t *fingerprint_keys[] = {L"desc", L"ja3_hash"};
	UJObject o_desc, o_ja3_hash;

	obj = UJDecode(json_str, json_len, NULL, &state);

	if (obj == NULL) {
		printf("Error: %s\n", UJGetError(state));
	} else if (UJObjectUnpack(obj, 2, "SS", fingerprint_keys, &o_desc, &o_ja3_hash) != -1) {
		const wchar_t *hash = UJReadString(o_ja3_hash, NULL);
		const wchar_t *desc = UJReadString(o_desc, NULL);
		size_t hash_max = wcslen(hash);
		size_t desc_max = wcslen(desc);

		*ja3_hash = calloc(1, hash_max+1);
		*description = calloc(1, desc_max+1);
		wcstombs(*ja3_hash, hash, hash_max+1);
		wcstombs(*description, desc, desc_max+1);
	}

	UJFree(state);
}

void parse_json_from_file(const char *json_str) {
	char *p = (char *)json_str;

	char *substr = strtok(p, "\n");
	while (substr) {
		char *start = strchr(substr, '{');
		char *end = strchr(substr, '}');

		if (!start || !end) {
			return;
		}

		substr = start;
		substr[end - substr + 1] = '\0';

		char *description = NULL;
		char *ja3_hash = NULL;

		parse_json((const char *)substr, &ja3_hash, &description);
		if (add_to_hash(ja3_hash, description) != 0) {
			free(ja3_hash);
			free(description);
		}

		substr = strtok(NULL, "\n");
	}
}
