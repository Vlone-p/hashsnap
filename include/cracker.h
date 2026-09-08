#ifndef CRACKER_H
#define CRACKER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SHA512,
    HASH_NTLM
} hash_type_t;

typedef enum {
    SALT_NONE,
    SALT_PREFIX,
    SALT_SUFFIX
} salt_mode_t;

#define MAX_DIGEST_LEN 64
#define MAX_IDENT_LEN 128
#define MAX_SALT_LEN 64
#define MAX_RESULT_LEN 256

typedef struct {
    char identifier[MAX_IDENT_LEN];
    uint8_t digest[MAX_DIGEST_LEN];
    uint8_t salt[MAX_SALT_LEN];
    int salt_len;
    volatile int found;
    char result[MAX_RESULT_LEN];
} target_t;

typedef struct htable_node {
    size_t target_index;
    struct htable_node *next;
} htable_node_t;

typedef struct {
    htable_node_t **buckets;
    size_t capacity;
    int built;
} htable_t;

typedef struct {

    hash_type_t type;
    int target_len;
    salt_mode_t salt_mode;
    int use_rules;

    target_t *targets;
    size_t target_count;
    volatile size_t remaining;
    int uniform_salt;
    htable_t table;

    char **words;
    size_t word_count;

    int bruteforce;
    const char *charset;
    int min_len;
    int max_len;

    pthread_mutex_t lock;
    size_t next_index;
    uint64_t attempts;
    FILE *outfile;
} crack_job_t;

void compute_digest(crack_job_t *job, const char *candidate, size_t len,
                     const uint8_t *salt, int salt_len, uint8_t *out);

void build_htable(crack_job_t *job);
void free_htable(crack_job_t *job);

int check_candidate_all(crack_job_t *job, const char *candidate, size_t len);

void *dictionary_worker(void *arg);

typedef struct {
    crack_job_t *job;
    int thread_id;
    int num_threads;
} bruteforce_args_t;

void *bruteforce_worker(void *arg);

int parse_hex_hash(const char *hex, uint8_t *out, int expected_len);
int hash_type_digest_len(hash_type_t t);

#endif
