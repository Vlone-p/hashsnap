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
    SALT_PREFIX,  /* hash(salt + candidate) */
    SALT_SUFFIX   /* hash(candidate + salt) */
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

/* Simple separate chaining hash table over target digests, used to
 * check one candidate hash against many targets in O(1) average time.
 * Only valid/built when every target shares the same salt (including
 * the common case of no salt at all): see cracker.c for details. */
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
    /* shared, read only config */
    hash_type_t type;
    int target_len;           /* digest byte length for this hash type */
    salt_mode_t salt_mode;
    int use_rules;

    /* targets (1 for single hash mode, many for batch mode) */
    target_t *targets;
    size_t target_count;
    volatile size_t remaining;  /* count of targets not yet cracked */
    int uniform_salt;           /* 1 if all targets share the same salt (fast path) */
    htable_t table;             /* built only when uniform_salt == 1 */

    /* dictionary mode */
    char **words;
    size_t word_count;

    /* brute force mode */
    int bruteforce;
    const char *charset;
    int min_len;
    int max_len;

    /* shared mutable state */
    pthread_mutex_t lock;
    size_t next_index;        /* next dictionary word to claim */
    uint64_t attempts;        /* total candidates tried, for stats */
    FILE *outfile;            /* optional: results written here as found */
} crack_job_t;

/* Computes the digest of `candidate` (after applying the given salt
 * mode/value, if any) into `out`. */
void compute_digest(crack_job_t *job, const char *candidate, size_t len,
                     const uint8_t *salt, int salt_len, uint8_t *out);

/* Builds the hash table for fast lookups; call once after targets are
 * loaded, only when job->uniform_salt is 1. */
void build_htable(crack_job_t *job);
void free_htable(crack_job_t *job);

/* Checks one candidate against all targets not yet found (fast path
 * via hash table when uniform_salt, slow path iterating targets
 * otherwise). Marks matching target(s) found and writes to job->outfile
 * if set. Returns the number of targets newly found in this call. */
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
