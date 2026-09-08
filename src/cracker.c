#include "cracker.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "ntlm.h"
#include "rules.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hash_type_digest_len(hash_type_t t) {
    switch (t) {
        case HASH_MD5:    return 16;
        case HASH_SHA1:   return 20;
        case HASH_SHA256: return 32;
        case HASH_SHA512: return 64;
        case HASH_NTLM:   return 16;
        default:          return 0;
    }
}

int parse_hex_hash(const char *hex, uint8_t *out, int expected_len) {
    size_t hexlen = strlen(hex);
    if ((int)hexlen != expected_len * 2) return 0;
    for (int i = 0; i < expected_len; ++i) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return 1;
}

void compute_digest(crack_job_t *job, const char *candidate, size_t len,
                     const uint8_t *salt, int salt_len, uint8_t *out) {
    uint8_t buf[512];
    const uint8_t *input = (const uint8_t *)candidate;
    size_t input_len = len;

    if (salt_len > 0 && job->salt_mode != SALT_NONE) {
        size_t total = len + (size_t)salt_len;
        if (total > sizeof(buf)) total = sizeof(buf);

        if (job->salt_mode == SALT_PREFIX) {
            size_t sl = salt_len;
            if (sl > sizeof(buf)) sl = sizeof(buf);
            memcpy(buf, salt, sl);
            size_t remaining = sizeof(buf) - sl;
            size_t cl = len < remaining ? len : remaining;
            memcpy(buf + sl, candidate, cl);
            input_len = sl + cl;
        } else {
            size_t cl = len;
            if (cl > sizeof(buf)) cl = sizeof(buf);
            memcpy(buf, candidate, cl);
            size_t remaining = sizeof(buf) - cl;
            size_t sl = (size_t)salt_len < remaining ? (size_t)salt_len : remaining;
            memcpy(buf + cl, salt, sl);
            input_len = cl + sl;
        }
        input = buf;
    }

    switch (job->type) {
        case HASH_MD5:    md5_hash(input, input_len, out); break;
        case HASH_SHA1:   sha1_hash(input, input_len, out); break;
        case HASH_SHA256: sha256_hash(input, input_len, out); break;
        case HASH_SHA512: sha512_hash(input, input_len, out); break;
        case HASH_NTLM:   ntlm_hash(input, input_len, out); break;
    }
}

static size_t next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

static uint64_t digest_key(const uint8_t *digest) {
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) k = (k << 8) | digest[i];
    return k;
}

void build_htable(crack_job_t *job) {
    size_t cap = next_pow2(job->target_count * 2 + 1);
    if (cap < 16) cap = 16;

    job->table.buckets = calloc(cap, sizeof(htable_node_t *));
    job->table.capacity = cap;
    job->table.built = 1;

    for (size_t i = 0; i < job->target_count; ++i) {
        uint64_t key = digest_key(job->targets[i].digest);
        size_t slot = key & (cap - 1);

        htable_node_t *node = malloc(sizeof(htable_node_t));
        node->target_index = i;
        node->next = job->table.buckets[slot];
        job->table.buckets[slot] = node;
    }
}

void free_htable(crack_job_t *job) {
    if (!job->table.built) return;
    for (size_t i = 0; i < job->table.capacity; ++i) {
        htable_node_t *n = job->table.buckets[i];
        while (n) {
            htable_node_t *next = n->next;
            free(n);
            n = next;
        }
    }
    free(job->table.buckets);
    job->table.built = 0;
}

static int record_match(crack_job_t *job, target_t *t, const char *candidate) {
    pthread_mutex_lock(&job->lock);
    int newly = 0;
    if (!t->found) {
        t->found = 1;
        newly = 1;
        snprintf(t->result, sizeof(t->result), "%s", candidate);
        job->remaining--;
        if (job->outfile) {
            fprintf(job->outfile, "%s:%s\n", t->identifier, candidate);
            fflush(job->outfile);
        }
        fprintf(stderr, "\n%s%s[+] CRACKED%s %-30s -> %s%s%s\n",
                C_GREEN, C_BOLD, C_RESET, t->identifier, C_GREEN, candidate, C_RESET);
    }
    pthread_mutex_unlock(&job->lock);
    return newly;
}

int check_candidate_all(crack_job_t *job, const char *candidate, size_t len) {
    int newly_found = 0;

    if (job->uniform_salt) {

        uint8_t digest[MAX_DIGEST_LEN];
        int salt_len = job->target_count > 0 ? job->targets[0].salt_len : 0;
        const uint8_t *salt = job->target_count > 0 ? job->targets[0].salt : NULL;
        compute_digest(job, candidate, len, salt, salt_len, digest);

        uint64_t key = digest_key(digest);
        size_t slot = key & (job->table.capacity - 1);
        htable_node_t *node = job->table.buckets[slot];

        while (node) {
            target_t *t = &job->targets[node->target_index];
            if (!t->found && memcmp(digest, t->digest, job->target_len) == 0) {
                newly_found += record_match(job, t, candidate);
            }
            node = node->next;
        }
    } else {

        for (size_t i = 0; i < job->target_count; ++i) {
            target_t *t = &job->targets[i];
            if (t->found) continue;
            uint8_t digest[MAX_DIGEST_LEN];
            compute_digest(job, candidate, len, t->salt, t->salt_len, digest);
            if (memcmp(digest, t->digest, job->target_len) == 0) {
                newly_found += record_match(job, t, candidate);
            }
        }
    }

    return newly_found;
}

void *dictionary_worker(void *arg) {
    crack_job_t *job = (crack_job_t *)arg;
    char mutations[MAX_MUTATIONS][MAX_WORD_LEN];

    for (;;) {
        if (job->remaining == 0) break;

        pthread_mutex_lock(&job->lock);
        if (job->next_index >= job->word_count || job->remaining == 0) {
            pthread_mutex_unlock(&job->lock);
            break;
        }
        size_t idx = job->next_index++;
        pthread_mutex_unlock(&job->lock);

        const char *word = job->words[idx];

        if (job->use_rules) {
            int n = generate_mutations(word, mutations);
            for (int i = 0; i < n; ++i) {
                if (job->remaining == 0) break;
                size_t len = strlen(mutations[i]);
                __sync_fetch_and_add(&job->attempts, 1);
                check_candidate_all(job, mutations[i], len);
            }
        } else {
            size_t len = strlen(word);
            __sync_fetch_and_add(&job->attempts, 1);
            check_candidate_all(job, word, len);
        }
    }

    return NULL;
}

static void index_to_candidate(uint64_t index, int len, const char *charset,
                                int charset_len, char *out) {
    for (int i = len - 1; i >= 0; --i) {
        out[i] = charset[index % charset_len];
        index /= charset_len;
    }
    out[len] = '\0';
}

void *bruteforce_worker(void *arg) {
    bruteforce_args_t *bargs = (bruteforce_args_t *)arg;
    crack_job_t *job = bargs->job;
    int charset_len = (int)strlen(job->charset);
    char candidate[MAX_WORD_LEN];

    for (int len = job->min_len; len <= job->max_len; ++len) {
        if (job->remaining == 0) return NULL;

        uint64_t total = 1;
        for (int i = 0; i < len; ++i) {
            total *= (uint64_t)charset_len;
            if (total > (uint64_t)1e15) break;
        }

        for (uint64_t idx = bargs->thread_id; idx < total; idx += bargs->num_threads) {
            if (job->remaining == 0) return NULL;

            index_to_candidate(idx, len, job->charset, charset_len, candidate);
            __sync_fetch_and_add(&job->attempts, 1);
            check_candidate_all(job, candidate, (size_t)len);
        }
    }

    return NULL;
}
