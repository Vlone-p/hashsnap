#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "cracker.h"
#include "rules.h"
#include "colors.h"

#define DEFAULT_THREADS 4
#define MAX_WORDS 2000000
#define MAX_TARGETS 500000

static void print_banner(void) {
    printf("%s%s", C_CYAN, C_BOLD);
    printf(" _               _                           \n");
    printf("| |             | |                          \n");
    printf("| |__   __ _ ___| |__  ___ _ __   __ _ _ __  \n");
    printf("| '_ \\ / _` / __| '_ \\/ __| '_ \\ / _` | '_ \\ \n");
    printf("| | | | (_| \\__ \\ | | \\__ \\ | | | (_| | |_) |\n");
    printf("|_| |_|\\__,_|___/_| |_|___/_| |_|\\__,_| .__/ \n");
    printf("                                      | |    \n");
    printf("                                      |_|    \n");
    printf("%s", C_RESET);
    printf("%s%scrack hashes fast. dictionary + rules + brute-force + batch.%s\n\n",
           C_DIM, C_CYAN, C_RESET);
}

static void print_usage(const char *prog) {
    print_banner();
    printf("Usage:\n");
    printf("  Single hash, dictionary mode:\n");
    printf("    %s -h <hash> -t <type> -w <wordlist> [-r] [-j <threads>]\n\n", prog);
    printf("  Single hash, brute-force mode:\n");
    printf("    %s -h <hash> -t <type> -b -c <charset> --min <n> --max <n> [-j <threads>]\n\n", prog);
    printf("  Batch mode (crack many hashes from a file in one pass, dictionary or brute-force):\n");
    printf("    %s --batch <file> -t <type> -w <wordlist> [-r] [-j <threads>] [-o <outfile>]\n", prog);
    printf("    %s --batch <file> -t <type> -b -c <charset> --min <n> --max <n> [-j <threads>] [-o <outfile>]\n\n", prog);
    printf("Hash types: md5, sha1, sha256, sha512, ntlm\n\n");
    printf("Options:\n");
    printf("  -h <hash>       Target hash in hex (single-hash mode)\n");
    printf("  --batch <file>  Batch file: one target per line, 'id:hash' or 'id:hash:salt'\n");
    printf("                  (bare 'hash' per line also accepted)\n");
    printf("  -t <type>       Hash type: md5, sha1, sha256, sha512, ntlm\n");
    printf("  -w <file>       Wordlist file (dictionary mode)\n");
    printf("  -r              Apply mutation rules to each word (dictionary mode)\n");
    printf("  -b              Enable brute-force mode (single hash or batch)\n");
    printf("  -c <charset>    Character set for brute-force (e.g. \"abc0123\")\n");
    printf("  --min <n>       Minimum length for brute-force (default 1)\n");
    printf("  --max <n>       Maximum length for brute-force (default 6)\n");
    printf("  -s <salt>       Global salt applied to every target (literal text, not hex)\n");
    printf("  --salt-mode <m> 'prefix' (salt+candidate) or 'suffix' (candidate+salt).\n");
    printf("                  Default: prefix\n");
    printf("  -o <file>       Write cracked results here as 'identifier:plaintext'\n");
    printf("  -j <threads>    Number of threads (default %d)\n", DEFAULT_THREADS);
    printf("  --help          Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -h 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w data/sample_wordlist.txt -r\n", prog);
    printf("  %s --batch data/sample_ntlm_batch.txt -t ntlm -w data/sample_wordlist.txt -r -o cracked.txt\n", prog);
    printf("  %s --batch data/sample_salted_hashes.txt -t sha256 -w data/sample_wordlist.txt -r --salt-mode prefix\n", prog);
    printf("  %s -h aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d -t sha1 -b -c \"abcdefghijklmnopqrstuvwxyz0123456789\" --min 1 --max 5\n", prog);
    printf("  %s --batch data/sample_ntlm_batch.txt -t ntlm -b -c \"abcdefghijklmnopqrstuvwxyz0123456789\" --min 1 --max 5\n", prog);
}

static int parse_hash_type(const char *s, hash_type_t *out) {
    if (strcmp(s, "md5") == 0)        { *out = HASH_MD5; return 1; }
    if (strcmp(s, "sha1") == 0)       { *out = HASH_SHA1; return 1; }
    if (strcmp(s, "sha256") == 0)     { *out = HASH_SHA256; return 1; }
    if (strcmp(s, "sha512") == 0)     { *out = HASH_SHA512; return 1; }
    if (strcmp(s, "ntlm") == 0)       { *out = HASH_NTLM; return 1; }
    return 0;
}

static char **load_wordlist(const char *path, size_t *count_out) {
    FILE *f = fopen(path, "r");
    if (!f) {
        print_err("Error: could not open wordlist '%s'\n", path);
        return NULL;
    }

    char **words = malloc(sizeof(char *) * MAX_WORDS);
    if (!words) {
        print_err("Error: out of memory allocating wordlist\n");
        fclose(f);
        return NULL;
    }

    char line[MAX_WORD_LEN];
    size_t count = 0;
    while (fgets(line, sizeof(line), f) && count < MAX_WORDS) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;
        char *w = strdup(line);
        if (!w) {
            print_err("Error: out of memory loading wordlist\n");
            for (size_t i = 0; i < count; ++i) free(words[i]);
            free(words);
            fclose(f);
            return NULL;
        }
        words[count] = w;
        count++;
    }
    fclose(f);
    *count_out = count;
    return words;
}

static int load_batch(const char *path, crack_job_t *job) {
    FILE *f = fopen(path, "r");
    if (!f) {
        print_err("Error: could not open batch file '%s'\n", path);
        return 0;
    }

    target_t *targets = malloc(sizeof(target_t) * MAX_TARGETS);
    if (!targets) {
        print_err("Error: out of memory allocating target list\n");
        fclose(f);
        return 0;
    }
    size_t count = 0;
    char line[512];
    int lineno = 0;

    while (fgets(line, sizeof(line), f) && count < MAX_TARGETS) {
        lineno++;
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        char *id_field = NULL, *hash_field = NULL, *salt_field = NULL;
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", line);

        char *first_colon = strchr(buf, ':');
        if (!first_colon) {

            hash_field = buf;
        } else {
            *first_colon = '\0';
            id_field = buf;
            char *rest = first_colon + 1;
            char *second_colon = strchr(rest, ':');
            if (second_colon) {
                *second_colon = '\0';
                hash_field = rest;
                salt_field = second_colon + 1;
            } else {
                hash_field = rest;
            }
        }

        target_t *t = &targets[count];
        memset(t, 0, sizeof(target_t));

        if (id_field && id_field[0]) {
            snprintf(t->identifier, sizeof(t->identifier), "%.*s",
                     (int)sizeof(t->identifier) - 1, id_field);
        } else {
            snprintf(t->identifier, sizeof(t->identifier), "line%d", lineno);
        }

        if (!parse_hex_hash(hash_field, t->digest, job->target_len)) {
            print_warn("Warning: line %d: invalid hash '%s' for this hash type, skipping\n",
                    lineno, hash_field);
            continue;
        }

        if (salt_field && salt_field[0]) {
            size_t sl = strlen(salt_field);
            if (sl > MAX_SALT_LEN) sl = MAX_SALT_LEN;
            memcpy(t->salt, salt_field, sl);
            t->salt_len = (int)sl;
        }

        count++;
    }
    fclose(f);

    if (count == 0) {
        print_err("Error: no valid targets loaded from '%s'\n", path);
        free(targets);
        return 0;
    }

    if (count < MAX_TARGETS) {
        target_t *shrunk = realloc(targets, sizeof(target_t) * count);
        if (shrunk) targets = shrunk;
    }

    job->targets = targets;
    job->target_count = count;
    return 1;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct {
    crack_job_t *job;
    double start_time;
    volatile int *stop_flag;
} progress_args_t;

static void *progress_reporter(void *arg) {
    progress_args_t *pargs = (progress_args_t *)arg;
    crack_job_t *job = pargs->job;

    while (job->remaining > 0 && !*pargs->stop_flag) {
        usleep(500000);
        double elapsed = now_seconds() - pargs->start_time;
        uint64_t attempts = job->attempts;
        double rate = elapsed > 0 ? attempts / elapsed : 0;
        size_t cracked = job->target_count - job->remaining;
        fprintf(stderr, "\r%s[*] %s%6zu%s%s/%-6zu cracked | %10llu candidates | %10.0f H/s | %6.1fs%s",
                C_CYAN, C_BOLD, cracked, C_RESET, C_CYAN, job->target_count,
                (unsigned long long)attempts, rate, elapsed, C_RESET);
        fflush(stderr);
    }
    return NULL;
}

int main(int argc, char **argv) {
    detect_color_support();

    const char *hash_hex = NULL;
    const char *batch_path = NULL;
    const char *type_str = NULL;
    const char *wordlist_path = NULL;
    const char *charset = NULL;
    const char *global_salt = NULL;
    const char *salt_mode_str = "prefix";
    const char *output_path = NULL;
    int use_rules = 0;
    int bruteforce = 0;
    int min_len = 1;
    int max_len = 6;
    int threads = DEFAULT_THREADS;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            hash_hex = argv[++i];
        } else if (strcmp(argv[i], "--batch") == 0 && i + 1 < argc) {
            batch_path = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            type_str = argv[++i];
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            wordlist_path = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0) {
            use_rules = 1;
        } else if (strcmp(argv[i], "-b") == 0) {
            bruteforce = 1;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            charset = argv[++i];
        } else if (strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
            min_len = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            max_len = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            global_salt = argv[++i];
        } else if (strcmp(argv[i], "--salt-mode") == 0 && i + 1 < argc) {
            salt_mode_str = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_err("Unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!type_str) {
        print_err("Error: -t <type> is required.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!hash_hex && !batch_path) {
        print_err("Error: provide -h <hash> or --batch <file>.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (hash_hex && batch_path) {
        print_err("Error: use either -h or --batch, not both.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!bruteforce && !wordlist_path) {
        print_err("Error: provide -w <wordlist> or -b for brute-force mode.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (bruteforce && !charset) {
        print_err("Error: brute-force mode requires -c <charset>.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (threads < 1) threads = 1;

    crack_job_t job;
    memset(&job, 0, sizeof(job));

    if (!parse_hash_type(type_str, &job.type)) {
        print_err("Error: unknown hash type '%s' (use md5, sha1, sha256, sha512, ntlm)\n", type_str);
        return 1;
    }
    job.target_len = hash_type_digest_len(job.type);

    if (strcmp(salt_mode_str, "prefix") == 0) {
        job.salt_mode = SALT_PREFIX;
    } else if (strcmp(salt_mode_str, "suffix") == 0) {
        job.salt_mode = SALT_SUFFIX;
    } else {
        print_err("Error: --salt-mode must be 'prefix' or 'suffix'\n");
        return 1;
    }

    if (hash_hex) {
        target_t *t = malloc(sizeof(target_t));
        memset(t, 0, sizeof(target_t));
        snprintf(t->identifier, sizeof(t->identifier), "%s", hash_hex);
        if (!parse_hex_hash(hash_hex, t->digest, job.target_len)) {
            print_err("Error: hash '%s' is not valid hex of the expected length "
                            "(%d bytes / %d hex chars) for %s\n",
                    hash_hex, job.target_len, job.target_len * 2, type_str);
            free(t);
            return 1;
        }
        if (global_salt) {
            size_t sl = strlen(global_salt);
            if (sl > MAX_SALT_LEN) sl = MAX_SALT_LEN;
            memcpy(t->salt, global_salt, sl);
            t->salt_len = (int)sl;
        }
        job.targets = t;
        job.target_count = 1;
    } else {
        if (!load_batch(batch_path, &job)) return 1;
        if (global_salt) {

            for (size_t i = 0; i < job.target_count; ++i) {
                if (job.targets[i].salt_len == 0) {
                    size_t sl = strlen(global_salt);
                    if (sl > MAX_SALT_LEN) sl = MAX_SALT_LEN;
                    memcpy(job.targets[i].salt, global_salt, sl);
                    job.targets[i].salt_len = (int)sl;
                }
            }
        }
    }
    job.remaining = job.target_count;

    job.uniform_salt = 1;
    for (size_t i = 1; i < job.target_count; ++i) {
        if (job.targets[i].salt_len != job.targets[0].salt_len ||
            memcmp(job.targets[i].salt, job.targets[0].salt, (size_t)job.targets[0].salt_len) != 0) {
            job.uniform_salt = 0;
            break;
        }
    }
    if (job.uniform_salt) {
        if (!build_htable(&job)) {
            print_warn("Warning: could not allocate hash table, falling back to per-target matching\n");
            job.uniform_salt = 0;
        }
    }

    if (output_path) {
        job.outfile = fopen(output_path, "w");
        if (!job.outfile) {
            print_warn("Warning: could not open output file '%s', continuing without it\n", output_path);
        }
    }

    pthread_mutex_init(&job.lock, NULL);
    job.use_rules = use_rules;
    job.bruteforce = bruteforce;

    print_banner();
    printf("%s%s[!] For authorized security testing and educational use only.%s\n\n",
           C_YELLOW, C_BOLD, C_RESET);
    printf("%sHash type%s : %s%s%s\n", C_BOLD, C_RESET, C_MAGENTA, type_str, C_RESET);
    if (job.target_count == 1) {
        printf("%sTarget%s    : %s\n", C_BOLD, C_RESET, job.targets[0].identifier);
    } else {
        printf("%sTargets%s   : %zu (batch: %s)\n", C_BOLD, C_RESET, job.target_count, batch_path);
    }
    if (job.targets[0].salt_len > 0 || !job.uniform_salt) {
        printf("%sSalt%s      : %s (%s)\n", C_BOLD, C_RESET,
               job.uniform_salt ? "uniform, applied to all targets" :
               "per-target (mixed) -- slower matching path", salt_mode_str);
    }
    printf("%sMode%s      : %s%s\n", C_BOLD, C_RESET, bruteforce ? "brute-force" : "dictionary",
           (!bruteforce && use_rules) ? " + rules" : "");
    printf("%sThreads%s   : %d\n", C_BOLD, C_RESET, threads);

    double start = now_seconds();
    volatile int stop_flag = 0;
    pthread_t progress_thread;
    progress_args_t pargs = { &job, start, &stop_flag };
    pthread_create(&progress_thread, NULL, progress_reporter, &pargs);

    pthread_t *worker_threads = malloc(sizeof(pthread_t) * threads);
    bruteforce_args_t *bargs = NULL;

    if (bruteforce) {
        job.charset = charset;
        job.min_len = min_len;
        job.max_len = max_len;
        bargs = malloc(sizeof(bruteforce_args_t) * threads);
        for (int i = 0; i < threads; ++i) {
            bargs[i].job = &job;
            bargs[i].thread_id = i;
            bargs[i].num_threads = threads;
            pthread_create(&worker_threads[i], NULL, bruteforce_worker, &bargs[i]);
        }
    } else {
        size_t word_count = 0;
        char **words = load_wordlist(wordlist_path, &word_count);
        if (!words) {
            stop_flag = 1;
            pthread_join(progress_thread, NULL);
            return 1;
        }
        job.words = words;
        job.word_count = word_count;
        printf("%sWordlist%s  : %s (%zu words)\n", C_BOLD, C_RESET, wordlist_path, word_count);
        printf("%s-----------------------------------------------------%s\n", C_DIM, C_RESET);

        for (int i = 0; i < threads; ++i) {
            pthread_create(&worker_threads[i], NULL, dictionary_worker, &job);
        }
    }

    printf("%s-----------------------------------------------------%s\n", C_DIM, C_RESET);

    for (int i = 0; i < threads; ++i) {
        pthread_join(worker_threads[i], NULL);
    }

    stop_flag = 1;
    pthread_join(progress_thread, NULL);

    double elapsed = now_seconds() - start;
    size_t cracked = job.target_count - job.remaining;

    printf("\n%s-----------------------------------------------------%s\n", C_DIM, C_RESET);
    if (job.target_count == 1) {
        if (job.targets[0].found) {
            printf("%s%s[+] CRACKED: %s%s\n", C_GREEN, C_BOLD, job.targets[0].result, C_RESET);
        } else {
            printf("%s[-] Not found in given wordlist/keyspace.%s\n", C_YELLOW, C_RESET);
        }
    } else {
        printf("%s%s[*] Cracked %zu / %zu hashes.%s\n", C_GREEN, C_BOLD, cracked, job.target_count, C_RESET);
        if (output_path && job.outfile) {
            printf("[*] Results written to %s\n", output_path);
        }
    }
    printf("[*] Total attempts : %llu\n", (unsigned long long)job.attempts);
    printf("[*] Time elapsed   : %.2fs\n", elapsed);
    printf("[*] Average rate   : %.0f H/s\n", elapsed > 0 ? job.attempts / elapsed : 0);
    printf("%s%s=====================================================%s\n", C_CYAN, C_DIM, C_RESET);

    free(worker_threads);
    if (bargs) free(bargs);
    if (job.words) {
        for (size_t i = 0; i < job.word_count; ++i) free(job.words[i]);
        free(job.words);
    }
    if (job.outfile) fclose(job.outfile);
    free_htable(&job);
    free(job.targets);
    pthread_mutex_destroy(&job.lock);

    return cracked > 0 ? 0 : 2;
}
