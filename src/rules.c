#include "rules.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

static const char *suffixes[] = {
    "1", "12", "123", "1234", "!", "007", "2023", "2024", "2025", "01"
};
#define NUM_SUFFIXES (int)(sizeof(suffixes) / sizeof(suffixes[0]))

static void leet(const char *in, char *out) {
    size_t len = strlen(in);
    for (size_t i = 0; i < len && i < MAX_WORD_LEN - 1; ++i) {
        char c = tolower((unsigned char)in[i]);
        switch (c) {
            case 'a': out[i] = '4'; break;
            case 'e': out[i] = '3'; break;
            case 'i': out[i] = '1'; break;
            case 'o': out[i] = '0'; break;
            case 's': out[i] = '5'; break;
            default:  out[i] = in[i]; break;
        }
    }
    out[len < MAX_WORD_LEN - 1 ? len : MAX_WORD_LEN - 1] = '\0';
}

static void capitalize(const char *in, char *out) {
    snprintf(out, MAX_WORD_LEN, "%s", in);
    if (out[0]) out[0] = toupper((unsigned char)out[0]);
}

static void upper(const char *in, char *out) {
    size_t len = strlen(in);
    size_t n = len < MAX_WORD_LEN - 1 ? len : MAX_WORD_LEN - 1;
    for (size_t i = 0; i < n; ++i) out[i] = toupper((unsigned char)in[i]);
    out[n] = '\0';
}

int generate_mutations(const char *word, char out[][MAX_WORD_LEN]) {
    int n = 0;

    snprintf(out[n], MAX_WORD_LEN, "%s", word);
    n++;

    capitalize(word, out[n]);
    n++;

    upper(word, out[n]);
    n++;

    leet(word, out[n]);
    n++;

    {
        char tmp[MAX_WORD_LEN];
        leet(word, tmp);
        capitalize(tmp, out[n]);
        n++;
    }

    for (int i = 0; i < NUM_SUFFIXES && n < MAX_MUTATIONS - 1; ++i) {
        size_t wl = strlen(word);
        size_t sl = strlen(suffixes[i]);
        if (wl + sl >= MAX_WORD_LEN) continue;
        snprintf(out[n], MAX_WORD_LEN, "%s%s", word, suffixes[i]);
        n++;
    }

    {
        char cap[MAX_WORD_LEN];
        capitalize(word, cap);
        size_t wl = strlen(cap);
        for (int i = 0; i < NUM_SUFFIXES && n < MAX_MUTATIONS; ++i) {
            size_t sl = strlen(suffixes[i]);
            if (wl + sl >= MAX_WORD_LEN) continue;
            snprintf(out[n], MAX_WORD_LEN, "%s%s", cap, suffixes[i]);
            n++;
        }
    }

    return n;
}
