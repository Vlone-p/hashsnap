/*
 * Simple rule based mutation engine, inspired by the kinds of rules
 * used in tools like Hashcat/John (leetspeak, capitalization,
 * common suffixes). This is a small, illustrative subset.
 */
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

    /* original */
    snprintf(out[n], MAX_WORD_LEN, "%s", word);
    n++;

    /* capitalized */
    capitalize(word, out[n]);
    n++;

    /* all uppercase */
    upper(word, out[n]);
    n++;

    /* leetspeak */
    leet(word, out[n]);
    n++;

    /* leetspeak + capitalized first char */
    {
        char tmp[MAX_WORD_LEN];
        leet(word, tmp);
        capitalize(tmp, out[n]);
        n++;
    }

    /* word + common suffixes */
    for (int i = 0; i < NUM_SUFFIXES && n < MAX_MUTATIONS - 1; ++i) {
        size_t wl = strlen(word);
        size_t sl = strlen(suffixes[i]);
        if (wl + sl >= MAX_WORD_LEN) continue;
        snprintf(out[n], MAX_WORD_LEN, "%s%s", word, suffixes[i]);
        n++;
    }

    /* capitalized + common suffixes (e.g. "Password1", "Password123!"),
     * an extremely common real world pattern */
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
