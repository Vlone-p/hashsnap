#ifndef RULES_H
#define RULES_H

#include <stddef.h>

#define MAX_WORD_LEN 128
#define MAX_MUTATIONS 32

/* Generates mutations of `word` into the `out` array (each up to
 * MAX_WORD_LEN chars). Returns the number of mutations produced.
 * `out` must have space for at least MAX_MUTATIONS strings. */
int generate_mutations(const char *word, char out[][MAX_WORD_LEN]);

#endif
