#ifndef RULES_H
#define RULES_H

#include <stddef.h>

#define MAX_WORD_LEN 128
#define MAX_MUTATIONS 32

int generate_mutations(const char *word, char out[][MAX_WORD_LEN]);

#endif
