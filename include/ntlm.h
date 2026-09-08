#ifndef NTLM_H
#define NTLM_H

#include <stdint.h>
#include <stddef.h>

void ntlm_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif
