#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[5];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t data[], size_t len);
void sha1_final(SHA1_CTX *ctx, uint8_t hash[20]);
void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
