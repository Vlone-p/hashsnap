#ifndef MD4_H
#define MD4_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} MD4_CTX;

void md4_init(MD4_CTX *ctx);
void md4_update(MD4_CTX *ctx, const uint8_t data[], size_t len);
void md4_final(MD4_CTX *ctx, uint8_t hash[16]);
void md4_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif
