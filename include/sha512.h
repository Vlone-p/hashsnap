#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[8];
    uint64_t bitlen_lo, bitlen_hi; /* 128-bit length counter */
    uint8_t data[128];
    uint32_t datalen;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t data[], size_t len);
void sha512_final(SHA512_CTX *ctx, uint8_t hash[64]);
void sha512_hash(const uint8_t *data, size_t len, uint8_t out[64]);

#endif
