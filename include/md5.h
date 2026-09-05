#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[4];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t data[], size_t len);
void md5_final(MD5_CTX *ctx, uint8_t hash[16]);
void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif
