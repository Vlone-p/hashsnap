#include "md4.h"
#include <string.h>

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define FF(a, b, c, d, x, s) { (a) += F((b),(c),(d)) + (x); (a) = ROTLEFT((a), (s)); }
#define GG(a, b, c, d, x, s) { (a) += G((b),(c),(d)) + (x) + 0x5A827999u; (a) = ROTLEFT((a), (s)); }
#define HH(a, b, c, d, x, s) { (a) += H((b),(c),(d)) + (x) + 0x6ED9EBA1u; (a) = ROTLEFT((a), (s)); }

static void md4_transform(MD4_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, X[16];

    for (int i = 0, j = 0; i < 16; ++i, j += 4)
        X[i] = (uint32_t)data[j] | ((uint32_t)data[j+1] << 8) |
               ((uint32_t)data[j+2] << 16) | ((uint32_t)data[j+3] << 24);

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    FF(a,b,c,d,X[0],3);   FF(d,a,b,c,X[1],7);   FF(c,d,a,b,X[2],11);  FF(b,c,d,a,X[3],19);
    FF(a,b,c,d,X[4],3);   FF(d,a,b,c,X[5],7);   FF(c,d,a,b,X[6],11);  FF(b,c,d,a,X[7],19);
    FF(a,b,c,d,X[8],3);   FF(d,a,b,c,X[9],7);   FF(c,d,a,b,X[10],11); FF(b,c,d,a,X[11],19);
    FF(a,b,c,d,X[12],3);  FF(d,a,b,c,X[13],7);  FF(c,d,a,b,X[14],11); FF(b,c,d,a,X[15],19);

    GG(a,b,c,d,X[0],3);   GG(d,a,b,c,X[4],5);   GG(c,d,a,b,X[8],9);   GG(b,c,d,a,X[12],13);
    GG(a,b,c,d,X[1],3);   GG(d,a,b,c,X[5],5);   GG(c,d,a,b,X[9],9);   GG(b,c,d,a,X[13],13);
    GG(a,b,c,d,X[2],3);   GG(d,a,b,c,X[6],5);   GG(c,d,a,b,X[10],9);  GG(b,c,d,a,X[14],13);
    GG(a,b,c,d,X[3],3);   GG(d,a,b,c,X[7],5);   GG(c,d,a,b,X[11],9);  GG(b,c,d,a,X[15],13);

    HH(a,b,c,d,X[0],3);   HH(d,a,b,c,X[8],9);   HH(c,d,a,b,X[4],11);  HH(b,c,d,a,X[12],15);
    HH(a,b,c,d,X[2],3);   HH(d,a,b,c,X[10],9);  HH(c,d,a,b,X[6],11);  HH(b,c,d,a,X[14],15);
    HH(a,b,c,d,X[1],3);   HH(d,a,b,c,X[9],9);   HH(c,d,a,b,X[5],11);  HH(b,c,d,a,X[13],15);
    HH(a,b,c,d,X[3],3);   HH(d,a,b,c,X[11],9);  HH(c,d,a,b,X[7],11);  HH(b,c,d,a,X[15],15);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void md4_init(MD4_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void md4_update(MD4_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            md4_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void md4_final(MD4_CTX *ctx, uint8_t hash[16]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        md4_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    for (int j = 0; j < 8; ++j)
        ctx->data[56 + j] = (uint8_t)(ctx->bitlen >> (8 * j));

    md4_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            hash[i * 4 + j] = (uint8_t)(ctx->state[i] >> (8 * j));
        }
    }
}

void md4_hash(const uint8_t *data, size_t len, uint8_t out[16]) {
    MD4_CTX ctx;
    md4_init(&ctx);
    md4_update(&ctx, data, len);
    md4_final(&ctx, out);
}
