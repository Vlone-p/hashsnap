#include "ntlm.h"
#include "md4.h"

void ntlm_hash(const uint8_t *data, size_t len, uint8_t out[16]) {

    uint8_t utf16le[512];
    size_t n = len;
    if (n > 256) n = 256;

    for (size_t i = 0; i < n; ++i) {
        utf16le[i * 2] = data[i];
        utf16le[i * 2 + 1] = 0x00;
    }

    md4_hash(utf16le, n * 2, out);
}
