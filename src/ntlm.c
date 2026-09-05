/*
 * NTLM hash: NTHash = MD4(UTF-16LE(password)).
 * This is the hash format used for Windows/Active Directory account
 * passwords (as seen in SAM/NTDS.dit dumps, e.g. via secretsdump).
 */
#include "ntlm.h"
#include "md4.h"

void ntlm_hash(const uint8_t *data, size_t len, uint8_t out[16]) {
    /* Simple ASCII/Latin-1 -> UTF-16LE expansion: each input byte
     * becomes a 2-byte little endian code unit (high byte 0x00).
     * This matches real NTLM behavior for standard ASCII passwords. */
    uint8_t utf16le[512]; /* supports candidates up to 256 chars */
    size_t n = len;
    if (n > 256) n = 256;

    for (size_t i = 0; i < n; ++i) {
        utf16le[i * 2] = data[i];
        utf16le[i * 2 + 1] = 0x00;
    }

    md4_hash(utf16le, n * 2, out);
}
