#ifndef NTLM_H
#define NTLM_H

#include <stdint.h>
#include <stddef.h>

/* NTLM password hash = MD4(UTF-16LE(password)).
 * `data` is treated as an ASCII/UTF-8 byte string and converted to
 * UTF-16LE before hashing (sufficient for standard password cracking
 * wordlists/charsets; full Unicode codepoints above U+FFFF are not
 * handled). Output is always 16 bytes (same size as MD4/MD5). */
void ntlm_hash(const uint8_t *data, size_t len, uint8_t out[16]);

#endif
