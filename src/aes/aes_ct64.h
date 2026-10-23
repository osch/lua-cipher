#ifndef CIPHER_AES_CT64_H
#define CIPHER_AES_CT64_H

#include <stddef.h>
#include <stdint.h>

/*
 * AES block cipher (FIPS 197), bitsliced constant-time implementation with 64-bit words:
 * no table lookups and no branches that depend on the key or the data. Up to four
 * blocks are processed in one pass (four times as fast as single blocks, used by the
 * modes that can process blocks in parallel).
 *
 * Adapted from the "aes_ct64" implementation of BearSSL (MIT licence, see LICENSE).
 */

#define AES_BLOCK 16

typedef struct AesKey
{
    unsigned nr;               /* number of rounds: 10, 12, 14 (0: not set) */
    unsigned keylen;           /* 16, 24, 32 */
    uint64_t sk[8 * 15];       /* the expanded bitsliced round keys, 8 words per round */
} AesKey;

/* sets the key (16, 24 or 32 bytes), returns 0, or -1 for an invalid length */
int  cipher_aes_setkey(AesKey* k, const uint8_t* key, size_t len);

/* encrypts / decrypts n blocks of 16 bytes (ECB), in and out may be the same */
void cipher_aes_encrypt(const AesKey* k, const uint8_t* in, uint8_t* out, size_t n);
void cipher_aes_decrypt(const AesKey* k, const uint8_t* in, uint8_t* out, size_t n);

/* overwrites memory with zeros in a way that the compiler does not remove */
void cipher_aes_wipe(void* p, size_t n);

#endif /* CIPHER_AES_CT64_H */
