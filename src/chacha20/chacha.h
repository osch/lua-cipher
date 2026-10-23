#ifndef CIPHER_CHACHA_H
#define CIPHER_CHACHA_H

#include <stddef.h>
#include <stdint.h>

/*
 * The stream cipher ChaCha20 (RFC 8439: 96 bit nonce, 32 bit block counter; the original
 * of D. J. Bernstein: 64 bit nonce, 64 bit block counter) and XChaCha20
 * (draft-irtf-cfrg-xchacha: 192 bit nonce, HChaCha20 subkey, then ChaCha20 of RFC 8439).
 * Only additions, rotations and xors of 32 bit words: no table lookups, no branches on
 * the key or the data.
 */

#define CHACHA_KEY    32
#define CHACHA_BLOCK  64

typedef struct ChaCha
{
    uint32_t s[16];            /* the input of the block function (constants, key, counter, nonce) */
    uint8_t  ks[CHACHA_BLOCK]; /* keystream of the current block, ks[kspos..63] not yet used */
    unsigned kspos;
    int      ctr64;            /* 1: 64 bit block counter in s[12], s[13] (8 byte nonce) */
    uint64_t next;             /* the next block counter value */
    int      ended;            /* the block counter has passed its last value */
} ChaCha;

/*
 * Sets key, nonce (8, 12 or 24 bytes) and the initial block counter (for 12 and 24 byte
 * nonces at most 2^32 - 1).
 */
void cipher_chacha_init(ChaCha* c, const uint8_t* key, const uint8_t* nonce, size_t noncelen,
                        uint64_t counter);

/* 1 if len more bytes of keystream are available before the counter would wrap around */
int  cipher_chacha_available(const ChaCha* c, uint64_t len);

/* out = in xor the next len bytes of the keystream (in == NULL: the keystream itself);
 * cipher_chacha_available() must have been checked */
void cipher_chacha_xor(ChaCha* c, const uint8_t* in, uint8_t* out, size_t len);

/* HChaCha20 (draft-irtf-cfrg-xchacha, 2.2): the 32 byte subkey of key and a 16 byte nonce */
void cipher_chacha_hchacha(uint8_t* out, const uint8_t* key, const uint8_t* nonce);

/* overwrites memory with zeros in a way that the compiler does not remove */
void cipher_chacha_wipe(void* p, size_t n);

#endif /* CIPHER_CHACHA_H */
