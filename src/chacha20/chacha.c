/*
 * ChaCha20 and HChaCha20, after RFC 8439 (sections 2.1 to 2.4) and
 * draft-irtf-cfrg-xchacha-03 (section 2.2), in portable C. The quarter round uses only
 * additions, xors and rotations of 32 bit words, so there are no table lookups and no
 * branches that depend on the key or the data.
 */

#include <string.h>

#include "chacha.h"

/* ============================================================================================ */

void cipher_chacha_wipe(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static uint32_t load32le(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t* p, uint32_t x)
{
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)                          \
    do {                                        \
        a += b; d ^= a; d = ROTL32(d, 16);      \
        c += d; b ^= c; b = ROTL32(b, 12);      \
        a += b; d ^= a; d = ROTL32(d, 8);       \
        c += d; b ^= c; b = ROTL32(b, 7);       \
    } while (0)

/* the 20 rounds (10 column rounds and 10 diagonal rounds) on x */
static void rounds(uint32_t* x)
{
    uint32_t x0 = x[0],   x1 = x[1],   x2 = x[2],   x3 = x[3];
    uint32_t x4 = x[4],   x5 = x[5],   x6 = x[6],   x7 = x[7];
    uint32_t x8 = x[8],   x9 = x[9],   x10 = x[10], x11 = x[11];
    uint32_t x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];
    int i;
    for (i = 0; i < 10; ++i) {
        QR(x0, x4, x8,  x12);
        QR(x1, x5, x9,  x13);
        QR(x2, x6, x10, x14);
        QR(x3, x7, x11, x15);
        QR(x0, x5, x10, x15);
        QR(x1, x6, x11, x12);
        QR(x2, x7, x8,  x13);
        QR(x3, x4, x9,  x14);
    }
    x[0]  = x0;  x[1]  = x1;  x[2]  = x2;  x[3]  = x3;
    x[4]  = x4;  x[5]  = x5;  x[6]  = x6;  x[7]  = x7;
    x[8]  = x8;  x[9]  = x9;  x[10] = x10; x[11] = x11;
    x[12] = x12; x[13] = x13; x[14] = x14; x[15] = x15;
}

/* "expand 32-byte k" */
static void setConstants(uint32_t* s)
{
    s[0] = 0x61707865u;
    s[1] = 0x3320646eu;
    s[2] = 0x79622d32u;
    s[3] = 0x6b206574u;
}

void cipher_chacha_hchacha(uint8_t* out, const uint8_t* key, const uint8_t* nonce)
{
    uint32_t x[16];
    int      i;
    setConstants(x);
    for (i = 0; i < 8; ++i) {
        x[4 + i] = load32le(key + 4 * i);
    }
    for (i = 0; i < 4; ++i) {
        x[12 + i] = load32le(nonce + 4 * i);
    }
    rounds(x);
    /* the first and the last row, without the addition of the input */
    for (i = 0; i < 4; ++i) {
        store32le(out + 4 * i, x[i]);
        store32le(out + 16 + 4 * i, x[12 + i]);
    }
    cipher_chacha_wipe(x, sizeof x);
}

void cipher_chacha_init(ChaCha* c, const uint8_t* key, const uint8_t* nonce, size_t noncelen,
                        uint64_t counter)
{
    int i;
    memset(c, 0, sizeof(ChaCha));
    setConstants(c->s);
    if (noncelen == 24) {
        /* XChaCha20: the subkey of the first 16 bytes, then ChaCha20 with the nonce of four
         * zero bytes and the last 8 bytes */
        uint8_t sub[CHACHA_KEY];
        cipher_chacha_hchacha(sub, key, nonce);
        for (i = 0; i < 8; ++i) {
            c->s[4 + i] = load32le(sub + 4 * i);
        }
        cipher_chacha_wipe(sub, sizeof sub);
        c->s[13] = 0;
        c->s[14] = load32le(nonce + 16);
        c->s[15] = load32le(nonce + 20);
    } else {
        for (i = 0; i < 8; ++i) {
            c->s[4 + i] = load32le(key + 4 * i);
        }
        if (noncelen == 8) {
            c->ctr64 = 1;
            c->s[14] = load32le(nonce);
            c->s[15] = load32le(nonce + 4);
        } else {
            c->s[13] = load32le(nonce);
            c->s[14] = load32le(nonce + 4);
            c->s[15] = load32le(nonce + 8);
        }
    }
    c->next  = counter;
    c->kspos = CHACHA_BLOCK;
}

int cipher_chacha_available(const ChaCha* c, uint64_t len)
{
    uint64_t have = CHACHA_BLOCK - c->kspos;   /* unused bytes of the current block */
    uint64_t blocks;
    if (len <= have) {
        return 1;
    }
    if (c->ended) {
        return 0;
    }
    len -= have;
    blocks = len / CHACHA_BLOCK + ((len % CHACHA_BLOCK) != 0);
    if (c->ctr64) {
        /* 2^64 - next blocks are left (all of them if next is 0) */
        return c->next == 0 || blocks <= (uint64_t)0 - c->next;
    }
    return blocks <= (((uint64_t)1) << 32) - c->next;
}

/* the keystream block of the next counter value into c->ks */
static void nextBlock(ChaCha* c)
{
    uint32_t x[16];
    int      i;
    c->s[12] = (uint32_t)c->next;
    if (c->ctr64) {
        c->s[13] = (uint32_t)(c->next >> 32);
    }
    memcpy(x, c->s, sizeof x);
    rounds(x);
    for (i = 0; i < 16; ++i) {
        store32le(c->ks + 4 * i, x[i] + c->s[i]);
    }
    cipher_chacha_wipe(x, sizeof x);
    c->kspos = 0;
    if (++c->next == 0 || (!c->ctr64 && c->next == (((uint64_t)1) << 32))) {
        c->ended = 1;
    }
}

void cipher_chacha_xor(ChaCha* c, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        size_t n, i;
        if (c->kspos == CHACHA_BLOCK) {
            nextBlock(c);
        }
        n = CHACHA_BLOCK - c->kspos;
        if (n > len) {
            n = len;
        }
        if (in) {
            for (i = 0; i < n; ++i) {
                out[i] = in[i] ^ c->ks[c->kspos + i];
            }
            in += n;
        } else {
            memcpy(out, c->ks + c->kspos, n);
        }
        c->kspos += (unsigned)n;
        out += n;
        len -= n;
    }
}
