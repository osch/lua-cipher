/*
 * Poly1305 (RFC 8439, section 2.5) with 26 bit limbs: the accumulator h and the key part
 * r are held in five 26 bit limbs, the products of the limbs (32 x 32 -> 64 bit) are
 * summed up and reduced modulo 2^130 - 5 with the identity 2^130 = 5. This is the well
 * known approach of the public domain poly1305-donna (32 bit variant) of Andrew Moon,
 * written anew for lua-cipher. The final reduction and the comparison select with masks,
 * there are no branches on the key or the data.
 */

#include <string.h>

#include "poly1305.h"
#include "chacha.h"

/* ============================================================================================ */

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

#define MASK26 0x3ffffffu

void cipher_poly1305_init(Poly1305* p, const uint8_t* key)
{
    memset(p, 0, sizeof(Poly1305));
    /* r with the bits cleared that RFC 8439 2.5 clamps ("r &= 0ffffffc0ffffffc0ffffffc0fffffff") */
    p->r[0] = (load32le(key + 0)     ) & 0x3ffffffu;
    p->r[1] = (load32le(key + 3) >> 2) & 0x3ffff03u;
    p->r[2] = (load32le(key + 6) >> 4) & 0x3ffc0ffu;
    p->r[3] = (load32le(key + 9) >> 6) & 0x3f03fffu;
    p->r[4] = (load32le(key + 12) >> 8) & 0x00fffffu;
    p->pad[0] = load32le(key + 16);
    p->pad[1] = load32le(key + 20);
    p->pad[2] = load32le(key + 24);
    p->pad[3] = load32le(key + 28);
}

/* whole blocks of 16 bytes; hibit: 2^128 in the limb representation (1 << 24 in h4), 0 for
 * the last block that is padded with 0x01 and zeros */
static void blocks(Poly1305* p, const uint8_t* m, size_t len, uint32_t hibit)
{
    const uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    while (len >= 16) {
        /* h += m */
        h0 += (load32le(m + 0)     ) & MASK26;
        h1 += (load32le(m + 3) >> 2) & MASK26;
        h2 += (load32le(m + 6) >> 4) & MASK26;
        h3 += (load32le(m + 9) >> 6) & MASK26;
        h4 += (load32le(m + 12) >> 8) | hibit;

        /* h *= r (mod 2^130 - 5) */
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        /* partial reduction */
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & MASK26;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & MASK26;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & MASK26;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & MASK26;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & MASK26;
        h0 += c * 5; c = h0 >> 26; h0 &= MASK26;
        h1 += c;

        m   += 16;
        len -= 16;
    }
    p->h[0] = h0;
    p->h[1] = h1;
    p->h[2] = h2;
    p->h[3] = h3;
    p->h[4] = h4;
}

void cipher_poly1305_update(Poly1305* p, const uint8_t* data, size_t len)
{
    if (p->buflen > 0) {
        size_t n = 16 - p->buflen;
        if (n > len) {
            n = len;
        }
        memcpy(p->buf + p->buflen, data, n);
        p->buflen += n;
        data += n;
        len  -= n;
        if (p->buflen < 16) {
            return;
        }
        blocks(p, p->buf, 16, 1u << 24);
        p->buflen = 0;
    }
    if (len >= 16) {
        size_t n = len & ~(size_t)15;
        blocks(p, data, n, 1u << 24);
        data += n;
        len  -= n;
    }
    if (len > 0) {
        memcpy(p->buf, data, len);
        p->buflen = len;
    }
}

void cipher_poly1305_pad16(Poly1305* p)
{
    if (p->buflen > 0) {
        memset(p->buf + p->buflen, 0, 16 - p->buflen);
        blocks(p, p->buf, 16, 1u << 24);
        p->buflen = 0;
    }
}

void cipher_poly1305_finish(Poly1305* p, uint8_t* tag)
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t f;

    if (p->buflen > 0) {
        /* the last block: the bytes, 0x01, zeros (and no 2^128) */
        p->buf[p->buflen] = 1;
        memset(p->buf + p->buflen + 1, 0, 15 - p->buflen);
        blocks(p, p->buf, 16, 0);
    }
    h0 = p->h[0]; h1 = p->h[1]; h2 = p->h[2]; h3 = p->h[3]; h4 = p->h[4];

    /* full carry */
                 c = h1 >> 26; h1 &= MASK26;
    h2 += c;     c = h2 >> 26; h2 &= MASK26;
    h3 += c;     c = h3 >> 26; h3 &= MASK26;
    h4 += c;     c = h4 >> 26; h4 &= MASK26;
    h0 += c * 5; c = h0 >> 26; h0 &= MASK26;
    h1 += c;

    /* g = h + 5 - 2^130: if g is not negative, h >= p and the result is g */
    g0 = h0 + 5; c = g0 >> 26; g0 &= MASK26;
    g1 = h1 + c; c = g1 >> 26; g1 &= MASK26;
    g2 = h2 + c; c = g2 >> 26; g2 &= MASK26;
    g3 = h3 + c; c = g3 >> 26; g3 &= MASK26;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1u;            /* all ones if g4 >= 0 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h mod 2^128 in four 32 bit words */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + s) mod 2^128 */
    f = (uint64_t)h0 + p->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32le(tag + 0, h0);
    store32le(tag + 4, h1);
    store32le(tag + 8, h2);
    store32le(tag + 12, h3);

    cipher_chacha_wipe(p, sizeof(Poly1305));
}
