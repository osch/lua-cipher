/*
 * GHASH of GCM (NIST SP 800-38D), constant time with 64-bit integer multiplications.
 *
 * Adapted from the "ghash_ctmul64" implementation of BearSSL by Thomas Pornin
 * (https://bearssl.org/, src/hash/ghash_ctmul64.c, MIT licence, see LICENSE).
 *
 * The carry-less product of two 64-bit values is computed with four masked integer
 * multiplications per part: the data bits are kept four bits apart, so that the carries
 * of the integer additions fall into the "holes" that are masked out afterwards. The
 * upper half of the 128-bit product comes from the product of the bit-reversed values.
 */

#include <string.h>

#include "ghash.h"

static uint64_t dec64be(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40)
         | ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8)  |  (uint64_t)p[7];
}

static void enc64be(uint8_t* p, uint64_t x)
{
    int i;
    for (i = 7; i >= 0; --i) {
        p[i] = (uint8_t)x;
        x >>= 8;
    }
}

/* the lower 64 bits of the carry-less product of x and y */
static uint64_t bmul64(uint64_t x, uint64_t y)
{
    uint64_t x0, x1, x2, x3;
    uint64_t y0, y1, y2, y3;
    uint64_t z0, z1, z2, z3;

    x0 = x & (uint64_t)0x1111111111111111u;
    x1 = x & (uint64_t)0x2222222222222222u;
    x2 = x & (uint64_t)0x4444444444444444u;
    x3 = x & (uint64_t)0x8888888888888888u;
    y0 = y & (uint64_t)0x1111111111111111u;
    y1 = y & (uint64_t)0x2222222222222222u;
    y2 = y & (uint64_t)0x4444444444444444u;
    y3 = y & (uint64_t)0x8888888888888888u;
    z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    z0 &= (uint64_t)0x1111111111111111u;
    z1 &= (uint64_t)0x2222222222222222u;
    z2 &= (uint64_t)0x4444444444444444u;
    z3 &= (uint64_t)0x8888888888888888u;
    return z0 | z1 | z2 | z3;
}

static uint64_t rev64(uint64_t x)
{
#define RMS(m, s)  do { x = ((x & (uint64_t)(m)) << (s)) | ((x >> (s)) & (uint64_t)(m)); } while (0)
    RMS(0x5555555555555555u,  1);
    RMS(0x3333333333333333u,  2);
    RMS(0x0F0F0F0F0F0F0F0Fu,  4);
    RMS(0x00FF00FF00FF00FFu,  8);
    RMS(0x0000FFFF0000FFFFu, 16);
#undef RMS
    return (x << 32) | (x >> 32);
}

void cipher_ghash(uint8_t y[16], const uint8_t h[16], const uint8_t* data, size_t len)
{
    const uint8_t* buf = data;
    uint64_t       y0, y1;
    uint64_t       h0, h1, h2, h0r, h1r, h2r;

    y1  = dec64be(y);
    y0  = dec64be(y + 8);
    h1  = dec64be(h);
    h0  = dec64be(h + 8);
    h0r = rev64(h0);
    h1r = rev64(h1);
    h2  = h0 ^ h1;
    h2r = h0r ^ h1r;
    while (len > 0) {
        const uint8_t* src;
        uint8_t        tmp[16];
        uint64_t       y0r, y1r, y2, y2r;
        uint64_t       z0, z1, z2, z0h, z1h, z2h;
        uint64_t       v0, v1, v2, v3;

        if (len >= 16) {
            src  = buf;
            buf += 16;
            len -= 16;
        } else {
            memcpy(tmp, buf, len);
            memset(tmp + len, 0, sizeof tmp - len);
            src = tmp;
            len = 0;
        }
        y1 ^= dec64be(src);
        y0 ^= dec64be(src + 8);

        y0r = rev64(y0);
        y1r = rev64(y1);
        y2  = y0 ^ y1;
        y2r = y0r ^ y1r;

        z0  = bmul64(y0, h0);
        z1  = bmul64(y1, h1);
        z2  = bmul64(y2, h2);
        z0h = bmul64(y0r, h0r);
        z1h = bmul64(y1r, h1r);
        z2h = bmul64(y2r, h2r);
        z2  ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = rev64(z0h) >> 1;
        z1h = rev64(z1h) >> 1;
        z2h = rev64(z2h) >> 1;

        v0 = z0;
        v1 = z0h ^ z2;
        v2 = z1 ^ z2h;
        v3 = z1h;

        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 = (v0 << 1);

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

        y0 = v2;
        y1 = v3;
    }
    enc64be(y, y1);
    enc64be(y + 8, y0);
}
