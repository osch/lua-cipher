/*
 * DES (FIPS 46-3) and Triple DES (TDEA with the keying options 1 and 2, NIST SP 800-67),
 * without table lookups and without branches that depend on the key or the data.
 *
 * Table based DES implementations combine the S-boxes with the permutation P into eight
 * tables of 64 words ("SP-boxes") that are indexed with key and data dependent values,
 * which is open to cache timing attacks. Here each S-box is held as four 64 bit
 * constants, one for each of its four output bits: bit x of SB[i][j] is output bit j of
 * the S-box i+1 for the 6 bit input x. An output bit is the constant shifted right by x
 * (a shift by a variable amount, which takes the same time for every amount on current
 * processors), and it is moved directly to its place after the permutation P (SD[i][j]).
 * Every memory access and every branch is the same for all keys and all data.
 *
 * The halves are kept rotated left by one bit between the initial and the final
 * permutation (as in Richard Outerbridge's public domain implementation), so that the
 * eight 6 bit inputs of the expansion E are plain rotations of the right half. The
 * initial and the final permutation are computed with the usual sequence of masked
 * swaps.
 */

#include <string.h>

#include "des_ct.h"

/* ============================================================================================ */

#define C64(x) ((uint64_t)(x##ULL))

void cipher_des_wipe(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static uint32_t load32be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store32be(uint8_t* p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> ((32u - n) & 31u));
}

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << ((32u - n) & 31u));
}

/* ============================================================================================ */
/* key schedule (FIPS 46-3, Appendix 1: permuted choices PC-1, PC-2 and the left shifts)       */
/* ============================================================================================ */

static const unsigned char PC1[56] =
{
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const unsigned char PC2[48] =
{
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const unsigned char SHIFTS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

/* the 16 subkeys of an 8 byte key: subkey bits 6i+1 .. 6i+6 (FIPS numbering) in sk[r][i],
 * the first one as the highest bit; the parity bits (8, 16, ..., 64) are not used by PC-1 */
static void schedule(uint8_t sk[16][8], const uint8_t* key)
{
    uint64_t k = ((uint64_t)load32be(key) << 32) | load32be(key + 4);
    uint64_t cd;
    uint32_t c = 0, d = 0;
    unsigned i, r;

    for (i = 0; i < 28; ++i) {
        c |= (uint32_t)((k >> (64 - PC1[i])) & 1u) << (27 - i);
        d |= (uint32_t)((k >> (64 - PC1[28 + i])) & 1u) << (27 - i);
    }
    for (r = 0; r < 16; ++r) {
        unsigned s = SHIFTS[r];
        c  = ((c << s) | (c >> (28 - s))) & 0x0FFFFFFFu;
        d  = ((d << s) | (d >> (28 - s))) & 0x0FFFFFFFu;
        cd = ((uint64_t)c << 28) | d;
        memset(sk[r], 0, 8);
        for (i = 0; i < 48; ++i) {
            sk[r][i / 6] |= (uint8_t)(((cd >> (56 - PC2[i])) & 1u) << (5 - i % 6));
        }
    }
    cipher_des_wipe(&k, sizeof k);
    cipher_des_wipe(&cd, sizeof cd);
    cipher_des_wipe(&c, sizeof c);
    cipher_des_wipe(&d, sizeof d);
}

int cipher_des_setkey(DesKey* k, const uint8_t* key, size_t len)
{
    if (len != 8 && len != 16 && len != 24) {
        return -1;
    }
    memset(k, 0, sizeof(DesKey));
    k->keylen = (unsigned)len;
    schedule(k->sk[0], key);
    if (len == 8) {
        k->n = 1;
    } else {
        k->n = 3;
        schedule(k->sk[1], key + 8);
        if (len == 24) {
            schedule(k->sk[2], key + 16);
        } else {
            memcpy(k->sk[2], k->sk[0], sizeof k->sk[0]);   /* two key Triple DES: K3 = K1 */
        }
    }
    return 0;
}

/* ============================================================================================ */
/* the cipher function f                                                                        */
/* ============================================================================================ */

/*
 * SB[i][j]: bit x is the output bit j (j = 0: the highest of the four bits) of the S-box
 * S(i+1) of FIPS 46-3 for the input x = b1 b2 b3 b4 b5 b6 (b1 the highest bit), i.e. of
 * the entry in row 2*b1 + b6 and column b2 b3 b4 b5.
 * SD[i][j]: the position of this bit in the output of f after the permutation P, in the
 * representation rotated left by one bit (position 31 is bit 1 of FIPS 46-3 rotated).
 */
static const uint64_t SB[8][4] =
{
    { C64(0x869d497a86e67619), C64(0xb0c7871b497826bd), C64(0x27e9d492609f1f29), C64(0x917be9066f81b478) },
    { C64(0xe196196e69c3a659), C64(0x68f93c169346c3e9), C64(0x746a8b7462949fc3), C64(0xcd235ad2b865168f) },
    { C64(0x96692d696b9c90d3), C64(0xd96a863526f4794a), C64(0x76b9960c39c2b749), C64(0x4b8d9c63a965569a) },
    { C64(0x92c3e719ed90583e), C64(0xcb69718c74ca0e97), C64(0xacd1168f692cce71), C64(0x09b77c1ac34998e7) },
    { C64(0x429dcd6a79e1348e), C64(0x695b9ca191666b96), C64(0xc70b39c692f05d2b), C64(0xa4cd96d24b76b948) },
    { C64(0xb44ab695c9a4695b), C64(0xc69938d615e69a69), C64(0x52cbe13c6d9216da), C64(0x95a36a597c3ca34c) },
    { C64(0x92c761f82c96d966), C64(0x869cd96699e643c3), C64(0x6a95f41a9e4b81f4), C64(0x348e9679497969a6) },
    { C64(0xc17abd2438c716b9), C64(0x394e96b1596aa569), C64(0xa71658a7c8f13f0c), C64(0x9f6281cd619c7c2b) }
};

static const unsigned char SD[8][4] =
{
    { 24, 16, 10,  2 },
    { 20,  5, 31, 15 },
    {  9, 17,  3, 27 },
    {  7, 13, 23,  0 },
    { 25, 19,  8, 30 },
    { 29,  4, 22, 14 },
    {  1, 21, 11, 26 },
    { 28,  6, 18, 12 }
};

/* bit x (0 .. 63) of the constant c */
#if SIZE_MAX > 0xFFFFFFFFu
    /* 64 bit platforms: a shift of a 64 bit word by a variable amount is one instruction */
    #define SBIT(c, x)  ((uint32_t)((c) >> (x)) & 1u)
#else
    /* 32 bit platforms: a 64 bit shift may be compiled with a branch on bit 5 of the amount;
     * shift both halves and select one with a mask instead */
    static uint32_t sbit(uint64_t c, unsigned x)
    {
        uint32_t lo = (uint32_t)c >> (x & 31u);
        uint32_t hi = (uint32_t)(c >> 32) >> (x & 31u);
        uint32_t m  = 0u - (uint32_t)(x >> 5);
        return ((lo & ~m) | (hi & m)) & 1u;
    }
    #define SBIT(c, x)  sbit((c), (x))
#endif

/* the S-box i on the bits 4i .. 4i+5 of E(R) (FIPS numbering, bit 0 is bit 32): the right
 * half (rotated left by one bit) rotated left by rot */
#define SBOX(f, r, k, i, rot)                                       \
    do {                                                            \
        unsigned x_ = (rotl32((r), (rot)) & 63u) ^ (k)[i];          \
        (f) |= (SBIT(SB[i][0], x_) << SD[i][0])                     \
             | (SBIT(SB[i][1], x_) << SD[i][1])                     \
             | (SBIT(SB[i][2], x_) << SD[i][2])                     \
             | (SBIT(SB[i][3], x_) << SD[i][3]);                    \
    } while (0)

/* f(R, K) of FIPS 46-3 on the right half r (rotated left by one bit), with the
 * permutation P; the result is rotated left by one bit as well */
static uint32_t fround(uint32_t r, const uint8_t* k)
{
    uint32_t f = 0;
    SBOX(f, r, k, 0,  4);
    SBOX(f, r, k, 1,  8);
    SBOX(f, r, k, 2, 12);
    SBOX(f, r, k, 3, 16);
    SBOX(f, r, k, 4, 20);
    SBOX(f, r, k, 5, 24);
    SBOX(f, r, k, 6, 28);
    SBOX(f, r, k, 7,  0);
    return f;
}

/* the 16 rounds on the halves l, r (rotated); afterwards the halves are exchanged (the
 * preoutput R16 L16), so that the rounds of the next key of Triple DES follow directly */
static void rounds(const uint8_t sk[16][8], int decrypt, uint32_t* pl, uint32_t* pr)
{
    uint32_t l = *pl, r = *pr, t;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        t = l ^ fround(r, sk[decrypt ? 15 - i : i]);
        l = r;
        r = t;
    }
    *pl = r;
    *pr = l;
}

/* ============================================================================================ */
/* initial and final permutation                                                                */
/* ============================================================================================ */

/* the initial permutation IP; the halves are returned rotated left by one bit */
static void initialPermutation(uint32_t* pl, uint32_t* pr)
{
    uint32_t l = *pl, r = *pr, w;
    w = ((l >> 4)  ^ r) & 0x0F0F0F0Fu;  r ^= w;  l ^= w << 4;
    w = ((l >> 16) ^ r) & 0x0000FFFFu;  r ^= w;  l ^= w << 16;
    w = ((r >> 2)  ^ l) & 0x33333333u;  l ^= w;  r ^= w << 2;
    w = ((r >> 8)  ^ l) & 0x00FF00FFu;  l ^= w;  r ^= w << 8;
    r = rotl32(r, 1);
    w = (l ^ r) & 0xAAAAAAAAu;          l ^= w;  r ^= w;
    l = rotl32(l, 1);
    *pl = l;
    *pr = r;
}

/* the final permutation IP^-1 of the halves (rotated left by one bit) */
static void finalPermutation(uint32_t* pl, uint32_t* pr)
{
    uint32_t l = *pr, r = *pl, w;
    r = rotr32(r, 1);
    w = (l ^ r) & 0xAAAAAAAAu;          l ^= w;  r ^= w;
    l = rotr32(l, 1);
    w = ((l >> 8)  ^ r) & 0x00FF00FFu;  r ^= w;  l ^= w << 8;
    w = ((l >> 2)  ^ r) & 0x33333333u;  r ^= w;  l ^= w << 2;
    w = ((r >> 16) ^ l) & 0x0000FFFFu;  l ^= w;  r ^= w << 16;
    w = ((r >> 4)  ^ l) & 0x0F0F0F0Fu;  l ^= w;  r ^= w << 4;
    *pl = r;
    *pr = l;
}

/* ============================================================================================ */

static void cryptBlocks(const DesKey* k, const uint8_t* in, uint8_t* out, size_t n, int decrypt)
{
    while (n--) {
        uint32_t l = load32be(in);
        uint32_t r = load32be(in + 4);
        initialPermutation(&l, &r);
        if (k->n == 1) {
            rounds(k->sk[0], decrypt, &l, &r);
        } else if (!decrypt) {
            /* TDEA encryption: E(K3, D(K2, E(K1, P))) */
            rounds(k->sk[0], 0, &l, &r);
            rounds(k->sk[1], 1, &l, &r);
            rounds(k->sk[2], 0, &l, &r);
        } else {
            /* TDEA decryption: D(K1, E(K2, D(K3, C))) */
            rounds(k->sk[2], 1, &l, &r);
            rounds(k->sk[1], 0, &l, &r);
            rounds(k->sk[0], 1, &l, &r);
        }
        finalPermutation(&l, &r);
        store32be(out, l);
        store32be(out + 4, r);
        in  += DES_BLOCK;
        out += DES_BLOCK;
    }
}

void cipher_des_encrypt(const DesKey* k, const uint8_t* in, uint8_t* out, size_t n)
{
    cryptBlocks(k, in, out, n, 0);
}

void cipher_des_decrypt(const DesKey* k, const uint8_t* in, uint8_t* out, size_t n)
{
    cryptBlocks(k, in, out, n, 1);
}

/* ============================================================================================ */
