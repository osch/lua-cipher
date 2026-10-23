#include "../common/data.h"
#include "aes_ct64.h"
#include "ghash.h"
#include "aesmod.h"

/* ============================================================================================ */

const char* const CIPHER_AES_KEY_CLASS_NAME       = "cipher.aes.key";
const char* const CIPHER_AES_ENCRYPTOR_CLASS_NAME = "cipher.aes.encryptor";
const char* const CIPHER_AES_DECRYPTOR_CLASS_NAME = "cipher.aes.decryptor";

/* ============================================================================================ */

#define M_ECB    0
#define M_CBC    1
#define M_CFB    2
#define M_CFB8   3
#define M_OFB    4
#define M_CTR    5
#define M_GCM    6

static const char* const ModeNames[] = { "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr", "gcm", NULL };

#define DEFAULT_MODE  M_CBC

/* the modes that process whole blocks and have padding */
#define IS_BLOCK_MODE(m)  ((m) == M_ECB || (m) == M_CBC)

/* GCM: at most 2^32 - 2 blocks of data for one IV (NIST SP 800-38D, 5.2.1.1) */
#define GCM_MAX_DATA  ((((uint64_t)1) << 36) - 32)

/* errors of the data, raised by raiseDataError() */
#define ERR_NONE     0
#define ERR_LENGTH   1   /* data length is not a multiple of the block size */
#define ERR_PADDING  2
#define ERR_AUTH     3
#define ERR_LIMIT    4
#define ERR_NOTAG    5

/* ============================================================================================ */

#define OPT_MODE     0x0001
#define OPT_IV       0x0002
#define OPT_PADDING  0x0004
#define OPT_AAD      0x0008
#define OPT_TAGLEN   0x0010
#define OPT_TAG      0x0020
#define OPT_OUT      0x0040   /* never allowed, see optionError() */

#define OPTS_ENCRYPT  (OPT_MODE | OPT_IV | OPT_PADDING | OPT_AAD | OPT_TAGLEN)
#define OPTS_DECRYPT  (OPTS_ENCRYPT | OPT_TAG)

typedef struct Options
{
    unsigned given;            /* the OPT_* bits of the options given */
    int      mode;
    int      padding;          /* 1: pkcs7, 0: none */
    Input    iv;
    Input    aad;
    Input    tag;
    unsigned taglen;
} Options;

static void optionError(lua_State* L, int arg, const char* func, const char* name, unsigned opt)
{
    if (!name) {
        luaL_argerror(L, arg, "option names must be strings");
    }
    if (opt == 0) {
        luaL_argerror(L, arg, lua_pushfstring(L, "unknown option '%s'", name));
    }
    if (opt == OPT_OUT) {
        /* the output carray is an argument of its own, the last one of every call */
        luaL_argerror(L, arg, "option 'out' is not supported: pass the carray as the last argument");
    }
    luaL_argerror(L, arg, lua_pushfstring(L, "option '%s' is not supported by %s()", name, func));
}

static void checkDataOption(lua_State* L, int arg, const char* name, Input* in)
{
    const char* prefix = lua_pushfstring(L, "%s: ", name);              /* -> value, prefix */
    if (lua_type(L, -2) == LUA_TNUMBER || !toInput(L, -2, arg, prefix, in)) {
        luaL_argerror(L, arg, lua_pushfstring(L, "invalid %s value", name));
    }
    lua_pop(L, 1);                                                      /* -> value */
}

static int validTagLength(lua_Integer n)
{
    /* NIST SP 800-38D, 5.2.1.2: 128, 120, 112, 104, 96 bits, and 64 and 32 bits */
    return (n >= 12 && n <= 16) || n == 8 || n == 4;
}

static const char* modeName(int mode)
{
    return ModeNames[mode];
}

/*
 * Reads the options table at arg (0: none) for the function func, which allows the
 * options in allowed, and checks them for the mode. Errors of options that are missing
 * are raised for the argument position pos (the position of the options).
 */
static void checkOptions(lua_State* L, int arg, int pos, const char* func, unsigned allowed,
                         Options* o)
{
    int t = arg ? lua_type(L, arg) : LUA_TNONE;

    memset(o, 0, sizeof(Options));
    o->mode    = DEFAULT_MODE;
    o->padding = -1;
    o->taglen  = 16;

    if (t != LUA_TNONE && t != LUA_TNIL) {
        if (t != LUA_TTABLE) {
            luaL_argerror(L, arg, lua_pushfstring(L, "table expected, got %s", luaL_typename(L, arg)));
        }
        lua_pushnil(L);                                                 /* -> key */
        while (lua_next(L, arg)) {                                      /* -> key, value */
            const char* name = (lua_type(L, -2) == LUA_TSTRING) ? lua_tostring(L, -2) : NULL;
            unsigned    opt  = 0;
            if (name) {
                if      (strcmp(name, "mode")    == 0) opt = OPT_MODE;
                else if (strcmp(name, "iv")      == 0) opt = OPT_IV;
                else if (strcmp(name, "padding") == 0) opt = OPT_PADDING;
                else if (strcmp(name, "aad")     == 0) opt = OPT_AAD;
                else if (strcmp(name, "taglen")  == 0) opt = OPT_TAGLEN;
                else if (strcmp(name, "tag")     == 0) opt = OPT_TAG;
                else if (strcmp(name, "out")     == 0) opt = OPT_OUT;
            }
            if (!(opt & allowed)) {
                optionError(L, arg, func, name, opt);
            }
            switch (opt) {
                case OPT_MODE: {
                    const char* m = (lua_type(L, -1) == LUA_TSTRING) ? lua_tostring(L, -1) : NULL;
                    int         i;
                    o->mode = -1;
                    for (i = 0; m && ModeNames[i]; ++i) {
                        if (strcmp(m, ModeNames[i]) == 0) {
                            o->mode = i;
                        }
                    }
                    if (o->mode < 0) {
                        luaL_argerror(L, arg, "invalid mode value");
                    }
                    break;
                }
                case OPT_PADDING: {
                    const char* p = (lua_type(L, -1) == LUA_TSTRING) ? lua_tostring(L, -1) : NULL;
                    if (p && strcmp(p, "pkcs7") == 0) {
                        o->padding = 1;
                    } else if (p && strcmp(p, "none") == 0) {
                        o->padding = 0;
                    } else {
                        luaL_argerror(L, arg, "invalid padding value");
                    }
                    break;
                }
                case OPT_IV:
                    checkDataOption(L, arg, "iv", &o->iv);
                    break;
                case OPT_AAD:
                    checkDataOption(L, arg, "aad", &o->aad);
                    break;
                case OPT_TAG:
                    checkDataOption(L, arg, "tag", &o->tag);
                    break;
                case OPT_TAGLEN: {
                    lua_Integer v = 0;
                    if (!topInteger(L, &v) || !validTagLength(v)) {
                        luaL_argerror(L, arg, "invalid taglen value");
                    }
                    o->taglen = (unsigned)v;
                    break;
                }
                default:
                    break;
            }
            o->given |= opt;
            lua_pop(L, 1);                                              /* -> key */
        }                                                               /* -> */
    }

    /* the options for the mode */
    if (o->mode == M_ECB) {
        if (o->given & OPT_IV) {
            luaL_argerror(L, pos, "option 'iv' is not supported by mode 'ecb'");
        }
    } else {
        if (!(o->given & OPT_IV)) {
            luaL_argerror(L, pos, lua_pushfstring(L, "option 'iv' is required for mode '%s'",
                                                     modeName(o->mode)));
        }
        if (o->mode == M_GCM ? (o->iv.len == 0) : (o->iv.len != AES_BLOCK)) {
            luaL_argerror(L, pos, lua_pushfstring(L, "invalid iv length (%d)", (int)o->iv.len));
        }
    }
    if (IS_BLOCK_MODE(o->mode)) {
        if (o->padding < 0) {
            o->padding = 1;
        }
    } else {
        if (o->padding > 0) {
            luaL_argerror(L, pos, lua_pushfstring(L, "option 'padding' is not supported by mode '%s'",
                                                     modeName(o->mode)));
        }
        o->padding = 0;
    }
    if (o->mode != M_GCM) {
        const char* name = (o->given & OPT_AAD) ? "aad" : (o->given & OPT_TAGLEN) ? "taglen"
                         : (o->given & OPT_TAG) ? "tag" : NULL;
        if (name) {
            luaL_argerror(L, pos, lua_pushfstring(L, "option '%s' is not supported by mode '%s'",
                                                     name, modeName(o->mode)));
        }
    } else if (o->given & OPT_TAG) {
        if (!validTagLength((lua_Integer)o->tag.len)) {
            luaL_argerror(L, pos, lua_pushfstring(L, "invalid tag length (%d)", (int)o->tag.len));
        }
        if ((o->given & OPT_TAGLEN) && o->taglen != o->tag.len) {
            luaL_argerror(L, pos, "tag length contradicts taglen");
        }
        o->taglen = (unsigned)o->tag.len;
    }
}

/* ============================================================================================ */

/*
 * The key argument at arg: a key object of aes.newkey() (returned) or the key data
 * (string or carray of 16, 24 or 32 bytes, in *raw; NULL is returned).
 */
static const AesKey* checkKey(lua_State* L, int arg, Input* raw)
{
    const AesKey* k = (const AesKey*)luaL_testudata(L, arg, CIPHER_AES_KEY_CLASS_NAME);
    if (k) {
        return k;
    }
    if (lua_type(L, arg) == LUA_TNUMBER || !toInput(L, arg, arg, "", raw)) {
        luaL_argerror(L, arg, lua_pushfstring(L, "string, carray or aes key expected, got %s",
                                                 luaL_typename(L, arg)));
    }
    if (raw->len != 16 && raw->len != 24 && raw->len != 32) {
        luaL_argerror(L, arg, lua_pushfstring(L, "invalid key length (%d)", (int)raw->len));
    }
    return NULL;
}

/* ============================================================================================ */

/*
 * The state of an encryption or decryption: one-shot functions have it on the C stack,
 * stream objects in their userdata. No function of this section calls Lua.
 */
typedef struct Engine
{
    AesKey   key;
    int      mode;
    int      decrypt;
    int      padding;
    uint8_t  iv[16];      /* cbc: last ciphertext block; cfb, cfb8, ofb: the register;
                             ctr, gcm: the next counter block */
    uint8_t  ks[64];      /* ctr, gcm, cfb, ofb: keystream, ks[kspos..kslen-1] unused */
    size_t   kspos;
    size_t   kslen;
    uint8_t  buf[16];     /* ecb, cbc: input bytes of an incomplete block */
    size_t   buflen;
    uint64_t total;       /* bytes of data given so far */
    /* gcm */
    uint8_t  h[16];
    uint8_t  j0[16];
    uint8_t  y[16];       /* GHASH so far */
    uint8_t  gbuf[16];    /* ciphertext bytes of an incomplete GHASH block */
    size_t   glen;
    uint64_t aadlen;
    unsigned taglen;
    int      taglenGiven; /* decryption: taglen was given as option */
    uint8_t  tag[16];     /* encryption: the tag after the end; decryption: the expected tag */
    int      hasTag;
} Engine;

static void xorBytes(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

static void put64be(uint8_t* p, uint64_t x)
{
    int i;
    for (i = 7; i >= 0; --i) {
        p[i] = (uint8_t)x;
        x >>= 8;
    }
}

/* ctr: the 128 bit counter + 1 (big endian, wraps around) */
static void inc128(uint8_t* c)
{
    int i;
    for (i = 15; i >= 0; --i) {
        if (++c[i] != 0) {
            break;
        }
    }
}

/* gcm: the lower 32 bits of the counter + 1 */
static void inc32(uint8_t* c)
{
    int i;
    for (i = 15; i >= 12; --i) {
        if (++c[i] != 0) {
            break;
        }
    }
}

static void ghashFeed(Engine* e, const uint8_t* data, size_t len)
{
    if (e->glen > 0) {
        size_t n = 16 - e->glen;
        if (n > len) {
            n = len;
        }
        memcpy(e->gbuf + e->glen, data, n);
        e->glen += n;
        data    += n;
        len     -= n;
        if (e->glen < 16) {
            return;
        }
        cipher_ghash(e->y, e->h, e->gbuf, 16);
        e->glen = 0;
    }
    if (len >= 16) {
        size_t n = len & ~(size_t)15;
        cipher_ghash(e->y, e->h, data, n);
        data += n;
        len  -= n;
    }
    if (len > 0) {
        memcpy(e->gbuf, data, len);
        e->glen = len;
    }
}

/* the tag of gcm from the GHASH so far into tag (16 bytes) */
static void gcmTag(Engine* e, uint8_t* tag)
{
    uint8_t lens[16];
    uint8_t ek[16];

    if (e->glen > 0) {
        cipher_ghash(e->y, e->h, e->gbuf, e->glen);   /* padded with zeros */
        e->glen = 0;
    }
    put64be(lens, e->aadlen * 8);
    put64be(lens + 8, e->total * 8);
    cipher_ghash(e->y, e->h, lens, 16);
    cipher_aes_encrypt(&e->key, e->j0, ek, 1);
    xorBytes(tag, ek, e->y, 16);
}

static void engineInit(Engine* e, const AesKey* k, const Input* raw, const Options* o, int decrypt)
{
    memset(e, 0, sizeof(Engine));
    if (k) {
        e->key = *k;
    } else {
        cipher_aes_setkey(&e->key, raw->ptr, raw->len);
    }
    e->mode    = o->mode;
    e->decrypt = decrypt;
    e->padding = o->padding;
    e->kspos   = 0;
    e->kslen   = 0;
    switch (e->mode) {
        case M_CBC:
        case M_CFB8:
        case M_CTR:
            memcpy(e->iv, o->iv.ptr, 16);
            break;
        case M_CFB:
        case M_OFB:
            memcpy(e->iv, o->iv.ptr, 16);
            e->kspos = e->kslen = 16;   /* the first keystream block is computed when needed */
            break;
        case M_GCM: {
            static const uint8_t zero[16] = { 0 };
            cipher_aes_encrypt(&e->key, zero, e->h, 1);
            if (o->iv.len == 12) {
                memcpy(e->j0, o->iv.ptr, 12);
                e->j0[15] = 1;
            } else {
                uint8_t lens[16];
                memset(lens, 0, 8);
                put64be(lens + 8, (uint64_t)o->iv.len * 8);
                cipher_ghash(e->j0, e->h, o->iv.ptr, o->iv.len);
                cipher_ghash(e->j0, e->h, lens, 16);
            }
            memcpy(e->iv, e->j0, 16);
            inc32(e->iv);
            if (o->aad.len > 0) {
                cipher_ghash(e->y, e->h, o->aad.ptr, o->aad.len);   /* padded with zeros */
            }
            e->aadlen = o->aad.len;
            e->taglen = o->taglen;
            e->taglenGiven = (o->given & (OPT_TAGLEN | OPT_TAG)) != 0;
            if (o->given & OPT_TAG) {
                memcpy(e->tag, o->tag.ptr, o->tag.len);
                e->hasTag = 1;
            }
            break;
        }
        default:
            break;
    }
}

/* ecb, cbc: n whole blocks from in to out (in != out) */
static void blockRun(Engine* e, const uint8_t* in, uint8_t* out, size_t n)
{
    size_t i;
    if (n == 0) {
        return;
    }
    if (e->mode == M_ECB) {
        if (e->decrypt) {
            cipher_aes_decrypt(&e->key, in, out, n);
        } else {
            cipher_aes_encrypt(&e->key, in, out, n);
        }
    } else if (e->decrypt) {
        /* cbc: all blocks at once (four in parallel), then the xor with the previous one */
        cipher_aes_decrypt(&e->key, in, out, n);
        xorBytes(out, out, e->iv, 16);
        for (i = 1; i < n; ++i) {
            xorBytes(out + 16 * i, out + 16 * i, in + 16 * (i - 1), 16);
        }
        memcpy(e->iv, in + 16 * (n - 1), 16);
    } else {
        for (i = 0; i < n; ++i) {
            xorBytes(out, in, e->iv, 16);
            cipher_aes_encrypt(&e->key, out, out, 1);
            memcpy(e->iv, out, 16);
            in  += 16;
            out += 16;
        }
    }
}

/* ecb, cbc: the number of output bytes of update(len bytes) */
static size_t blockUpdateSize(const Engine* e, size_t len)
{
    size_t avail = e->buflen + len;
    if (e->decrypt && e->padding) {
        /* the last block is held back: it has the padding */
        return (avail > 0) ? ((avail - 1) & ~(size_t)15) : 0;
    }
    return avail & ~(size_t)15;
}

/* ecb, cbc: processes n (from blockUpdateSize) output bytes, keeps the rest of in */
static void blockUpdate(Engine* e, const uint8_t* in, size_t len, uint8_t* out, size_t n)
{
    if (e->buflen > 0 && n > 0) {
        size_t take = 16 - e->buflen;
        memcpy(e->buf + e->buflen, in, take);
        in  += take;
        len -= take;
        blockRun(e, e->buf, out, 1);
        out += 16;
        n   -= 16;
        e->buflen = 0;
    }
    blockRun(e, in, out, n / 16);
    in  += n;
    len -= n;
    memcpy(e->buf + e->buflen, in, len);
    e->buflen += len;
}

/* ctr, gcm: xor with the keystream of the counter blocks, four at a time */
static void ctrRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        size_t n;
        if (e->kspos == e->kslen) {
            int i;
            for (i = 0; i < 4; ++i) {
                memcpy(e->ks + 16 * i, e->iv, 16);
                if (e->mode == M_GCM) {
                    inc32(e->iv);
                } else {
                    inc128(e->iv);
                }
            }
            cipher_aes_encrypt(&e->key, e->ks, e->ks, 4);
            e->kspos = 0;
            e->kslen = 64;
        }
        n = e->kslen - e->kspos;
        if (n > len) {
            n = len;
        }
        xorBytes(out, in, e->ks + e->kspos, n);
        e->kspos += n;
        in  += n;
        out += n;
        len -= n;
    }
}

/* cfb (128 bit segments) */
static void cfbRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        if (e->kspos == 16) {
            if (e->decrypt && len >= 64) {
                /* decryption: the inputs of four blocks are known, in parallel */
                uint8_t t[64];
                memcpy(t, e->iv, 16);
                memcpy(t + 16, in, 48);
                cipher_aes_encrypt(&e->key, t, t, 4);
                memcpy(e->iv, in + 48, 16);
                xorBytes(out, in, t, 64);
                in  += 64;
                out += 64;
                len -= 64;
                continue;
            }
            cipher_aes_encrypt(&e->key, e->iv, e->ks, 1);
            e->kspos = 0;
        }
        {
            uint8_t c;
            if (e->decrypt) {
                c = *in;
                *out = c ^ e->ks[e->kspos];
            } else {
                c = *in ^ e->ks[e->kspos];
                *out = c;
            }
            e->iv[e->kspos++] = c;
            ++in;
            ++out;
            --len;
        }
    }
}

/* cfb8 (8 bit segments): one block encryption per byte */
static void cfb8Run(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    uint8_t t[16];
    while (len > 0) {
        uint8_t c;
        cipher_aes_encrypt(&e->key, e->iv, t, 1);
        if (e->decrypt) {
            c = *in;
            *out = c ^ t[0];
        } else {
            c = *in ^ t[0];
            *out = c;
        }
        memmove(e->iv, e->iv + 1, 15);
        e->iv[15] = c;
        ++in;
        ++out;
        --len;
    }
}

/* ofb */
static void ofbRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        size_t n;
        if (e->kspos == 16) {
            cipher_aes_encrypt(&e->key, e->iv, e->iv, 1);
            memcpy(e->ks, e->iv, 16);
            e->kspos = 0;
        }
        n = 16 - e->kspos;
        if (n > len) {
            n = len;
        }
        xorBytes(out, in, e->ks + e->kspos, n);
        e->kspos += n;
        in  += n;
        out += n;
        len -= n;
    }
}

/* the modes without blocks: len bytes from in to out */
static void streamRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    switch (e->mode) {
        case M_CTR:
            ctrRun(e, in, out, len);
            break;
        case M_GCM:
            if (e->decrypt) {
                ghashFeed(e, in, len);
                ctrRun(e, in, out, len);
            } else {
                ctrRun(e, in, out, len);
                ghashFeed(e, out, len);
            }
            break;
        case M_CFB:
            cfbRun(e, in, out, len);
            break;
        case M_CFB8:
            cfb8Run(e, in, out, len);
            break;
        case M_OFB:
            ofbRun(e, in, out, len);
            break;
        default:
            break;
    }
}

/* the size of the output of update(len bytes), or an error */
static int updateSize(const Engine* e, size_t len, size_t* n)
{
    if (e->mode == M_GCM && (uint64_t)len > GCM_MAX_DATA - e->total) {
        return ERR_LIMIT;
    }
    *n = IS_BLOCK_MODE(e->mode) ? blockUpdateSize(e, len) : len;
    return ERR_NONE;
}

static void engineUpdate(Engine* e, const uint8_t* in, size_t len, uint8_t* out, size_t n)
{
    if (IS_BLOCK_MODE(e->mode)) {
        blockUpdate(e, in, len, out, n);
    } else {
        streamRun(e, in, out, len);
    }
    e->total += len;
}

/*
 * The maximum size of the output of finish(len bytes), or an error that is found before
 * anything is done.
 */
static int finishSize(const Engine* e, size_t len, size_t* n)
{
    size_t   avail = e->buflen + len;
    uint64_t total = e->total + len;

    if (!IS_BLOCK_MODE(e->mode)) {
        return updateSize(e, len, n);
    }
    if (e->padding && !e->decrypt) {
        *n = (avail & ~(size_t)15) + 16;
        return ERR_NONE;
    }
    if (avail & 15) {
        return ERR_LENGTH;
    }
    if (e->padding && total == 0) {
        return ERR_PADDING;
    }
    *n = avail;
    return ERR_NONE;
}

/* checks the PKCS#7 padding of the last block (without branches on the data), returns
 * its length, 0 if it is invalid */
static unsigned pkcs7Length(const uint8_t* block)
{
    unsigned p   = block[15];
    unsigned bad = ((p - 1u) >> 8) | ((16u - p) >> 8);   /* p == 0 or p > 16 */
    unsigned i;
    for (i = 0; i < 16; ++i) {
        unsigned inPad = ((i + p - 16u) >> 8) ^ 0xFFFFFFu;   /* i >= 16 - p: 0xFFFFFF */
        bad |= (block[i] ^ p) & inPad;
    }
    bad = (bad | (0u - bad)) >> 31;                          /* 1 if bad != 0 */
    return p & (bad - 1u);
}

/*
 * finish(len bytes): the output (at most n bytes, from finishSize()) to out, the number
 * of bytes in *produced. Returns an error of the data (padding, authentication); the
 * output is then overwritten with zeros.
 */
static int engineFinish(Engine* e, const uint8_t* in, size_t len, uint8_t* out, size_t n,
                        size_t* produced)
{
    *produced = 0;
    if (!IS_BLOCK_MODE(e->mode)) {
        engineUpdate(e, in, len, out, len);
        *produced = len;
        if (e->mode == M_GCM) {
            uint8_t tag[16];
            gcmTag(e, tag);
            if (e->decrypt) {
                unsigned diff = 0, i;
                if (!e->hasTag) {
                    cipher_aes_wipe(out, len);
                    *produced = 0;
                    return ERR_NOTAG;
                }
                for (i = 0; i < e->taglen; ++i) {
                    diff |= (unsigned)(tag[i] ^ e->tag[i]);
                }
                if (diff != 0) {
                    cipher_aes_wipe(out, len);
                    *produced = 0;
                    return ERR_AUTH;
                }
            } else {
                memcpy(e->tag, tag, 16);
                e->hasTag = 1;
            }
        }
        return ERR_NONE;
    }
    if (e->padding && !e->decrypt) {
        size_t m = n - 16;
        unsigned pad;
        blockUpdate(e, in, len, out, m);
        pad = 16 - (unsigned)e->buflen;
        memset(e->buf + e->buflen, (int)pad, pad);
        blockRun(e, e->buf, out + m, 1);
        e->buflen = 0;
        *produced = n;
    } else {
        /* all of the data are whole blocks (checked by finishSize()) */
        blockUpdate(e, in, len, out, n);
        *produced = n;
        if (e->padding) {
            unsigned pad = pkcs7Length(out + n - 16);
            if (pad == 0) {
                cipher_aes_wipe(out, n);
                *produced = 0;
                return ERR_PADDING;
            }
            *produced = n - pad;
        }
    }
    e->total += len;
    return ERR_NONE;
}

/* raises the error of the data; total: the length of all data (for ERR_LENGTH) */
static int raiseDataError(lua_State* L, int err, uint64_t total)
{
    switch (err) {
        case ERR_LENGTH:
            lua_pushinteger(L, (lua_Integer)total);
            return luaL_error(L, "data length (%s) is not a multiple of the block size (16)",
                              lua_tostring(L, -1));
        case ERR_PADDING: return luaL_error(L, "invalid padding");
        case ERR_AUTH:    return luaL_error(L, "authentication failed");
        case ERR_LIMIT:   return luaL_error(L, "data exceeds the limit of mode 'gcm'");
        case ERR_NOTAG:   return luaL_error(L, "no tag given for mode 'gcm'");
        default:          return luaL_error(L, "internal error");
    }
}

/* ============================================================================================ */
/* module functions                                                                             */
/* ============================================================================================ */

static void pushTag(lua_State* L, const Engine* e)
{
    lua_pushlstring(L, (const char*)e->tag, e->taglen);
}

/* aes.encrypt(data, key [, opts] [, out]) -> ciphertext [, tag]
 * aes.decrypt(data, key [, opts] [, out]) -> plaintext */
static int oneShot(lua_State* L, int decrypt)
{
    Input         in, raw;
    Options       opt;
    Output        o;
    const AesKey* k;
    Engine        e;
    int           optsArg, outArg, err;
    size_t        n = 0, produced = 0, space;
    uint8_t*      p;

    checkInput(L, 1, &in);
    k = checkKey(L, 2, &raw);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, optsArg ? optsArg : 3, decrypt ? "decrypt" : "encrypt",
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    if (decrypt && opt.mode == M_GCM && !(opt.given & OPT_TAG)) {
        luaL_argerror(L, optsArg ? optsArg : 3, "option 'tag' is required for mode 'gcm'");
    }
    /* the output size depends on mode, padding and direction only: it is computed
     * (and the output prepared, which may raise "cannot resize carray") before the
     * key schedule is set up, so that no error leaves key material on the C stack */
    memset(&e, 0, sizeof e);
    e.mode    = opt.mode;
    e.decrypt = decrypt;
    e.padding = opt.padding;
    err = finishSize(&e, in.len, &n);
    if (err) {
        return raiseDataError(L, err, (uint64_t)in.len);
    }
    outInit(L, &o, outArg, outArg, 1);
    p = outPrep(&o, n, &space);
    engineInit(&e, k, &raw, &opt, decrypt);
    if (decrypt && e.mode == M_GCM) {
        /* the tag is checked before anything is decrypted */
        uint8_t  tag[16];
        unsigned diff = 0, i;
        Engine   check = e;
        ghashFeed(&check, in.ptr, in.len);
        check.total = in.len;
        gcmTag(&check, tag);
        for (i = 0; i < e.taglen; ++i) {
            diff |= (unsigned)(tag[i] ^ e.tag[i]);
        }
        cipher_aes_wipe(&check, sizeof check);
        if (diff != 0) {
            err = ERR_AUTH;
        } else {
            ctrRun(&e, in.ptr, p, in.len);
            produced = in.len;
        }
    } else {
        err = engineFinish(&e, in.ptr, in.len, p, n, &produced);
    }
    if (err) {
        cipher_aes_wipe(&e, sizeof e);
        outDiscard(&o);
        return raiseDataError(L, err, (uint64_t)in.len);
    }
    outCommit(&o, produced);
    outPush(&o, 0);
    if (e.mode == M_GCM && !decrypt) {
        pushTag(L, &e);
        cipher_aes_wipe(&e, sizeof e);
        return 2;
    }
    cipher_aes_wipe(&e, sizeof e);
    return 1;
}

static int Aes_encrypt(lua_State* L)
{
    return oneShot(L, 0);
}

static int Aes_decrypt(lua_State* L)
{
    return oneShot(L, 1);
}

/* ============================================================================================ */

typedef struct Stream
{
    Engine e;
    int    closed;
} Stream;

static Stream* newStream(lua_State* L, int decrypt)
{
    Input         raw;
    Options       opt;
    const AesKey* k;
    Stream*       s;

    k = checkKey(L, 1, &raw);
    checkOptions(L, lua_isnoneornil(L, 2) ? 0 : 2, 2, decrypt ? "decryptor" : "encryptor",
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    s = (Stream*)lua_newuserdata(L, sizeof(Stream));                    /* -> stream */
    engineInit(&s->e, k, &raw, &opt, decrypt);
    s->closed = 0;
    luaL_setmetatable(L, decrypt ? CIPHER_AES_DECRYPTOR_CLASS_NAME : CIPHER_AES_ENCRYPTOR_CLASS_NAME);
    return s;
}

/* aes.encryptor(key [, opts]) */
static int Aes_encryptor(lua_State* L)
{
    newStream(L, 0);
    return 1;
}

/* aes.decryptor(key [, opts]) */
static int Aes_decryptor(lua_State* L)
{
    newStream(L, 1);
    return 1;
}

/* aes.newkey(key) -> key object */
static int Aes_newkey(lua_State* L)
{
    Input   raw;
    AesKey* k;

    if (checkKey(L, 1, &raw)) {
        /* a key object: a new one with the same key */
        AesKey* k0 = (AesKey*)lua_touserdata(L, 1);
        k = (AesKey*)lua_newuserdata(L, sizeof(AesKey));
        *k = *k0;
    } else {
        k = (AesKey*)lua_newuserdata(L, sizeof(AesKey));
        cipher_aes_setkey(k, raw.ptr, raw.len);
    }
    luaL_setmetatable(L, CIPHER_AES_KEY_CLASS_NAME);
    return 1;
}

/* aes.version() -> the version of the module (there is no external library) */
static int Aes_version(lua_State* L)
{
    lua_getfield(L, lua_upvalueindex(1), "_VERSION");
    return 1;
}

/* ============================================================================================ */
/* stream methods                                                                               */
/* ============================================================================================ */

static Stream* checkStream(lua_State* L, int decrypt)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, decrypt ? CIPHER_AES_DECRYPTOR_CLASS_NAME
                                                       : CIPHER_AES_ENCRYPTOR_CLASS_NAME);
    if (s->closed) {
        luaL_error(L, "%s is closed", decrypt ? "decryptor" : "encryptor");
    }
    return s;
}

static void closeStream(Stream* s)
{
    int      hasTag = s->e.hasTag && !s->e.decrypt;
    int      mode   = s->e.mode;
    unsigned taglen = s->e.taglen;
    uint8_t  tag[16];
    memcpy(tag, s->e.tag, 16);
    cipher_aes_wipe(&s->e, sizeof s->e);
    s->e.mode = mode;
    if (hasTag) {
        /* the tag of an encryptor stays available for tag() */
        memcpy(s->e.tag, tag, 16);
        s->e.taglen = taglen;
        s->e.hasTag = 1;
    }
    cipher_aes_wipe(tag, sizeof tag);
    s->closed = 1;
}

static int failStream(lua_State* L, Stream* s, Output* o, int err, uint64_t total)
{
    closeStream(s);
    outDiscard(o);
    return raiseDataError(L, err, total);
}

/* encryptor:update(chunk [, out]), decryptor:update(chunk [, out]) -> string or nil, or out */
static int streamUpdate(lua_State* L, int decrypt)
{
    Stream*  s = checkStream(L, decrypt);
    Input    in;
    Output   o;
    size_t   n = 0, space;
    uint8_t* p;
    int      err;

    checkInput(L, 2, &in);
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    err = updateSize(&s->e, in.len, &n);
    if (err) {
        failStream(L, s, &o, err, s->e.total + in.len);
    }
    p = outPrep(&o, n, &space);
    engineUpdate(&s->e, in.ptr, in.len, p, n);
    outCommit(&o, n);
    outPush(&o, 1);
    return 1;
}

/* encryptor:finish([chunk] [, out]) -> string, or out [, tag]
 * decryptor:finish([chunk] [, tag] [, out]) -> string, or out */
static int streamFinish(lua_State* L, int decrypt)
{
    Stream*  s = checkStream(L, decrypt);
    Input    in, tag;
    Output   o;
    size_t   n = 0, produced = 0, space;
    uint8_t* p;
    int      err, outArg = 3;

    optInput(L, 2, &in);
    if (decrypt && lua_type(L, 3) == LUA_TSTRING) {
        /* the expected tag (gcm) */
        if (s->e.mode != M_GCM) {
            luaL_argerror(L, 3, lua_pushfstring(L, "mode '%s' has no tag", modeName(s->e.mode)));
        }
        tag.ptr = (const uint8_t*)lua_tolstring(L, 3, &tag.len);
        if (!validTagLength((lua_Integer)tag.len)) {
            luaL_argerror(L, 3, lua_pushfstring(L, "invalid tag length (%d)", (int)tag.len));
        }
        if (s->e.taglenGiven && s->e.taglen != tag.len) {
            luaL_argerror(L, 3, "tag length contradicts taglen");
        }
        outArg = 4;
    } else {
        tag.ptr = NULL;
        tag.len = 0;
        if (decrypt && lua_isnil(L, 3) && !lua_isnoneornil(L, 4)) {
            outArg = 4;   /* finish(chunk, nil, out) */
        }
    }
    lua_settop(L, outArg);
    outInit(L, &o, optOut(L, outArg), outArg, 2);
    if (tag.ptr) {
        memcpy(s->e.tag, tag.ptr, tag.len);
        s->e.taglen = (unsigned)tag.len;
        s->e.hasTag = 1;
    }
    err = finishSize(&s->e, in.len, &n);
    if (err) {
        failStream(L, s, &o, err, s->e.total + in.len);
    }
    p   = outPrep(&o, n, &space);
    err = engineFinish(&s->e, in.ptr, in.len, p, n, &produced);
    if (err) {
        failStream(L, s, &o, err, s->e.total + in.len);
    }
    outCommit(&o, produced);
    closeStream(s);
    outPush(&o, 0);
    if (!decrypt && s->e.hasTag) {
        pushTag(L, &s->e);
        return 2;
    }
    return 1;
}

static int Encryptor_update(lua_State* L)
{
    return streamUpdate(L, 0);
}

static int Encryptor_finish(lua_State* L)
{
    return streamFinish(L, 0);
}

/* encryptor:tag() -> the tag (gcm, after finish()) */
static int Encryptor_tag(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_AES_ENCRYPTOR_CLASS_NAME);
    if (s->e.mode != M_GCM) {
        return luaL_error(L, "mode '%s' has no tag", modeName(s->e.mode));
    }
    if (!s->closed || !s->e.hasTag) {
        return luaL_error(L, "the tag is only available after finish()");
    }
    pushTag(L, &s->e);
    return 1;
}

static int Decryptor_update(lua_State* L)
{
    return streamUpdate(L, 1);
}

static int Decryptor_finish(lua_State* L)
{
    return streamFinish(L, 1);
}

static int Stream_release(lua_State* L)
{
    Stream* s = (Stream*)lua_touserdata(L, 1);
    if (s) {
        cipher_aes_wipe(s, sizeof(Stream));
        s->closed = 1;
    }
    return 0;
}

static int Encryptor_toString(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_AES_ENCRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_AES_ENCRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

static int Decryptor_toString(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_AES_DECRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_AES_DECRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

/* ============================================================================================ */
/* key methods                                                                                  */
/* ============================================================================================ */

/* key:encryptblock(data [, out]), key:decryptblock(data [, out]) -> string, or out */
static int keyBlocks(lua_State* L, int decrypt)
{
    AesKey*  k = (AesKey*)luaL_checkudata(L, 1, CIPHER_AES_KEY_CLASS_NAME);
    Input    in;
    Output   o;
    size_t   space;
    uint8_t* p;

    checkInput(L, 2, &in);
    if (in.len % AES_BLOCK != 0) {
        luaL_argerror(L, 2, lua_pushfstring(L, "data length (%d) is not a multiple of the block size (16)",
                                               (int)in.len));
    }
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    p = outPrep(&o, in.len, &space);
    if (decrypt) {
        cipher_aes_decrypt(k, in.ptr, p, in.len / AES_BLOCK);
    } else {
        cipher_aes_encrypt(k, in.ptr, p, in.len / AES_BLOCK);
    }
    outCommit(&o, in.len);
    outPush(&o, 0);
    return 1;
}

static int Key_encryptblock(lua_State* L)
{
    return keyBlocks(L, 0);
}

static int Key_decryptblock(lua_State* L)
{
    return keyBlocks(L, 1);
}

static int Key_release(lua_State* L)
{
    AesKey* k = (AesKey*)lua_touserdata(L, 1);
    if (k) {
        cipher_aes_wipe(k, sizeof(AesKey));
    }
    return 0;
}

static int Key_toString(lua_State* L)
{
    AesKey* k = (AesKey*)luaL_checkudata(L, 1, CIPHER_AES_KEY_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_AES_KEY_CLASS_NAME, (void*)k);
    return 1;
}

/* ============================================================================================ */

static const luaL_Reg ModuleFunctions[] =
{
    { "encrypt",      Aes_encrypt      },
    { "decrypt",      Aes_decrypt      },
    { "encryptor",    Aes_encryptor    },
    { "decryptor",    Aes_decryptor    },
    { "newkey",       Aes_newkey       },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg EncryptorMethods[] =
{
    { "update",       Encryptor_update },
    { "finish",       Encryptor_finish },
    { "tag",          Encryptor_tag    },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg EncryptorMetaMethods[] =
{
    { "__tostring",   Encryptor_toString },
    { "__gc",         Stream_release     },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg DecryptorMethods[] =
{
    { "update",       Decryptor_update },
    { "finish",       Decryptor_finish },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg DecryptorMetaMethods[] =
{
    { "__tostring",   Decryptor_toString },
    { "__gc",         Stream_release     },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg KeyMethods[] =
{
    { "encryptblock", Key_encryptblock },
    { "decryptblock", Key_decryptblock },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg KeyMetaMethods[] =
{
    { "__tostring",   Key_toString },
    { "__gc",         Key_release  },
    { NULL,           NULL } /* sentinel */
};

/* ============================================================================================ */

static void setupMeta(lua_State* L, const char* className, int capiCache,
                      const luaL_Reg* methods, const luaL_Reg* metaMethods)
{                                                          /* -> meta */
    lua_pushstring(L, className);                          /* -> meta, className */
    lua_setfield(L, -2, "__metatable");                    /* -> meta */

    luaL_setfuncs(L, metaMethods, 0);                      /* -> meta */

    lua_newtable(L);                                       /* -> meta, Class */
    lua_pushvalue(L, capiCache);                           /* -> meta, Class, cc */
    luaL_setfuncs(L, methods, 1);                          /* -> meta, Class */
    lua_setfield(L, -2, "__index");                        /* -> meta */
}

int cipher_aes_init_module(lua_State* L, int module)
{
    int capiCache = pushCapiCache(L);                      /* -> cc */

    if (luaL_newmetatable(L, CIPHER_AES_ENCRYPTOR_CLASS_NAME)) {   /* -> cc, meta */
        setupMeta(L, CIPHER_AES_ENCRYPTOR_CLASS_NAME, capiCache,
                  EncryptorMethods, EncryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_AES_DECRYPTOR_CLASS_NAME)) {   /* -> cc, meta */
        setupMeta(L, CIPHER_AES_DECRYPTOR_CLASS_NAME, capiCache,
                  DecryptorMethods, DecryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_AES_KEY_CLASS_NAME)) {         /* -> cc, meta */
        setupMeta(L, CIPHER_AES_KEY_CLASS_NAME, capiCache, KeyMethods, KeyMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    lua_pushvalue(L, module);                              /* -> cc, module */
        lua_pushvalue(L, capiCache);                       /* -> cc, module, cc */
        luaL_setfuncs(L, ModuleFunctions, 1);              /* -> cc, module */
        lua_pushvalue(L, module);                          /* -> cc, module, module */
        lua_pushcclosure(L, Aes_version, 1);               /* -> cc, module, version */
        lua_setfield(L, -2, "version");                    /* -> cc, module */
    lua_pop(L, 2);                                         /* -> */

    return 0;
}

/* ============================================================================================ */
