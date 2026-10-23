#include "../common/data.h"
#include "des_ct.h"
#include "desmod.h"

/*
 * DES and Triple DES (EDE) in the modes of operation ECB, CBC, CFB (64 bit segments),
 * CFB8, OFB and CTR, with the API of cipher.aes: the structure of this file follows
 * src/aes/aesmod.c, with a block size of 8 bytes and without GCM.
 */

/* ============================================================================================ */

const char* const CIPHER_DES_KEY_CLASS_NAME       = "cipher.des.key";
const char* const CIPHER_DES_ENCRYPTOR_CLASS_NAME = "cipher.des.encryptor";
const char* const CIPHER_DES_DECRYPTOR_CLASS_NAME = "cipher.des.decryptor";

/* ============================================================================================ */

#define M_ECB    0
#define M_CBC    1
#define M_CFB    2
#define M_CFB8   3
#define M_OFB    4
#define M_CTR    5

static const char* const ModeNames[] = { "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr", NULL };

#define DEFAULT_MODE  M_CBC

/* the modes that process whole blocks and have padding */
#define IS_BLOCK_MODE(m)  ((m) == M_ECB || (m) == M_CBC)

#define B  DES_BLOCK

/* errors of the data, raised by raiseDataError() */
#define ERR_NONE     0
#define ERR_LENGTH   1   /* data length is not a multiple of the block size */
#define ERR_PADDING  2

/* ============================================================================================ */

#define OPT_MODE     0x0001
#define OPT_IV       0x0002
#define OPT_PADDING  0x0004
#define OPT_OUT      0x0040   /* never allowed, see optionError() */

#define OPTS_ENCRYPT  (OPT_MODE | OPT_IV | OPT_PADDING)
#define OPTS_DECRYPT  OPTS_ENCRYPT

typedef struct Options
{
    unsigned given;            /* the OPT_* bits of the options given */
    int      mode;
    int      padding;          /* 1: pkcs7, 0: none */
    Input    iv;
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
        if (o->iv.len != B) {
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
}

/* ============================================================================================ */

/*
 * The key argument at arg: a key object of des.newkey() (returned) or the key data
 * (string or carray of 8, 16 or 24 bytes, in *raw; NULL is returned).
 */
static const DesKey* checkKey(lua_State* L, int arg, Input* raw)
{
    const DesKey* k = (const DesKey*)luaL_testudata(L, arg, CIPHER_DES_KEY_CLASS_NAME);
    if (k) {
        return k;
    }
    if (lua_type(L, arg) == LUA_TNUMBER || !toInput(L, arg, arg, "", raw)) {
        luaL_argerror(L, arg, lua_pushfstring(L, "string, carray or des key expected, got %s",
                                                 luaL_typename(L, arg)));
    }
    if (raw->len != 8 && raw->len != 16 && raw->len != 24) {
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
    DesKey   key;
    int      mode;
    int      decrypt;
    int      padding;
    uint8_t  iv[B];       /* cbc: last ciphertext block; cfb, cfb8, ofb: the register;
                             ctr: the next counter block */
    uint8_t  ks[B];       /* ctr, cfb, ofb: keystream, ks[kspos..B-1] unused */
    size_t   kspos;
    uint8_t  buf[B];      /* ecb, cbc: input bytes of an incomplete block */
    size_t   buflen;
    uint64_t total;       /* bytes of data given so far */
} Engine;

static void xorBytes(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

/* ctr: the 64 bit counter + 1 (big endian, wraps around) */
static void inc64(uint8_t* c)
{
    int i;
    for (i = B - 1; i >= 0; --i) {
        if (++c[i] != 0) {
            break;
        }
    }
}

/* the state without the key, see engineKey() */
static void engineInit(Engine* e, const Options* o, int decrypt)
{
    memset(e, 0, sizeof(Engine));
    e->mode    = o->mode;
    e->decrypt = decrypt;
    e->padding = o->padding;
    e->kspos   = B;   /* the first keystream block is computed when needed */
    if (e->mode != M_ECB) {
        memcpy(e->iv, o->iv.ptr, B);
    }
}

static void engineKey(Engine* e, const DesKey* k, const Input* raw)
{
    if (k) {
        e->key = *k;
    } else {
        cipher_des_setkey(&e->key, raw->ptr, raw->len);
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
            cipher_des_decrypt(&e->key, in, out, n);
        } else {
            cipher_des_encrypt(&e->key, in, out, n);
        }
    } else if (e->decrypt) {
        cipher_des_decrypt(&e->key, in, out, n);
        xorBytes(out, out, e->iv, B);
        for (i = 1; i < n; ++i) {
            xorBytes(out + B * i, out + B * i, in + B * (i - 1), B);
        }
        memcpy(e->iv, in + B * (n - 1), B);
    } else {
        for (i = 0; i < n; ++i) {
            xorBytes(out, in, e->iv, B);
            cipher_des_encrypt(&e->key, out, out, 1);
            memcpy(e->iv, out, B);
            in  += B;
            out += B;
        }
    }
}

/* ecb, cbc: the number of output bytes of update(len bytes) */
static size_t blockUpdateSize(const Engine* e, size_t len)
{
    size_t avail = e->buflen + len;
    if (e->decrypt && e->padding) {
        /* the last block is held back: it has the padding */
        return (avail > 0) ? ((avail - 1) & ~(size_t)(B - 1)) : 0;
    }
    return avail & ~(size_t)(B - 1);
}

/* ecb, cbc: processes n (from blockUpdateSize) output bytes, keeps the rest of in */
static void blockUpdate(Engine* e, const uint8_t* in, size_t len, uint8_t* out, size_t n)
{
    if (e->buflen > 0 && n > 0) {
        size_t take = B - e->buflen;
        memcpy(e->buf + e->buflen, in, take);
        in  += take;
        len -= take;
        blockRun(e, e->buf, out, 1);
        out += B;
        n   -= B;
        e->buflen = 0;
    }
    blockRun(e, in, out, n / B);
    in  += n;
    len -= n;
    memcpy(e->buf + e->buflen, in, len);
    e->buflen += len;
}

/* ctr: xor with the keystream of the counter blocks */
static void ctrRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        size_t n;
        if (e->kspos == B) {
            cipher_des_encrypt(&e->key, e->iv, e->ks, 1);
            inc64(e->iv);
            e->kspos = 0;
        }
        n = B - e->kspos;
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

/* cfb (64 bit segments) */
static void cfbRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        uint8_t c;
        if (e->kspos == B) {
            cipher_des_encrypt(&e->key, e->iv, e->ks, 1);
            e->kspos = 0;
        }
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

/* cfb8 (8 bit segments): one block encryption per byte */
static void cfb8Run(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    uint8_t t[B];
    while (len > 0) {
        uint8_t c;
        cipher_des_encrypt(&e->key, e->iv, t, 1);
        if (e->decrypt) {
            c = *in;
            *out = c ^ t[0];
        } else {
            c = *in ^ t[0];
            *out = c;
        }
        memmove(e->iv, e->iv + 1, B - 1);
        e->iv[B - 1] = c;
        ++in;
        ++out;
        --len;
    }
    cipher_des_wipe(t, sizeof t);
}

/* ofb */
static void ofbRun(Engine* e, const uint8_t* in, uint8_t* out, size_t len)
{
    while (len > 0) {
        size_t n;
        if (e->kspos == B) {
            cipher_des_encrypt(&e->key, e->iv, e->iv, 1);
            memcpy(e->ks, e->iv, B);
            e->kspos = 0;
        }
        n = B - e->kspos;
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

/* the size of the output of update(len bytes) */
static size_t updateSize(const Engine* e, size_t len)
{
    return IS_BLOCK_MODE(e->mode) ? blockUpdateSize(e, len) : len;
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
        *n = len;
        return ERR_NONE;
    }
    if (e->padding && !e->decrypt) {
        *n = (avail & ~(size_t)(B - 1)) + B;
        return ERR_NONE;
    }
    if (avail & (B - 1)) {
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
    unsigned p   = block[B - 1];
    unsigned bad = ((p - 1u) >> 8) | ((B - p) >> 8);   /* p == 0 or p > B */
    unsigned i;
    for (i = 0; i < B; ++i) {
        unsigned inPad = ((i + p - B) >> 8) ^ 0xFFFFFFu;   /* i >= B - p: 0xFFFFFF */
        bad |= (block[i] ^ p) & inPad;
    }
    bad = (bad | (0u - bad)) >> 31;                       /* 1 if bad != 0 */
    return p & (bad - 1u);
}

/*
 * finish(len bytes): the output (at most n bytes, from finishSize()) to out, the number
 * of bytes in *produced. Returns an error of the data (padding); the output is then
 * overwritten with zeros.
 */
static int engineFinish(Engine* e, const uint8_t* in, size_t len, uint8_t* out, size_t n,
                        size_t* produced)
{
    *produced = 0;
    if (!IS_BLOCK_MODE(e->mode)) {
        engineUpdate(e, in, len, out, len);
        *produced = len;
        return ERR_NONE;
    }
    if (e->padding && !e->decrypt) {
        size_t m = n - B;
        unsigned pad;
        blockUpdate(e, in, len, out, m);
        pad = B - (unsigned)e->buflen;
        memset(e->buf + e->buflen, (int)pad, pad);
        blockRun(e, e->buf, out + m, 1);
        e->buflen = 0;
        *produced = n;
    } else {
        /* all of the data are whole blocks (checked by finishSize()) */
        blockUpdate(e, in, len, out, n);
        *produced = n;
        if (e->padding) {
            unsigned pad = pkcs7Length(out + n - B);
            if (pad == 0) {
                cipher_des_wipe(out, n);
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
            return luaL_error(L, "data length (%s) is not a multiple of the block size (8)",
                              lua_tostring(L, -1));
        case ERR_PADDING: return luaL_error(L, "invalid padding");
        default:          return luaL_error(L, "internal error");
    }
}

/* ============================================================================================ */
/* module functions                                                                             */
/* ============================================================================================ */

/* des.encrypt(data, key [, opts] [, out]) -> ciphertext
 * des.decrypt(data, key [, opts] [, out]) -> plaintext */
static int oneShot(lua_State* L, int decrypt)
{
    Input         in, raw;
    Options       opt;
    Output        o;
    const DesKey* k;
    Engine        e;
    int           optsArg, outArg, err;
    size_t        n = 0, produced = 0, space;
    uint8_t*      p;

    checkInput(L, 1, &in);
    k = checkKey(L, 2, &raw);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, optsArg ? optsArg : 3, decrypt ? "decrypt" : "encrypt",
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    engineInit(&e, &opt, decrypt);
    err = finishSize(&e, in.len, &n);
    if (err) {
        return raiseDataError(L, err, (uint64_t)in.len);
    }
    outInit(L, &o, outArg, outArg, 1);
    p   = outPrep(&o, n, &space);         /* may raise an error: before the key is set up */
    engineKey(&e, k, &raw);
    err = engineFinish(&e, in.ptr, in.len, p, n, &produced);
    cipher_des_wipe(&e, sizeof e);
    if (err) {
        outDiscard(&o);
        return raiseDataError(L, err, (uint64_t)in.len);
    }
    outCommit(&o, produced);
    outPush(&o, 0);
    return 1;
}

static int Des_encrypt(lua_State* L)
{
    return oneShot(L, 0);
}

static int Des_decrypt(lua_State* L)
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
    const DesKey* k;
    Stream*       s;

    k = checkKey(L, 1, &raw);
    checkOptions(L, lua_isnoneornil(L, 2) ? 0 : 2, 2, decrypt ? "decryptor" : "encryptor",
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    s = (Stream*)lua_newuserdata(L, sizeof(Stream));                    /* -> stream */
    engineInit(&s->e, &opt, decrypt);
    engineKey(&s->e, k, &raw);
    s->closed = 0;
    luaL_setmetatable(L, decrypt ? CIPHER_DES_DECRYPTOR_CLASS_NAME : CIPHER_DES_ENCRYPTOR_CLASS_NAME);
    return s;
}

/* des.encryptor(key [, opts]) */
static int Des_encryptor(lua_State* L)
{
    newStream(L, 0);
    return 1;
}

/* des.decryptor(key [, opts]) */
static int Des_decryptor(lua_State* L)
{
    newStream(L, 1);
    return 1;
}

/* des.newkey(key) -> key object */
static int Des_newkey(lua_State* L)
{
    Input   raw;
    DesKey* k;

    if (checkKey(L, 1, &raw)) {
        /* a key object: a new one with the same key */
        DesKey* k0 = (DesKey*)lua_touserdata(L, 1);
        k = (DesKey*)lua_newuserdata(L, sizeof(DesKey));
        *k = *k0;
    } else {
        k = (DesKey*)lua_newuserdata(L, sizeof(DesKey));
        cipher_des_setkey(k, raw.ptr, raw.len);
    }
    luaL_setmetatable(L, CIPHER_DES_KEY_CLASS_NAME);
    return 1;
}

/* des.version() -> the version of the module (there is no external library) */
static int Des_version(lua_State* L)
{
    lua_getfield(L, lua_upvalueindex(1), "_VERSION");
    return 1;
}

/* ============================================================================================ */
/* stream methods                                                                               */
/* ============================================================================================ */

static Stream* checkStream(lua_State* L, int decrypt)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, decrypt ? CIPHER_DES_DECRYPTOR_CLASS_NAME
                                                       : CIPHER_DES_ENCRYPTOR_CLASS_NAME);
    if (s->closed) {
        luaL_error(L, "%s is closed", decrypt ? "decryptor" : "encryptor");
    }
    return s;
}

static void closeStream(Stream* s)
{
    int mode = s->e.mode;
    cipher_des_wipe(&s->e, sizeof s->e);
    s->e.mode = mode;
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
    size_t   n, space;
    uint8_t* p;

    checkInput(L, 2, &in);
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    n = updateSize(&s->e, in.len);
    p = outPrep(&o, n, &space);
    engineUpdate(&s->e, in.ptr, in.len, p, n);
    outCommit(&o, n);
    outPush(&o, 1);
    return 1;
}

/* encryptor:finish([chunk] [, out]), decryptor:finish([chunk] [, out]) -> string, or out */
static int streamFinish(lua_State* L, int decrypt)
{
    Stream*  s = checkStream(L, decrypt);
    Input    in;
    Output   o;
    size_t   n = 0, produced = 0, space;
    uint8_t* p;
    int      err, outArg = 3;

    optInput(L, 2, &in);
    if (decrypt && lua_type(L, 3) == LUA_TSTRING) {
        /* the position of the tag of authenticated modes (cipher.aes): DES has none */
        luaL_argerror(L, 3, lua_pushfstring(L, "mode '%s' has no tag", modeName(s->e.mode)));
    }
    if (decrypt && lua_isnil(L, 3) && !lua_isnoneornil(L, 4)) {
        outArg = 4;   /* finish(chunk, nil, out) */
    }
    lua_settop(L, outArg);
    outInit(L, &o, optOut(L, outArg), outArg, 2);
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

/* encryptor:tag(): DES has no authenticated mode */
static int Encryptor_tag(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_DES_ENCRYPTOR_CLASS_NAME);
    return luaL_error(L, "mode '%s' has no tag", modeName(s->e.mode));
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
        cipher_des_wipe(s, sizeof(Stream));
        s->closed = 1;
    }
    return 0;
}

static int Encryptor_toString(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_DES_ENCRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_DES_ENCRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

static int Decryptor_toString(lua_State* L)
{
    Stream* s = (Stream*)luaL_checkudata(L, 1, CIPHER_DES_DECRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_DES_DECRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

/* ============================================================================================ */
/* key methods                                                                                  */
/* ============================================================================================ */

/* key:encryptblock(data [, out]), key:decryptblock(data [, out]) -> string, or out */
static int keyBlocks(lua_State* L, int decrypt)
{
    DesKey*  k = (DesKey*)luaL_checkudata(L, 1, CIPHER_DES_KEY_CLASS_NAME);
    Input    in;
    Output   o;
    size_t   space;
    uint8_t* p;

    checkInput(L, 2, &in);
    if (in.len % B != 0) {
        luaL_argerror(L, 2, lua_pushfstring(L, "data length (%d) is not a multiple of the block size (8)",
                                               (int)in.len));
    }
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    p = outPrep(&o, in.len, &space);
    if (decrypt) {
        cipher_des_decrypt(k, in.ptr, p, in.len / B);
    } else {
        cipher_des_encrypt(k, in.ptr, p, in.len / B);
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
    DesKey* k = (DesKey*)lua_touserdata(L, 1);
    if (k) {
        cipher_des_wipe(k, sizeof(DesKey));
    }
    return 0;
}

static int Key_toString(lua_State* L)
{
    DesKey* k = (DesKey*)luaL_checkudata(L, 1, CIPHER_DES_KEY_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_DES_KEY_CLASS_NAME, (void*)k);
    return 1;
}

/* ============================================================================================ */

static const luaL_Reg ModuleFunctions[] =
{
    { "encrypt",      Des_encrypt      },
    { "decrypt",      Des_decrypt      },
    { "encryptor",    Des_encryptor    },
    { "decryptor",    Des_decryptor    },
    { "newkey",       Des_newkey       },
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

int cipher_des_init_module(lua_State* L, int module)
{
    int capiCache = pushCapiCache(L);                      /* -> cc */

    if (luaL_newmetatable(L, CIPHER_DES_ENCRYPTOR_CLASS_NAME)) {   /* -> cc, meta */
        setupMeta(L, CIPHER_DES_ENCRYPTOR_CLASS_NAME, capiCache,
                  EncryptorMethods, EncryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_DES_DECRYPTOR_CLASS_NAME)) {   /* -> cc, meta */
        setupMeta(L, CIPHER_DES_DECRYPTOR_CLASS_NAME, capiCache,
                  DecryptorMethods, DecryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_DES_KEY_CLASS_NAME)) {         /* -> cc, meta */
        setupMeta(L, CIPHER_DES_KEY_CLASS_NAME, capiCache, KeyMethods, KeyMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    lua_pushvalue(L, module);                              /* -> cc, module */
        lua_pushvalue(L, capiCache);                       /* -> cc, module, cc */
        luaL_setfuncs(L, ModuleFunctions, 1);              /* -> cc, module */
        lua_pushvalue(L, module);                          /* -> cc, module, module */
        lua_pushcclosure(L, Des_version, 1);               /* -> cc, module, version */
        lua_setfield(L, -2, "version");                    /* -> cc, module */
    lua_pop(L, 2);                                         /* -> */

    return 0;
}

/* ============================================================================================ */
