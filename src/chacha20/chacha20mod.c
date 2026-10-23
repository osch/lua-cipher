#include "../common/data.h"
#include "chacha.h"
#include "poly1305.h"
#include "chacha20mod.h"

/*
 * The stream cipher ChaCha20 (chacha20.crypt(), chacha20.new()), the AEAD construction
 * ChaCha20-Poly1305 of RFC 8439 and XChaCha20-Poly1305 (chacha20.encrypt(), decrypt(),
 * encryptor(), decryptor()) and the one-time authenticator Poly1305 (chacha20.poly1305()).
 */

/* ============================================================================================ */

const char* const CIPHER_CHACHA20_STREAM_CLASS_NAME    = "cipher.chacha20.stream";
const char* const CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME = "cipher.chacha20.encryptor";
const char* const CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME = "cipher.chacha20.decryptor";

/* ============================================================================================ */

/* errors of the data, raised by raiseDataError() */
#define ERR_NONE     0
#define ERR_AUTH     1
#define ERR_LIMIT    2
#define ERR_NOTAG    3

#define TAG_LEN      16

/* ============================================================================================ */

#define OPT_IV       0x0001
#define OPT_COUNTER  0x0002
#define OPT_AAD      0x0004
#define OPT_TAG      0x0008
#define OPT_OUT      0x0010   /* never allowed, see optionError() */

#define OPTS_CRYPT    (OPT_IV | OPT_COUNTER)
#define OPTS_ENCRYPT  (OPT_IV | OPT_AAD)
#define OPTS_DECRYPT  (OPTS_ENCRYPT | OPT_TAG)
#define OPTS_POLY1305 0

/* the kinds of functions, for the checks of the options */
#define K_CRYPT      0        /* the plain stream cipher: iv of 8, 12 or 24 bytes, counter */
#define K_AEAD       1        /* ChaCha20-Poly1305: iv of 12 or 24 bytes */
#define K_POLY1305   2        /* no options */

typedef struct Options
{
    unsigned    given;         /* the OPT_* bits of the options given */
    Input       iv;
    Input       aad;
    Input       tag;
    lua_Integer counter;
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

/*
 * Reads the options table at arg (0: none) for the function func of the kind kind, which
 * allows the options in allowed. Errors of options that are missing are raised for the
 * argument position pos (the position of the options).
 */
static void checkOptions(lua_State* L, int arg, int pos, const char* func, int kind,
                         unsigned allowed, Options* o)
{
    int t = arg ? lua_type(L, arg) : LUA_TNONE;

    memset(o, 0, sizeof(Options));

    if (t != LUA_TNONE && t != LUA_TNIL) {
        if (t != LUA_TTABLE) {
            luaL_argerror(L, arg, lua_pushfstring(L, "table expected, got %s", luaL_typename(L, arg)));
        }
        lua_pushnil(L);                                                 /* -> key */
        while (lua_next(L, arg)) {                                      /* -> key, value */
            const char* name = (lua_type(L, -2) == LUA_TSTRING) ? lua_tostring(L, -2) : NULL;
            unsigned    opt  = 0;
            if (name) {
                if      (strcmp(name, "iv")      == 0) opt = OPT_IV;
                else if (strcmp(name, "counter") == 0) opt = OPT_COUNTER;
                else if (strcmp(name, "aad")     == 0) opt = OPT_AAD;
                else if (strcmp(name, "tag")     == 0) opt = OPT_TAG;
                else if (strcmp(name, "out")     == 0) opt = OPT_OUT;
            }
            if (!(opt & allowed)) {
                optionError(L, arg, func, name, opt);
            }
            switch (opt) {
                case OPT_IV:
                    checkDataOption(L, arg, "iv", &o->iv);
                    break;
                case OPT_AAD:
                    checkDataOption(L, arg, "aad", &o->aad);
                    break;
                case OPT_TAG:
                    checkDataOption(L, arg, "tag", &o->tag);
                    break;
                case OPT_COUNTER:
                    if (!topInteger(L, &o->counter) || o->counter < 0) {
                        luaL_argerror(L, arg, "invalid counter value");
                    }
                    break;
                default:
                    break;
            }
            o->given |= opt;
            lua_pop(L, 1);                                              /* -> key */
        }                                                               /* -> */
    }

    if (kind == K_POLY1305) {
        return;
    }
    if (!(o->given & OPT_IV)) {
        luaL_argerror(L, pos, "option 'iv' is required");
    }
    if (kind == K_AEAD ? (o->iv.len != 12 && o->iv.len != 24)
                       : (o->iv.len != 8 && o->iv.len != 12 && o->iv.len != 24)) {
        luaL_argerror(L, pos, lua_pushfstring(L, "invalid iv length (%d)", (int)o->iv.len));
    }
    if (o->iv.len != 8 && (uint64_t)o->counter > 0xFFFFFFFFu) {
        /* RFC 8439 and XChaCha20: a 32 bit block counter */
        luaL_argerror(L, pos, "invalid counter value");
    }
    if ((o->given & OPT_TAG) && o->tag.len != TAG_LEN) {
        luaL_argerror(L, pos, lua_pushfstring(L, "invalid tag length (%d)", (int)o->tag.len));
    }
}

/* the key at arg: 32 bytes, string or carray */
static void checkKey(lua_State* L, int arg, Input* key)
{
    if (lua_type(L, arg) == LUA_TNUMBER || !toInput(L, arg, arg, "", key)) {
        luaL_argerror(L, arg, lua_pushfstring(L, "string or carray expected, got %s",
                                                 luaL_typename(L, arg)));
    }
    if (key->len != CHACHA_KEY) {
        luaL_argerror(L, arg, lua_pushfstring(L, "invalid key length (%d)", (int)key->len));
    }
}

static int raiseDataError(lua_State* L, int err)
{
    switch (err) {
        case ERR_AUTH:    return luaL_error(L, "authentication failed");
        case ERR_LIMIT:   return luaL_error(L, "data exceeds the limit of the counter");
        case ERR_NOTAG:   return luaL_error(L, "no tag given");
        default:          return luaL_error(L, "internal error");
    }
}

/* compares two tags of 16 bytes without branches on the bytes, returns 0 if equal */
static unsigned tagDiff(const uint8_t* a, const uint8_t* b)
{
    unsigned diff = 0, i;
    for (i = 0; i < TAG_LEN; ++i) {
        diff |= (unsigned)(a[i] ^ b[i]);
    }
    return diff;
}

/* ============================================================================================ */
/* the stream cipher                                                                            */
/* ============================================================================================ */

static void chachaSetup(ChaCha* c, const Input* key, const Options* o)
{
    cipher_chacha_init(c, key->ptr, o->iv.ptr, o->iv.len, (uint64_t)o->counter);
}

/* chacha20.crypt(data, key [, opts] [, out]) -> string, or out */
static int Chacha20_crypt(lua_State* L)
{
    Input    in, key;
    Options  opt;
    Output   o;
    ChaCha   c;
    int      optsArg, outArg;
    size_t   space;
    uint8_t* p;

    checkInput(L, 1, &in);
    checkKey(L, 2, &key);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, optsArg ? optsArg : 3, "crypt", K_CRYPT, OPTS_CRYPT, &opt);
    outInit(L, &o, outArg, outArg, 1);
    p = outPrep(&o, in.len, &space);      /* may raise an error: before the key is set up */
    chachaSetup(&c, &key, &opt);
    if (!cipher_chacha_available(&c, (uint64_t)in.len)) {
        cipher_chacha_wipe(&c, sizeof c);
        outDiscard(&o);
        return raiseDataError(L, ERR_LIMIT);
    }
    cipher_chacha_xor(&c, in.ptr, p, in.len);
    cipher_chacha_wipe(&c, sizeof c);
    outCommit(&o, in.len);
    outPush(&o, 0);
    return 1;
}

/* chacha20.new(key [, opts]) -> stream object */
static int Chacha20_new(lua_State* L)
{
    Input   key;
    Options opt;
    ChaCha* c;

    checkKey(L, 1, &key);
    checkOptions(L, lua_isnoneornil(L, 2) ? 0 : 2, 2, "new", K_CRYPT, OPTS_CRYPT, &opt);
    c = (ChaCha*)lua_newuserdata(L, sizeof(ChaCha));                    /* -> stream */
    chachaSetup(c, &key, &opt);
    luaL_setmetatable(L, CIPHER_CHACHA20_STREAM_CLASS_NAME);
    return 1;
}

/* stream:crypt(chunk [, out]) -> string, or out */
static int Stream_crypt(lua_State* L)
{
    ChaCha*  c = (ChaCha*)luaL_checkudata(L, 1, CIPHER_CHACHA20_STREAM_CLASS_NAME);
    Input    in;
    Output   o;
    size_t   space;
    uint8_t* p;

    checkInput(L, 2, &in);
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    if (!cipher_chacha_available(c, (uint64_t)in.len)) {
        /* nothing is done: the stream is unchanged */
        outDiscard(&o);
        return raiseDataError(L, ERR_LIMIT);
    }
    p = outPrep(&o, in.len, &space);
    cipher_chacha_xor(c, in.ptr, p, in.len);
    outCommit(&o, in.len);
    outPush(&o, 0);
    return 1;
}

static int Stream_release(lua_State* L)
{
    ChaCha* c = (ChaCha*)lua_touserdata(L, 1);
    if (c) {
        cipher_chacha_wipe(c, sizeof(ChaCha));
    }
    return 0;
}

static int Stream_toString(lua_State* L)
{
    ChaCha* c = (ChaCha*)luaL_checkudata(L, 1, CIPHER_CHACHA20_STREAM_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_CHACHA20_STREAM_CLASS_NAME, (void*)c);
    return 1;
}

/* ============================================================================================ */
/* ChaCha20-Poly1305 (RFC 8439, 2.8) and XChaCha20-Poly1305                                     */
/* ============================================================================================ */

/*
 * The state of an AEAD encryption or decryption: one-shot functions have it on the C
 * stack, stream objects in their userdata. No function of this section calls Lua.
 */
typedef struct Aead
{
    ChaCha   c;
    Poly1305 p;
    int      decrypt;
    uint64_t aadlen;
    uint64_t total;            /* bytes of data given so far */
    uint8_t  tag[TAG_LEN];     /* encryption: the tag after the end; decryption: the expected tag */
    int      hasTag;
} Aead;

static void aeadInit(Aead* a, const Input* key, const Options* o, int decrypt)
{
    uint8_t otk[CHACHA_BLOCK];

    memset(a, 0, sizeof(Aead));
    /* the one-time Poly1305 key: the first 32 bytes of the block with the counter 0; the
     * data is encrypted from the counter 1 */
    cipher_chacha_init(&a->c, key->ptr, o->iv.ptr, o->iv.len, 0);
    cipher_chacha_xor(&a->c, NULL, otk, CHACHA_BLOCK);
    cipher_poly1305_init(&a->p, otk);
    cipher_chacha_wipe(otk, sizeof otk);
    cipher_poly1305_update(&a->p, o->aad.ptr, o->aad.len);
    cipher_poly1305_pad16(&a->p);
    a->aadlen  = o->aad.len;
    a->decrypt = decrypt;
    if (o->given & OPT_TAG) {
        memcpy(a->tag, o->tag.ptr, TAG_LEN);
        a->hasTag = 1;
    }
}

static int aeadCheck(const Aead* a, size_t len)
{
    return cipher_chacha_available(&a->c, (uint64_t)len) ? ERR_NONE : ERR_LIMIT;
}

static void aeadUpdate(Aead* a, const uint8_t* in, uint8_t* out, size_t len)
{
    if (a->decrypt) {
        cipher_poly1305_update(&a->p, in, len);
        cipher_chacha_xor(&a->c, in, out, len);
    } else {
        cipher_chacha_xor(&a->c, in, out, len);
        cipher_poly1305_update(&a->p, out, len);
    }
    a->total += len;
}

static void store64le(uint8_t* p, uint64_t x)
{
    int i;
    for (i = 0; i < 8; ++i) {
        p[i] = (uint8_t)x;
        x >>= 8;
    }
}

/* the tag of the data so far: the padding and the lengths, the state of Poly1305 is used up */
static void aeadTag(Aead* a, uint8_t* tag)
{
    uint8_t lens[16];
    cipher_poly1305_pad16(&a->p);
    store64le(lens, a->aadlen);
    store64le(lens + 8, a->total);
    cipher_poly1305_update(&a->p, lens, 16);
    cipher_poly1305_finish(&a->p, tag);
}

/* chacha20.encrypt(data, key [, opts] [, out]) -> ciphertext, tag
 * chacha20.decrypt(data, key [, opts] [, out]) -> plaintext */
static int oneShot(lua_State* L, int decrypt)
{
    Input    in, key;
    Options  opt;
    Output   o;
    Aead     a;
    int      optsArg, outArg, err = ERR_NONE;
    size_t   space;
    uint8_t* p;
    uint8_t  tag[TAG_LEN];

    checkInput(L, 1, &in);
    checkKey(L, 2, &key);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, optsArg ? optsArg : 3, decrypt ? "decrypt" : "encrypt", K_AEAD,
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    if (decrypt && !(opt.given & OPT_TAG)) {
        luaL_argerror(L, optsArg ? optsArg : 3, "option 'tag' is required");
    }
    outInit(L, &o, outArg, outArg, 1);
    p = outPrep(&o, in.len, &space);      /* may raise an error: before the key is set up */
    aeadInit(&a, &key, &opt, decrypt);
    err = aeadCheck(&a, in.len);
    if (!err) {
        if (decrypt) {
            /* the tag is checked before anything is decrypted */
            cipher_poly1305_update(&a.p, in.ptr, in.len);
            a.total = in.len;
            aeadTag(&a, tag);
            if (tagDiff(tag, a.tag) != 0) {
                err = ERR_AUTH;
            } else {
                cipher_chacha_xor(&a.c, in.ptr, p, in.len);
            }
        } else {
            aeadUpdate(&a, in.ptr, p, in.len);
            aeadTag(&a, a.tag);
        }
    }
    cipher_chacha_wipe(tag, sizeof tag);
    if (err) {
        cipher_chacha_wipe(&a, sizeof a);
        outDiscard(&o);
        return raiseDataError(L, err);
    }
    outCommit(&o, in.len);
    outPush(&o, 0);
    if (!decrypt) {
        lua_pushlstring(L, (const char*)a.tag, TAG_LEN);
        cipher_chacha_wipe(&a, sizeof a);
        return 2;
    }
    cipher_chacha_wipe(&a, sizeof a);
    return 1;
}

static int Chacha20_encrypt(lua_State* L)
{
    return oneShot(L, 0);
}

static int Chacha20_decrypt(lua_State* L)
{
    return oneShot(L, 1);
}

/* ============================================================================================ */

typedef struct AeadStream
{
    Aead a;
    int  closed;
} AeadStream;

static AeadStream* newStream(lua_State* L, int decrypt)
{
    Input       key;
    Options     opt;
    AeadStream* s;

    checkKey(L, 1, &key);
    checkOptions(L, lua_isnoneornil(L, 2) ? 0 : 2, 2, decrypt ? "decryptor" : "encryptor", K_AEAD,
                 decrypt ? OPTS_DECRYPT : OPTS_ENCRYPT, &opt);
    s = (AeadStream*)lua_newuserdata(L, sizeof(AeadStream));            /* -> stream */
    aeadInit(&s->a, &key, &opt, decrypt);
    s->closed = 0;
    luaL_setmetatable(L, decrypt ? CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME
                                 : CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME);
    return s;
}

/* chacha20.encryptor(key [, opts]) */
static int Chacha20_encryptor(lua_State* L)
{
    newStream(L, 0);
    return 1;
}

/* chacha20.decryptor(key [, opts]) */
static int Chacha20_decryptor(lua_State* L)
{
    newStream(L, 1);
    return 1;
}

static AeadStream* checkStream(lua_State* L, int decrypt)
{
    AeadStream* s = (AeadStream*)luaL_checkudata(L, 1, decrypt ? CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME
                                                               : CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME);
    if (s->closed) {
        luaL_error(L, "%s is closed", decrypt ? "decryptor" : "encryptor");
    }
    return s;
}

static void closeStream(AeadStream* s)
{
    int     hasTag = s->a.hasTag && !s->a.decrypt;
    uint8_t tag[TAG_LEN];
    memcpy(tag, s->a.tag, TAG_LEN);
    cipher_chacha_wipe(&s->a, sizeof s->a);
    if (hasTag) {
        /* the tag of an encryptor stays available for tag() */
        memcpy(s->a.tag, tag, TAG_LEN);
        s->a.hasTag = 1;
    }
    cipher_chacha_wipe(tag, sizeof tag);
    s->closed = 1;
}

static int failStream(lua_State* L, AeadStream* s, Output* o, int err)
{
    closeStream(s);
    outDiscard(o);
    return raiseDataError(L, err);
}

/* encryptor:update(chunk [, out]), decryptor:update(chunk [, out]) -> string or nil, or out */
static int streamUpdate(lua_State* L, int decrypt)
{
    AeadStream* s = checkStream(L, decrypt);
    Input       in;
    Output      o;
    size_t      space;
    uint8_t*    p;
    int         err;

    checkInput(L, 2, &in);
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    err = aeadCheck(&s->a, in.len);
    if (err) {
        failStream(L, s, &o, err);
    }
    p = outPrep(&o, in.len, &space);
    aeadUpdate(&s->a, in.ptr, p, in.len);
    outCommit(&o, in.len);
    outPush(&o, 1);
    return 1;
}

/* encryptor:finish([chunk] [, out]) -> string, or out, and the tag
 * decryptor:finish([chunk] [, tag] [, out]) -> string, or out */
static int streamFinish(lua_State* L, int decrypt)
{
    AeadStream* s = checkStream(L, decrypt);
    Input       in, tag;
    Output      o;
    size_t      space;
    uint8_t*    p;
    int         err, outArg = 3;

    optInput(L, 2, &in);
    tag.ptr = NULL;
    tag.len = 0;
    if (decrypt && lua_type(L, 3) == LUA_TSTRING) {
        /* the expected tag */
        tag.ptr = (const uint8_t*)lua_tolstring(L, 3, &tag.len);
        if (tag.len != TAG_LEN) {
            luaL_argerror(L, 3, lua_pushfstring(L, "invalid tag length (%d)", (int)tag.len));
        }
        outArg = 4;
    } else if (decrypt && lua_isnil(L, 3) && !lua_isnoneornil(L, 4)) {
        outArg = 4;   /* finish(chunk, nil, out) */
    }
    lua_settop(L, outArg);
    outInit(L, &o, optOut(L, outArg), outArg, 2);
    if (tag.ptr) {
        memcpy(s->a.tag, tag.ptr, TAG_LEN);
        s->a.hasTag = 1;
    }
    err = aeadCheck(&s->a, in.len);
    if (err) {
        failStream(L, s, &o, err);
    }
    p = outPrep(&o, in.len, &space);
    aeadUpdate(&s->a, in.ptr, p, in.len);
    if (decrypt) {
        uint8_t computed[TAG_LEN];
        if (!s->a.hasTag) {
            err = ERR_NOTAG;
        } else {
            aeadTag(&s->a, computed);
            if (tagDiff(computed, s->a.tag) != 0) {
                err = ERR_AUTH;
            }
            cipher_chacha_wipe(computed, sizeof computed);
        }
        if (err) {
            cipher_chacha_wipe(p, in.len);
            failStream(L, s, &o, err);
        }
    } else {
        aeadTag(&s->a, s->a.tag);
        s->a.hasTag = 1;
    }
    outCommit(&o, in.len);
    closeStream(s);
    outPush(&o, 0);
    if (!decrypt) {
        lua_pushlstring(L, (const char*)s->a.tag, TAG_LEN);
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

/* encryptor:tag() -> the tag (after finish()) */
static int Encryptor_tag(lua_State* L)
{
    AeadStream* s = (AeadStream*)luaL_checkudata(L, 1, CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME);
    if (!s->closed || !s->a.hasTag) {
        return luaL_error(L, "the tag is only available after finish()");
    }
    lua_pushlstring(L, (const char*)s->a.tag, TAG_LEN);
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

static int AeadStream_release(lua_State* L)
{
    AeadStream* s = (AeadStream*)lua_touserdata(L, 1);
    if (s) {
        cipher_chacha_wipe(s, sizeof(AeadStream));
        s->closed = 1;
    }
    return 0;
}

static int Encryptor_toString(lua_State* L)
{
    AeadStream* s = (AeadStream*)luaL_checkudata(L, 1, CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

static int Decryptor_toString(lua_State* L)
{
    AeadStream* s = (AeadStream*)luaL_checkudata(L, 1, CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME, (void*)s);
    return 1;
}

/* ============================================================================================ */
/* Poly1305                                                                                     */
/* ============================================================================================ */

/* chacha20.poly1305(data, key [, opts] [, out]) -> tag (16 bytes), or out */
static int Chacha20_poly1305(lua_State* L)
{
    Input    in, key;
    Options  opt;
    Output   o;
    Poly1305 pl;
    int      optsArg, outArg;
    size_t   space;
    uint8_t* p;

    checkInput(L, 1, &in);
    checkKey(L, 2, &key);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, optsArg ? optsArg : 3, "poly1305", K_POLY1305, OPTS_POLY1305, &opt);
    outInit(L, &o, outArg, outArg, 1);
    p = outPrep(&o, TAG_LEN, &space);
    cipher_poly1305_init(&pl, key.ptr);
    cipher_poly1305_update(&pl, in.ptr, in.len);
    cipher_poly1305_finish(&pl, p);
    outCommit(&o, TAG_LEN);
    outPush(&o, 0);
    return 1;
}

/* chacha20.version() -> the version of the module (there is no external library) */
static int Chacha20_version(lua_State* L)
{
    lua_getfield(L, lua_upvalueindex(1), "_VERSION");
    return 1;
}

/* ============================================================================================ */

static const luaL_Reg ModuleFunctions[] =
{
    { "crypt",        Chacha20_crypt     },
    { "new",          Chacha20_new       },
    { "encrypt",      Chacha20_encrypt   },
    { "decrypt",      Chacha20_decrypt   },
    { "encryptor",    Chacha20_encryptor },
    { "decryptor",    Chacha20_decryptor },
    { "poly1305",     Chacha20_poly1305  },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg StreamMethods[] =
{
    { "crypt",        Stream_crypt     },
    { NULL,           NULL } /* sentinel */
};

static const luaL_Reg StreamMetaMethods[] =
{
    { "__tostring",   Stream_toString  },
    { "__gc",         Stream_release   },
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
    { "__gc",         AeadStream_release },
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
    { "__gc",         AeadStream_release },
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

int cipher_chacha20_init_module(lua_State* L, int module)
{
    int capiCache = pushCapiCache(L);                      /* -> cc */

    if (luaL_newmetatable(L, CIPHER_CHACHA20_STREAM_CLASS_NAME)) {     /* -> cc, meta */
        setupMeta(L, CIPHER_CHACHA20_STREAM_CLASS_NAME, capiCache,
                  StreamMethods, StreamMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME)) {  /* -> cc, meta */
        setupMeta(L, CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME, capiCache,
                  EncryptorMethods, EncryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    if (luaL_newmetatable(L, CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME)) {  /* -> cc, meta */
        setupMeta(L, CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME, capiCache,
                  DecryptorMethods, DecryptorMetaMethods);
    }
    lua_pop(L, 1);                                         /* -> cc */

    lua_pushvalue(L, module);                              /* -> cc, module */
        lua_pushvalue(L, capiCache);                       /* -> cc, module, cc */
        luaL_setfuncs(L, ModuleFunctions, 1);              /* -> cc, module */
        lua_pushvalue(L, module);                          /* -> cc, module, module */
        lua_pushcclosure(L, Chacha20_version, 1);          /* -> cc, module, version */
        lua_setfield(L, -2, "version");                    /* -> cc, module */
    lua_pop(L, 2);                                         /* -> */

    return 0;
}

/* ============================================================================================ */
