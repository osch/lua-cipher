#include "../common/data.h"
#include "rc4mod.h"

/*
 * RC4 (ARCFOUR) stream cipher: the key-scheduling algorithm and the pseudo-random
 * generation algorithm as published in 1994, see RFC 6229. Encryption and decryption are
 * the same operation: the data xor the keystream. Optionally the first bytes of the
 * keystream are discarded ("RC4-drop[n]").
 */

/* ============================================================================================ */

const char* const CIPHER_RC4_STREAM_CLASS_NAME = "cipher.rc4.stream";

/* ============================================================================================ */

typedef struct Rc4
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} Rc4;

static void rc4Wipe(Rc4* r)
{
    volatile uint8_t* v = (volatile uint8_t*)r;
    size_t            n = sizeof(Rc4);
    while (n--) {
        *v++ = 0;
    }
}

static void rc4Init(Rc4* r, const uint8_t* key, size_t len)
{
    unsigned i;
    uint8_t  j = 0;
    for (i = 0; i < 256; ++i) {
        r->s[i] = (uint8_t)i;
    }
    for (i = 0; i < 256; ++i) {
        uint8_t t = r->s[i];
        j = (uint8_t)(j + t + key[i % len]);
        r->s[i] = r->s[j];
        r->s[j] = t;
    }
    r->i = 0;
    r->j = 0;
}

/* out = in xor keystream; in == NULL: the keystream is discarded */
static void rc4Run(Rc4* r, const uint8_t* in, uint8_t* out, size_t len)
{
    uint8_t* s = r->s;
    uint8_t  i = r->i;
    uint8_t  j = r->j;
    while (len--) {
        uint8_t t;
        i = (uint8_t)(i + 1);
        t = s[i];
        j = (uint8_t)(j + t);
        s[i] = s[j];
        s[j] = t;
        if (in) {
            *out++ = *in++ ^ s[(uint8_t)(t + s[i])];
        }
    }
    r->i = i;
    r->j = j;
}

/* ============================================================================================ */

#define OPT_DROP   0x0001
#define OPT_OUT    0x0002   /* never allowed */

typedef struct Options
{
    lua_Integer drop;
} Options;

static void checkOptions(lua_State* L, int arg, Options* o)
{
    int t = arg ? lua_type(L, arg) : LUA_TNONE;

    o->drop = 0;
    if (t == LUA_TNONE || t == LUA_TNIL) {
        return;
    }
    if (t != LUA_TTABLE) {
        luaL_argerror(L, arg, lua_pushfstring(L, "table expected, got %s", luaL_typename(L, arg)));
    }
    lua_pushnil(L);                                                     /* -> key */
    while (lua_next(L, arg)) {                                          /* -> key, value */
        const char* name = (lua_type(L, -2) == LUA_TSTRING) ? lua_tostring(L, -2) : NULL;
        if (!name) {
            luaL_argerror(L, arg, "option names must be strings");
        }
        if (strcmp(name, "drop") == 0) {
            lua_Integer v = 0;
            if (!topInteger(L, &v) || v < 0) {
                luaL_argerror(L, arg, "invalid drop value");
            }
            o->drop = v;
        } else if (strcmp(name, "out") == 0) {
            luaL_argerror(L, arg, "option 'out' is not supported: pass the carray as the last argument");
        } else {
            luaL_argerror(L, arg, lua_pushfstring(L, "unknown option '%s'", name));
        }
        lua_pop(L, 1);                                                  /* -> key */
    }                                                                   /* -> */
}

/* the key at arg: 1 to 256 bytes, string or carray */
static void checkKey(lua_State* L, int arg, Input* key)
{
    if (lua_type(L, arg) == LUA_TNUMBER || !toInput(L, arg, arg, "", key)) {
        luaL_argerror(L, arg, lua_pushfstring(L, "string or carray expected, got %s",
                                                 luaL_typename(L, arg)));
    }
    if (key->len < 1 || key->len > 256) {
        luaL_argerror(L, arg, lua_pushfstring(L, "invalid key length (%d)", (int)key->len));
    }
}

static void rc4Setup(Rc4* r, const Input* key, const Options* o)
{
    rc4Init(r, key->ptr, key->len);
    if (o->drop > 0) {
        rc4Run(r, NULL, NULL, toSize(o->drop));
    }
}

/* ============================================================================================ */

/* rc4.crypt(data, key [, opts] [, out]) -> string, or out */
static int Rc4_crypt(lua_State* L)
{
    Input    in, key;
    Options  opt;
    Output   o;
    Rc4      r;
    int      optsArg, outArg;
    size_t   space;
    uint8_t* p;

    checkInput(L, 1, &in);
    checkKey(L, 2, &key);
    outArg = checkOptsOut(L, 3, &optsArg);
    checkOptions(L, optsArg, &opt);
    outInit(L, &o, outArg, outArg, 1);
    p = outPrep(&o, in.len, &space);
    rc4Setup(&r, &key, &opt);
    rc4Run(&r, in.ptr, p, in.len);
    rc4Wipe(&r);
    outCommit(&o, in.len);
    outPush(&o, 0);
    return 1;
}

/* rc4.new(key [, opts]) -> stream object */
static int Rc4_new(lua_State* L)
{
    Input   key;
    Options opt;
    Rc4*    r;

    checkKey(L, 1, &key);
    checkOptions(L, lua_isnoneornil(L, 2) ? 0 : 2, &opt);
    r = (Rc4*)lua_newuserdata(L, sizeof(Rc4));                          /* -> stream */
    rc4Setup(r, &key, &opt);
    luaL_setmetatable(L, CIPHER_RC4_STREAM_CLASS_NAME);
    return 1;
}

/* rc4.version() -> the version of the module (there is no external library) */
static int Rc4_version(lua_State* L)
{
    lua_getfield(L, lua_upvalueindex(1), "_VERSION");
    return 1;
}

/* ============================================================================================ */

/* stream:crypt(chunk [, out]) -> string, or out */
static int Stream_crypt(lua_State* L)
{
    Rc4*     r = (Rc4*)luaL_checkudata(L, 1, CIPHER_RC4_STREAM_CLASS_NAME);
    Input    in;
    Output   o;
    size_t   space;
    uint8_t* p;

    checkInput(L, 2, &in);
    lua_settop(L, 3);
    outInit(L, &o, optOut(L, 3), 3, 2);
    p = outPrep(&o, in.len, &space);
    rc4Run(r, in.ptr, p, in.len);
    outCommit(&o, in.len);
    outPush(&o, 0);
    return 1;
}

static int Stream_release(lua_State* L)
{
    Rc4* r = (Rc4*)lua_touserdata(L, 1);
    if (r) {
        rc4Wipe(r);
    }
    return 0;
}

static int Stream_toString(lua_State* L)
{
    Rc4* r = (Rc4*)luaL_checkudata(L, 1, CIPHER_RC4_STREAM_CLASS_NAME);
    lua_pushfstring(L, "%s: %p", CIPHER_RC4_STREAM_CLASS_NAME, (void*)r);
    return 1;
}

/* ============================================================================================ */

static const luaL_Reg ModuleFunctions[] =
{
    { "crypt",        Rc4_crypt        },
    { "new",          Rc4_new          },
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

/* ============================================================================================ */

int cipher_rc4_init_module(lua_State* L, int module)
{
    int capiCache = pushCapiCache(L);                      /* -> cc */

    if (luaL_newmetatable(L, CIPHER_RC4_STREAM_CLASS_NAME)) {     /* -> cc, meta */
        lua_pushstring(L, CIPHER_RC4_STREAM_CLASS_NAME);   /* -> cc, meta, className */
        lua_setfield(L, -2, "__metatable");                /* -> cc, meta */
        luaL_setfuncs(L, StreamMetaMethods, 0);            /* -> cc, meta */
        lua_newtable(L);                                   /* -> cc, meta, Class */
        lua_pushvalue(L, capiCache);                       /* -> cc, meta, Class, cc */
        luaL_setfuncs(L, StreamMethods, 1);                /* -> cc, meta, Class */
        lua_setfield(L, -2, "__index");                    /* -> cc, meta */
    }
    lua_pop(L, 1);                                         /* -> cc */

    lua_pushvalue(L, module);                              /* -> cc, module */
        lua_pushvalue(L, capiCache);                       /* -> cc, module, cc */
        luaL_setfuncs(L, ModuleFunctions, 1);              /* -> cc, module */
        lua_pushvalue(L, module);                          /* -> cc, module, module */
        lua_pushcclosure(L, Rc4_version, 1);               /* -> cc, module, version */
        lua_setfield(L, -2, "version");                    /* -> cc, module */
    lua_pop(L, 2);                                         /* -> */

    return 0;
}

/* ============================================================================================ */
