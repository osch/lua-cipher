#include "../common/util.h"
#include "main.h"
#include "rc4mod.h"

#ifndef CIPHER_RC4_VERSION
    #error CIPHER_RC4_VERSION is not defined
#endif 

#define CIPHER_RC4_STRINGIFY(x) #x
#define CIPHER_RC4_TOSTRING(x) CIPHER_RC4_STRINGIFY(x)
#define CIPHER_RC4_VERSION_STRING CIPHER_RC4_TOSTRING(CIPHER_RC4_VERSION)

/* ============================================================================================ */

static const char* const CIPHER_RC4_MODULE_NAME = "cipher.rc4";

/* ============================================================================================ */


DLL_PUBLIC int luaopen_cipher_rc4(lua_State* L)
{
    luaL_checkversion(L); /* does nothing if compiled for Lua 5.1 */

    /* ---------------------------------------- */

    int n = lua_gettop(L);
    
    int module      = ++n; lua_newtable(L);

    lua_pushliteral(L, CIPHER_RC4_VERSION_STRING);
    lua_setfield(L, module, "_VERSION");
    
    luaL_checkstack(L, LUA_MINSTACK, NULL);
    
    cipher_rc4_init_module(L, module);

    lua_newtable(L);                                   /* -> module meta */
    lua_pushstring(L, CIPHER_RC4_MODULE_NAME);         /* -> module meta, "cipher.rc4" */
    lua_setfield(L, -2, "__metatable");                /* -> module meta */
    lua_setmetatable(L, module);                       /* -> */
    
    lua_settop(L, module);

    return 1;
}

/* ============================================================================================ */
