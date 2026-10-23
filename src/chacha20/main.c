#include "../common/util.h"
#include "main.h"
#include "chacha20mod.h"

#ifndef CIPHER_CHACHA20_VERSION
    #error CIPHER_CHACHA20_VERSION is not defined
#endif 

#define CIPHER_CHACHA20_STRINGIFY(x) #x
#define CIPHER_CHACHA20_TOSTRING(x) CIPHER_CHACHA20_STRINGIFY(x)
#define CIPHER_CHACHA20_VERSION_STRING CIPHER_CHACHA20_TOSTRING(CIPHER_CHACHA20_VERSION)

/* ============================================================================================ */

static const char* const CIPHER_CHACHA20_MODULE_NAME = "cipher.chacha20";

/* ============================================================================================ */


DLL_PUBLIC int luaopen_cipher_chacha20(lua_State* L)
{
    luaL_checkversion(L); /* does nothing if compiled for Lua 5.1 */

    /* ---------------------------------------- */

    int n = lua_gettop(L);
    
    int module      = ++n; lua_newtable(L);

    lua_pushliteral(L, CIPHER_CHACHA20_VERSION_STRING);
    lua_setfield(L, module, "_VERSION");
    
    luaL_checkstack(L, LUA_MINSTACK, NULL);
    
    cipher_chacha20_init_module(L, module);

    lua_newtable(L);                                   /* -> module meta */
    lua_pushstring(L, CIPHER_CHACHA20_MODULE_NAME);         /* -> module meta, "cipher.chacha20" */
    lua_setfield(L, -2, "__metatable");                /* -> module meta */
    lua_setmetatable(L, module);                       /* -> */
    
    lua_settop(L, module);

    return 1;
}

/* ============================================================================================ */
