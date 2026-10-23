#include "../common/util.h"
#include "main.h"
#include "desmod.h"

#ifndef CIPHER_DES_VERSION
    #error CIPHER_DES_VERSION is not defined
#endif 

#define CIPHER_DES_STRINGIFY(x) #x
#define CIPHER_DES_TOSTRING(x) CIPHER_DES_STRINGIFY(x)
#define CIPHER_DES_VERSION_STRING CIPHER_DES_TOSTRING(CIPHER_DES_VERSION)

/* ============================================================================================ */

static const char* const CIPHER_DES_MODULE_NAME = "cipher.des";

/* ============================================================================================ */


DLL_PUBLIC int luaopen_cipher_des(lua_State* L)
{
    luaL_checkversion(L); /* does nothing if compiled for Lua 5.1 */

    /* ---------------------------------------- */

    int n = lua_gettop(L);
    
    int module      = ++n; lua_newtable(L);

    lua_pushliteral(L, CIPHER_DES_VERSION_STRING);
    lua_setfield(L, module, "_VERSION");
    
    luaL_checkstack(L, LUA_MINSTACK, NULL);
    
    cipher_des_init_module(L, module);

    lua_newtable(L);                                   /* -> module meta */
    lua_pushstring(L, CIPHER_DES_MODULE_NAME);         /* -> module meta, "cipher.des" */
    lua_setfield(L, -2, "__metatable");                /* -> module meta */
    lua_setmetatable(L, module);                       /* -> */
    
    lua_settop(L, module);

    return 1;
}

/* ============================================================================================ */
