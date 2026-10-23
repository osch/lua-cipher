#include "../common/util.h"
#include "main.h"
#include "aesmod.h"

#ifndef CIPHER_AES_VERSION
    #error CIPHER_AES_VERSION is not defined
#endif 

#define CIPHER_AES_STRINGIFY(x) #x
#define CIPHER_AES_TOSTRING(x) CIPHER_AES_STRINGIFY(x)
#define CIPHER_AES_VERSION_STRING CIPHER_AES_TOSTRING(CIPHER_AES_VERSION)

/* ============================================================================================ */

static const char* const CIPHER_AES_MODULE_NAME = "cipher.aes";

/* ============================================================================================ */


DLL_PUBLIC int luaopen_cipher_aes(lua_State* L)
{
    luaL_checkversion(L); /* does nothing if compiled for Lua 5.1 */

    /* ---------------------------------------- */

    int n = lua_gettop(L);
    
    int module      = ++n; lua_newtable(L);

    lua_pushliteral(L, CIPHER_AES_VERSION_STRING);
    lua_setfield(L, module, "_VERSION");
    
    luaL_checkstack(L, LUA_MINSTACK, NULL);
    
    cipher_aes_init_module(L, module);

    lua_newtable(L);                                   /* -> module meta */
    lua_pushstring(L, CIPHER_AES_MODULE_NAME);         /* -> module meta, "cipher.aes" */
    lua_setfield(L, -2, "__metatable");                /* -> module meta */
    lua_setmetatable(L, module);                       /* -> */
    
    lua_settop(L, module);

    return 1;
}

/* ============================================================================================ */
