#ifndef CIPHER_RC4MOD_H
#define CIPHER_RC4MOD_H

#include "../common/util.h"

/* ============================================================================================ */

extern const char* const CIPHER_RC4_STREAM_CLASS_NAME;

/* ============================================================================================ */

int cipher_rc4_init_module(lua_State* L, int module);

/* ============================================================================================ */

#endif /* CIPHER_RC4MOD_H */
