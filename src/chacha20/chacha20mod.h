#ifndef CIPHER_CHACHA20MOD_H
#define CIPHER_CHACHA20MOD_H

#include "../common/util.h"

/* ============================================================================================ */

extern const char* const CIPHER_CHACHA20_STREAM_CLASS_NAME;
extern const char* const CIPHER_CHACHA20_ENCRYPTOR_CLASS_NAME;
extern const char* const CIPHER_CHACHA20_DECRYPTOR_CLASS_NAME;

/* ============================================================================================ */

int cipher_chacha20_init_module(lua_State* L, int module);

/* ============================================================================================ */

#endif /* CIPHER_CHACHA20MOD_H */
