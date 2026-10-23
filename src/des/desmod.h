#ifndef CIPHER_DESMOD_H
#define CIPHER_DESMOD_H

#include "../common/util.h"

/* ============================================================================================ */

extern const char* const CIPHER_DES_KEY_CLASS_NAME;
extern const char* const CIPHER_DES_ENCRYPTOR_CLASS_NAME;
extern const char* const CIPHER_DES_DECRYPTOR_CLASS_NAME;

/* ============================================================================================ */

int cipher_des_init_module(lua_State* L, int module);

/* ============================================================================================ */

#endif /* CIPHER_DESMOD_H */
