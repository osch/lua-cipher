#ifndef CIPHER_AESMOD_H
#define CIPHER_AESMOD_H

#include "../common/util.h"

/* ============================================================================================ */

extern const char* const CIPHER_AES_KEY_CLASS_NAME;
extern const char* const CIPHER_AES_ENCRYPTOR_CLASS_NAME;
extern const char* const CIPHER_AES_DECRYPTOR_CLASS_NAME;

/* ============================================================================================ */

int cipher_aes_init_module(lua_State* L, int module);

/* ============================================================================================ */

#endif /* CIPHER_AESMOD_H */
