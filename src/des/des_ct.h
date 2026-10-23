#ifndef CIPHER_DES_CT_H
#define CIPHER_DES_CT_H

#include <stddef.h>
#include <stdint.h>

/*
 * DES (FIPS 46-3) and Triple DES (TDEA, EDE, NIST SP 800-67) without table lookups that
 * depend on the key or the data: the S-boxes are evaluated with shifts of constants, the
 * permutations with fixed shifts and masks, see des_ct.c.
 */

#define DES_BLOCK 8

typedef struct DesKey
{
    unsigned n;                /* 1: DES, 3: Triple DES (K1, K2, K3; K3 = K1 for 16 byte keys) */
    unsigned keylen;           /* 8, 16, 24 (0: not set) */
    uint8_t  sk[3][16][8];     /* the subkeys: 16 rounds of eight 6 bit values (one per S-box) */
} DesKey;

/* sets the key (8, 16 or 24 bytes; the parity bits are ignored), returns 0, or -1 for an
 * invalid length */
int  cipher_des_setkey(DesKey* k, const uint8_t* key, size_t len);

/* encrypts / decrypts n blocks of 8 bytes (ECB), in and out may be the same */
void cipher_des_encrypt(const DesKey* k, const uint8_t* in, uint8_t* out, size_t n);
void cipher_des_decrypt(const DesKey* k, const uint8_t* in, uint8_t* out, size_t n);

/* overwrites memory with zeros in a way that the compiler does not remove */
void cipher_des_wipe(void* p, size_t n);

#endif /* CIPHER_DES_CT_H */
