#ifndef CIPHER_POLY1305_H
#define CIPHER_POLY1305_H

#include <stddef.h>
#include <stdint.h>

/*
 * The one-time authenticator Poly1305 (RFC 8439, section 2.5): a 32 byte key (r, s), a
 * 16 byte tag. Arithmetic modulo 2^130 - 5 in five 26 bit limbs with 32 x 32 -> 64 bit
 * multiplications, without branches on the key or the data.
 */

#define POLY1305_KEY  32
#define POLY1305_TAG  16

typedef struct Poly1305
{
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buf[16];          /* bytes of an incomplete block */
    size_t   buflen;
} Poly1305;

void cipher_poly1305_init(Poly1305* p, const uint8_t* key);
void cipher_poly1305_update(Poly1305* p, const uint8_t* data, size_t len);

/* zero bytes up to the next multiple of 16 of the data so far (the padding of RFC 8439 2.8) */
void cipher_poly1305_pad16(Poly1305* p);

/* the tag (16 bytes); the state is overwritten with zeros */
void cipher_poly1305_finish(Poly1305* p, uint8_t* tag);

#endif /* CIPHER_POLY1305_H */
