#ifndef CIPHER_GHASH_H
#define CIPHER_GHASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * GHASH of GCM (NIST SP 800-38D): y = (y ^ block) * h in GF(2^128) for each 16 byte block
 * of data; a last partial block is padded with zeros. Constant time: carry-less
 * multiplication with integer multiplications ("holes" between the data bits), no table
 * lookups.
 *
 * Adapted from the "ghash_ctmul64" implementation of BearSSL (MIT licence, see LICENSE).
 */
void cipher_ghash(uint8_t y[16], const uint8_t h[16], const uint8_t* data, size_t len);

#endif /* CIPHER_GHASH_H */
