# cipher.chacha20 Documentation
<!-- ---------------------------------------------------------------------------------------- -->
##   Contents
<!-- ---------------------------------------------------------------------------------------- -->

   * [Overview](#overview)
   * [Data and Keys](#data-and-keys)
   * [Nonces and Counters](#nonces-and-counters)
   * [Module Functions](#module-functions)
        * [chacha20.crypt()](#chacha20_crypt)
        * [chacha20.new()](#chacha20_new)
        * [chacha20.encrypt()](#chacha20_encrypt)
        * [chacha20.decrypt()](#chacha20_decrypt)
        * [chacha20.encryptor()](#chacha20_encryptor)
        * [chacha20.decryptor()](#chacha20_decryptor)
        * [chacha20.poly1305()](#chacha20_poly1305)
        * [chacha20.version()](#chacha20_version)
        * [chacha20._VERSION](#chacha20__VERSION)
   * [Options](#options)
   * [Stream Methods](#stream-methods)
        * [stream:crypt()](#stream_crypt)
   * [Encryptor Methods](#encryptor-methods)
        * [encryptor:update()](#encryptor_update)
        * [encryptor:finish()](#encryptor_finish)
        * [encryptor:tag()](#encryptor_tag)
   * [Decryptor Methods](#decryptor-methods)
        * [decryptor:update()](#decryptor_update)
        * [decryptor:finish()](#decryptor_finish)
   * [ChaCha20-Poly1305](#chacha20-poly1305)
   * [Implementation and Side Channels](#implementation-and-side-channels)
   * [Performance](#performance)
   * [Compatibility](#compatibility)
   * [Errors](#errors)
   * [Thread safety / multiple Lua states](#thread-safety--multiple-lua-states)
   * [Building](#building)

<!-- ---------------------------------------------------------------------------------------- -->
##   Overview
<!-- ---------------------------------------------------------------------------------------- -->

The [Lua] module *cipher.chacha20* of [lua-cipher](../README.md) provides the stream 
cipher ChaCha20 and the authenticated encryption ChaCha20-Poly1305 of [RFC 8439], their
variants with 192 bit nonces XChaCha20 and XChaCha20-Poly1305 ([draft-irtf-cfrg-xchacha])
and the original ChaCha20 with 64 bit nonces, in self-contained C code without an 
external library:

  * [chacha20.encrypt()](#chacha20_encrypt) and [chacha20.decrypt()](#chacha20_decrypt) 
    are ChaCha20-Poly1305: they encrypt and authenticate the data and additional data 
    *aad* with a 16 byte tag, and check the tag before anything is decrypted. 
    [chacha20.encryptor()](#chacha20_encryptor) and 
    [chacha20.decryptor()](#chacha20_decryptor) do the same as streams.
  * [chacha20.crypt()](#chacha20_crypt) and [chacha20.new()](#chacha20_new) are the plain
    stream cipher ChaCha20, without authentication: the data xor the keystream, so 
    encryption and decryption are the same operation.
  * [chacha20.poly1305()](#chacha20_poly1305) is the one-time authenticator Poly1305 
    alone.
  * The implementation uses only additions, rotations and xors of 32 bit words and 
    integer multiplications: no table lookups and no branches that depend on the key or
    the data, see [Implementation and Side Channels](#implementation-and-side-channels).

ChaCha20 is a stream cipher, cipher.chacha20 has the functions of the stream cipher 
modules (*crypt*, *new*) and, for ChaCha20-Poly1305, those of authenticated encryption 
of the block cipher modules (*encrypt*, *decrypt*, *encryptor*, *decryptor*), see 
[Common Conventions](README.md#common-conventions). There is no *mode* option and there 
are no key objects: *encrypt* and *decrypt* are always ChaCha20-Poly1305, *crypt* is 
always ChaCha20, and the key of ChaCha20 needs no key schedule.

Data may be Lua strings or [carray] objects, see [Data and Keys](#data-and-keys). Errors
are raised with *error()*, see [Errors](#errors).

The module name to require is *"cipher.chacha20"*; it is also available as 
*require("cipher").chacha20* through the [meta module](README.md#the-meta-module-cipher):

```lua
local chacha20 = require("cipher.chacha20")

local key   = ("k"):rep(32)
local nonce = ("n"):rep(12)                  -- new for each message in real use
local ct, tag = chacha20.encrypt("secret", key, { iv = nonce, aad = "header" })
assert(chacha20.decrypt(ct, key, { iv = nonce, aad = "header", tag = tag }) == "secret")

local s = chacha20.crypt("secret", key, { iv = nonce })   -- ChaCha20 alone
assert(chacha20.crypt(s, key, { iv = nonce }) == "secret")
```

This module works with Lua 5.1 up to 5.5 and LuaJIT. The [carray] module is optional: 
cipher.chacha20 neither links against it nor requires it, carray objects are recognized
through the [Carray C API]. The rock *cipher.chacha20* depends on nothing but Lua and can
be installed without the other rocks of lua-cipher.

The metatable names (*getmetatable()*) are *"cipher.chacha20"*, 
*"cipher.chacha20.stream"*, *"cipher.chacha20.encryptor"* and 
*"cipher.chacha20.decryptor"*; the latter three also appear in *tostring()* of the 
objects.

[Lua]:                    https://www.lua.org
[RFC 8439]:               https://www.rfc-editor.org/rfc/rfc8439
[draft-irtf-cfrg-xchacha]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
[carray]:                 https://github.com/osch/lua-carray
[Carray C API]:           https://github.com/lua-capis/lua-carray-capi

<!-- ---------------------------------------------------------------------------------------- -->
##   Data and Keys
<!-- ---------------------------------------------------------------------------------------- -->

The data (argument *data*, and *chunk* of the stream methods) and the binary options 
*iv*, *aad* and *tag* may be

  * a Lua string (for the data also a number, converted as in the string library), or
  * a carray object with elements of 1 byte size (element types *"char"*, *"uchar"*, 
    *"schar"*, *"int8"*, *"uint8"*), read directly from its buffer, without copying; 
    read-only carrays are accepted.

The **key** is a string or carray of 32 bytes (*invalid key length (N)* otherwise), for 
all functions, also for [chacha20.poly1305()](#chacha20_poly1305).

The result is a Lua string. Every function and method can instead append its output to 
a carray given as its last argument *out* (see 
[Output](README.md#output-string-or-carray) in the Common Conventions): 
*chacha20.encrypt(data, key, opts, out)*, *stream:crypt(chunk, out)*, 
*decryptor:finish(chunk, tag, out)*; *chacha20.poly1305(data, key, out)* appends the 
tag. *out* must not be the input carray, and if a call raises an error, the carray is set
back to its previous length.

<!-- ---------------------------------------------------------------------------------------- -->
##   Nonces and Counters
<!-- ---------------------------------------------------------------------------------------- -->

The nonce is the option [*iv*](#option_iv); its length selects the variant:

| *iv*      | Variant                                  | Block counter | Data per nonce        | Functions        |
|-----------|------------------------------------------|---------------|-----------------------|------------------|
| 12 bytes  | ChaCha20 of RFC 8439                     | 32 bit        | 2^32 blocks, 256 GB   | all              |
| 24 bytes  | XChaCha20 (draft-irtf-cfrg-xchacha)      | 32 bit        | 2^32 blocks, 256 GB   | all              |
| 8 bytes   | the original ChaCha20 of D. J. Bernstein | 64 bit        | 2^64 blocks           | *crypt*, *new*   |

  * **12 bytes** is the nonce of RFC 8439 (TLS 1.3, WireGuard, JOSE, ...). It must never
    be used twice with the same key; random 12 byte nonces are safe only for a limited 
    number of messages per key (collisions), counters are the usual choice.
  * **24 bytes** (XChaCha20): the first 16 bytes of the nonce and the key give a subkey 
    (HChaCha20), with which ChaCha20 of RFC 8439 runs with the nonce of four zero bytes 
    and the last 8 bytes. 24 byte nonces may be chosen at random for any number of 
    messages.
  * **8 bytes**: the ChaCha20 of D. J. Bernstein's original definition (libsodium's 
    *crypto_stream_chacha20*): a 64 bit nonce and a 64 bit block counter. Only for the 
    plain stream cipher.

The block counter counts the blocks of 64 bytes of the keystream. The option 
[*counter*](#option_counter) of [crypt()](#chacha20_crypt) and [new()](#chacha20_new) 
sets its initial value (default 0); RFC 8439 encrypts from 1 in its AEAD construction 
and in its examples, the block 0 gives the key of Poly1305. With 12 and 24 byte nonces 
the counter has 32 bits: its initial value is at most 2^32 - 1, and the keystream may not
run over the end of the counter: more data raises *data exceeds the limit of the 
counter* (before anything is done; a stream object stays usable for the bytes that are 
left). The encryption and decryption functions of ChaCha20-Poly1305 start at the counter
1 (there is no *counter* option there), so the data per nonce is at most 
(2^32 - 1) * 64 bytes.

XChaCha20 follows draft-irtf-cfrg-xchacha with the 32 bit counter of RFC 8439; libsodium's
*crypto_stream_xchacha20* has a 64 bit counter, which gives the same keystream for the 
first 2^32 blocks (256 GB).

<!-- ---------------------------------------------------------------------------------------- -->
##   Module Functions
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_crypt">**`chacha20.crypt(data, key[, opts][, out])
  `**</span>
  
  Returns *data* xor the ChaCha20 keystream of *key*, *iv* and *counter*: the encryption
  of plaintext, and the decryption of ciphertext. The result is a string of the length of
  *data* (*""* for empty data), or appended to the carray *out*, which is returned.
  **There is no authentication**: use [chacha20.encrypt()](#chacha20_encrypt) unless a 
  format prescribes ChaCha20 alone.
  
  * *data* - string or carray, see [Data and Keys](#data-and-keys).
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required: 8, 12 or 24 bytes) and 
    *counter*.
  * *out* - optional carray.

  ```lua
  local ct = chacha20.crypt(data, key, { iv = nonce12 })               -- counter 0
  local ct1 = chacha20.crypt(data, key, { iv = nonce12, counter = 1 })
  local x = chacha20.crypt(data, key, { iv = nonce24 })                -- XChaCha20
  ```

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_new">**`chacha20.new(key[, opts])
  `**</span>
  
  Creates a stream object with the state of ChaCha20 for *key*, *iv* and *counter*, see 
  [Stream Methods](#stream-methods). The state (about 150 bytes, with the key) is part of
  the userdata and is overwritten with zeros when the object is collected.
  
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required) and *counter*.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_encrypt">**`chacha20.encrypt(data, key[, opts][, out])
  `**</span>
  
  Encrypts and authenticates *data* with ChaCha20-Poly1305 (RFC 8439, section 2.8; with a
  24 byte nonce XChaCha20-Poly1305) and returns the ciphertext (of the length of *data*)
  as string, or appended to the carray *out*, which is returned, and the 16 byte tag as 
  second result.
  
  * *data* - string or carray. May be empty (then the tag authenticates *aad* only).
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required: 12 or 24 bytes) and 
    *aad*.
  * *out* - optional carray.

  ```lua
  local ct, tag = chacha20.encrypt(data, key, { iv = nonce, aad = header })
  ```

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_decrypt">**`chacha20.decrypt(data, key[, opts][, out])
  `**</span>
  
  Checks the tag of the ciphertext *data* and the additional data *aad*, and returns the
  plaintext as string, or appended to the carray *out*, which is returned.
  
  * *data* - the ciphertext, string or carray.
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required), *aad* and *tag* 
    (required, 16 bytes).
  * *out* - optional carray.

  The tag is checked before anything is decrypted: if it does not match, *authentication
  failed* is raised and nothing is output (nothing is appended to *out*).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_encryptor">**`chacha20.encryptor(key[, opts])
  `**</span>
  
  Creates a ChaCha20-Poly1305 encryptor stream object, see 
  [Encryptor Methods](#encryptor-methods).
  
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required) and *aad*. The AAD is 
    processed here.

  The state (about 300 bytes) is part of the userdata; it is overwritten with zeros by 
  *finish()* (except the tag) and when the object is collected.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_decryptor">**`chacha20.decryptor(key[, opts])
  `**</span>
  
  Creates a ChaCha20-Poly1305 decryptor stream object, see 
  [Decryptor Methods](#decryptor-methods).
  
  * *key* - string or carray of 32 bytes.
  * *opts* - table with the [options](#options) *iv* (required), *aad* and *tag* (may 
    instead be given to [decryptor:finish()](#decryptor_finish)).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_poly1305">**`chacha20.poly1305(data, key[, opts][, out])
  `**</span>
  
  Returns the 16 byte Poly1305 tag (RFC 8439, section 2.5) of *data* with the 32 byte 
  one-time key *key* (*r* and *s*; *r* is clamped as the RFC says), as string or appended
  to the carray *out*. There are no options (an options table is accepted for the 
  conventions, it must be empty or *nil*); *chacha20.poly1305(data, key, out)* is 
  *chacha20.poly1305(data, key, nil, out)*.

  **Poly1305 is a one-time authenticator**: a key must never authenticate two different
  messages, otherwise forgeries are possible. Protocols derive a new key for each message,
  e.g. from the block 0 of ChaCha20 as in ChaCha20-Poly1305: 
  *chacha20.crypt(("\0"):rep(32), key, { iv = nonce })*. To compare a tag with an expected
  one, compare in constant time (or use [chacha20.decrypt()](#chacha20_decrypt), which 
  does).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="chacha20_version">**`chacha20.version()
  `**</span>
  
  Returns the version of the module, the same as [chacha20._VERSION](#chacha20__VERSION):
  there is no external library.

* <span id="chacha20__VERSION">**`chacha20._VERSION
  `**</span>
  
  The version of the module cipher.chacha20 as string, e.g. *"0.0.1"*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Options
<!-- ---------------------------------------------------------------------------------------- -->

Options are given as a table (see [Options](README.md#conv-options) of the Common 
Conventions). Unknown names (also *mode*, *taglen* and *padding*, which cipher.chacha20 
does not have) raise *unknown option 'name'*, options that the function does not take 
raise e.g. *option 'counter' is not supported by encrypt()*.

* <span id="option_iv">**`iv`**</span> - string or carray: the nonce, required for all 
  functions except *poly1305* (*option 'iv' is required*). *crypt* and *new*: 8, 12 or 24
  bytes; *encrypt*, *decrypt*, *encryptor*, *decryptor*: 12 or 24 bytes; else *invalid iv
  length (N)*. See [Nonces and Counters](#nonces-and-counters).

* <span id="option_counter">**`counter`**</span> - *crypt* and *new*: the initial block 
  counter, an integer >= 0 (default 0); at most 2^32 - 1 for 12 and 24 byte nonces (else
  *invalid counter value*). On Lua 5.1 and LuaJIT values above 2^53 cannot be given 
  exactly.

* <span id="option_aad">**`aad`**</span> - *encrypt*, *decrypt*, *encryptor*, *decryptor*:
  string or carray, the additional authenticated data (default empty: the same as no 
  AAD).

* <span id="option_tag">**`tag`**</span> - *decrypt* (required) and *decryptor*: the 
  expected tag, string or carray of 16 bytes (*invalid tag length (N)*). Tags are always 
  16 bytes, there is no option *taglen*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Stream Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="stream_crypt">**`stream:crypt(chunk[, out])
  `**</span>
  
  Returns *chunk* xor the next *#chunk* bytes of the keystream, as string or appended to
  the carray *out*. The calls continue one keystream: the output of all calls 
  concatenated is *chacha20.crypt()* of all chunks concatenated. A stream object has no 
  end and needs no *finish()*. Errors of *out* and *data exceeds the limit of the 
  counter* are raised before the keystream is advanced.

```lua
local st = chacha20.new(key, { iv = nonce })
for chunk in inputFile:lines(65536) do
    outputFile:write(st:crypt(chunk))
end
```

<!-- ---------------------------------------------------------------------------------------- -->
##   Encryptor Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="encryptor_update">**`encryptor:update(chunk[, out])
  `**</span>
  
  Encrypts *chunk* (string or carray) and returns the ciphertext of the same length as 
  string (*nil* for an empty chunk), or appended to the carray *out*, which is returned.

* <span id="encryptor_finish">**`encryptor:finish([chunk][, out])
  `**</span>
  
  Encrypts the optional last *chunk*, ends the stream and returns the rest of the 
  ciphertext as string (also *""*), or appended to *out*, and the 16 byte tag as second 
  result. Afterwards the object is closed: every call except *tag()* raises *encryptor is
  closed*.

* <span id="encryptor_tag">**`encryptor:tag()
  `**</span>
  
  Returns the tag again after *finish()*; before: *the tag is only available after 
  finish()*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Decryptor Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="decryptor_update">**`decryptor:update(chunk[, out])
  `**</span>
  
  Decrypts *chunk* and returns the plaintext of the same length as string (*nil* for an 
  empty chunk), or appended to *out*. **The output is not authenticated yet**, see 
  [ChaCha20-Poly1305](#chacha20-poly1305).

* <span id="decryptor_finish">**`decryptor:finish([chunk][, tag][, out])
  `**</span>
  
  Decrypts the optional last *chunk*, ends the stream, checks the tag and returns the 
  rest of the plaintext as string, or appended to *out*. *tag* (a string of 16 bytes; a 
  carray at this position is *out*) is the expected tag; it replaces the option *tag* of 
  *decryptor()*, one of both is required (*no tag given*). *d:finish(chunk, out)* and 
  *d:finish(chunk, nil, out)* are the same. Raises *authentication failed* if the tag 
  does not match (the output of this call is discarded); the object is closed afterwards 
  in any case.

<!-- ---------------------------------------------------------------------------------------- -->
##   ChaCha20-Poly1305
<!-- ---------------------------------------------------------------------------------------- -->

ChaCha20-Poly1305 (RFC 8439, section 2.8) encrypts with ChaCha20 from the block counter 1
and authenticates the AAD and the ciphertext with Poly1305, whose one-time key is the 
first half of the keystream block 0:

  * **Nonce**: never use the same nonce twice with the same key: this reveals the xor of 
    the plaintexts and the Poly1305 key, which allows forgeries. With 24 byte nonces 
    (XChaCha20-Poly1305) random nonces are safe.
  * **Data limit**: at most (2^32 - 1) * 64 bytes (about 256 GB) per nonce; more raises 
    *data exceeds the limit of the counter*.
  * **One-shot**: *ct, tag = chacha20.encrypt(pt, key, { iv = nonce, aad = a })*; 
    *chacha20.decrypt(ct, key, { iv = nonce, aad = a, tag = tag })* checks the tag first
    and decrypts only if it matches.
  * **Streams**: the AAD is given to *encryptor()* / *decryptor()*. *encryptor:finish()*
    returns the tag as second result (also by *encryptor:tag()*). The decryptor gets the 
    expected tag as option or as argument of *finish()*; **its *update()* returns 
    plaintext before the tag is checked**, as every streaming AEAD decryption must. A 
    caller that must not act on unauthenticated data keeps the output until *finish()* 
    has succeeded, or uses *chacha20.decrypt()*.
  * **Tags** are 16 bytes and are compared in constant time.
  * The ciphertext and the tag are separate results; formats that append the tag to the 
    ciphertext (RFC 8439's AEAD interface, libsodium's *_ietf_encrypt*, Python's 
    *ChaCha20Poly1305.encrypt()*, Go's *Seal*) are *ct .. tag*, and are split with 
    *data:sub(1, -17)*, *data:sub(-16)* for decryption.
  * **8 byte nonces**: pycryptodome and CryptX also accept 8 byte nonces for 
    ChaCha20-Poly1305 and then use the construction of RFC 8439 with the original 
    ChaCha20; this is the same as a 12 byte nonce of four zero bytes and the 8 bytes: 
    *iv = ("\0"):rep(4) .. nonce8*. The older construction of libsodium's 
    *crypto_aead_chacha20poly1305* (without padding of the Poly1305 input) is a different
    one and is not supported.

<!-- ---------------------------------------------------------------------------------------- -->
##   Implementation and Side Channels
<!-- ---------------------------------------------------------------------------------------- -->

cipher.chacha20 is written in portable C after the RFC, without assembly and without 
SIMD instructions.

  * **ChaCha20** and **HChaCha20** use only additions, xors and rotations of 32 bit words:
    there are no table lookups and no branches that depend on the key or the data.
  * **Poly1305** computes modulo 2^130 - 5 in five limbs of 26 bits with 32 x 32 -> 64 bit
    multiplications, following the well known approach of the public domain 
    *poly1305-donna* (32 bit variant); the final reduction selects with masks, without 
    branches.
  * **Tags** are compared without branches on the individual bytes; only the final result
    (equal or not) decides.
  * **Limits of this statement**: constant time in C depends on the compiler and the 
    processor. The 64 bit multiplications of Poly1305 are not constant time on some 
    small processors (where they are library calls). No guarantee is given that the 
    implementation is free of timing side channels on a particular platform; power 
    analysis and fault attacks are out of scope.
  * Stream states, keystream blocks and one-time keys are overwritten with zeros when they
    are no longer needed (also on errors and by the garbage collector); copies that Lua 
    makes of strings (keys given as strings, plaintexts) are beyond the module's control.

<!-- ---------------------------------------------------------------------------------------- -->
##   Performance
<!-- ---------------------------------------------------------------------------------------- -->

Orders of magnitude on a current x86-64 processor (one core, 16 MB of data, 
*tests/chacha20/bench01.lua*):

| Function                                          | Throughput           |
|---------------------------------------------------|----------------------|
| ChaCha20, XChaCha20 (*crypt*)                     | about 400 MB/s       |
| ChaCha20-Poly1305 (*encrypt*, *decrypt*)          | about 350 MB/s       |
| Poly1305                                          | about 1.9 GB/s       |
| a short message (48 bytes, *encrypt*) with a new key | about 1 µs per message |

That is two to three times the throughput of cipher.aes in its parallel modes. 
Implementations with SIMD instructions (OpenSSL, libsodium) are several times faster; 
where throughput matters more than self-containedness, they are the better choice.

<!-- ---------------------------------------------------------------------------------------- -->
##   Compatibility
<!-- ---------------------------------------------------------------------------------------- -->

The results are those of the standards; the test suite compares them with other 
implementations byte for byte ([tests/chacha20/test04.lua](../tests/chacha20/test04.lua)):

| cipher.chacha20                          | OpenSSL                      | Python                                   | Perl (CryptX)                  |
|------------------------------------------|------------------------------|------------------------------------------|--------------------------------|
| *crypt*, 12 byte *iv*, *counter* c       | *enc -chacha20 -K key -iv* c (4 bytes, little endian) .. nonce | *ChaCha20(key, c .. nonce)* (cryptography); *ChaCha20.new(key=, nonce=)* and *seek(64 * c)* (pycryptodome) | *Crypt::Stream::ChaCha->new(key, nonce, c)* |
| *crypt*, 8 byte *iv*                     | *-iv* c (8 bytes, little endian) .. nonce | cryptography as OpenSSL; pycryptodome with the 8 byte nonce | *Crypt::Stream::ChaCha* |
| *crypt*, 24 byte *iv* (XChaCha20)        | -                            | pycryptodome with the 24 byte nonce      | *Crypt::Stream::XChaCha* (CryptX 0.089 and later) |
| *encrypt*, *decrypt*, 12 byte *iv*       | (not in *enc*)               | *ChaCha20Poly1305* (ciphertext .. tag); *ChaCha20_Poly1305* | *Crypt::AuthEnc::ChaCha20Poly1305* |
| *encrypt*, *decrypt*, 24 byte *iv*       | -                            | pycryptodome *ChaCha20_Poly1305* with the 24 byte nonce | *Crypt::AuthEnc::ChaCha20Poly1305* |
| *poly1305*                               | *mac -macopt hexkey:*key *Poly1305* | *Poly1305.generate_tag()* (cryptography) | *Crypt::Mac::Poly1305* |

The constructions are those of libsodium's *crypto_stream_chacha20_ietf*, 
*crypto_stream_chacha20* (8 byte nonces), *crypto_aead_chacha20poly1305_ietf* and 
*crypto_aead_xchacha20poly1305_ietf* (with the tag appended to the ciphertext); 
*openssl enc* has no key derivation here either, the key and the IV are given in hex.

<!-- ---------------------------------------------------------------------------------------- -->
##   Errors
<!-- ---------------------------------------------------------------------------------------- -->

All errors are raised with *error()* as strings:

  * argument errors: *bad argument #2 to 'encrypt' (invalid key length (16))*, *string or
    carray expected, got table*, *option 'iv' is required*, *invalid iv length (16)*, 
    *invalid counter value*, *option 'tag' is required*, *invalid tag length (12)*, 
    *option 'counter' is not supported by encrypt()*, *option 'aad' is not supported by 
    crypt()*, *unknown option 'mode'*, the errors of *out* (see [Output: string or 
    carray](README.md#output-string-or-carray)); they are raised before anything is 
    done, a stream stays usable;
  * errors of the data: *authentication failed*, *no tag given* (a decryptor stream is 
    closed afterwards) and *data exceeds the limit of the counter* (an AEAD stream is 
    closed afterwards, a ChaCha20 stream object of *new()* is unchanged);
  * *encryptor is closed* / *decryptor is closed*: the stream was finished or failed.

<!-- ---------------------------------------------------------------------------------------- -->
##   Thread safety / multiple Lua states
<!-- ---------------------------------------------------------------------------------------- -->

cipher.chacha20 has no global mutable data: the module can be loaded into several Lua 
states of the same process, also used in parallel OS threads (one thread per Lua state).
Stream objects and the cache of the Carray C API belong to their Lua state.

<!-- ---------------------------------------------------------------------------------------- -->
##   Building
<!-- ---------------------------------------------------------------------------------------- -->

With LuaRocks from the repository root:

```
luarocks make rockspecs/cipher.chacha20-scm-0.rockspec
```

No external library is needed, only a C compiler. Without LuaRocks, the Makefile in 
*src* builds *src/build/lua$(LUA_VERSION)/cipher/chacha20.so* (*make chacha20*), and 
*src/activate.sh* sets the Lua paths for using it from the source tree.

The tests are run from the *tests/chacha20* directory:

  * *lua test01.lua* - string data: the test vectors of [RFC 8439] (sections 2.3.2, 
    2.4.2, 2.5.2, 2.6.2, 2.8.2 and Appendix A.1 to A.5: block function, encryption, 
    Poly1305, Poly1305 key generation, AEAD) and of [draft-irtf-cfrg-xchacha] (2.2.1 
    HChaCha20, A.3.1 XChaCha20-Poly1305, A.3.2 XChaCha20), the 64 bit nonce variant and 
    the carry of its counter, the limit of the 32 bit counter, one-shot functions and 
    streams with all chunk sizes (also 1 byte), wrong and missing tags, option and 
    argument errors, 10 MB
  * *lua test02.lua* - carray data, keys, nonces, AAD and tags, carray output of all 
    functions and methods; read-only and non-resizable carrays with the test helper 
    module *cipher_testcarray* (skipped if carray or the helper is not installed)
  * *lua test03.lua* - several Lua states in parallel threads (test helper module 
    *cipher_multistate*, skipped if it is not installed)
  * *lua test04.lua* - comparison with *openssl enc -chacha20* and *openssl mac 
    Poly1305*, Python's *cryptography* and *pycryptodome* (helper *test04.py*) and Perl's
    CryptX (helper *test04.pl*), in both directions, also the rejection of wrong tags; 
    each part is skipped if the tool or module is not installed, *CIPHER_TEST_REQUIRE* 
    (e.g. *openssl,cryptography,pycryptodome,cryptx*) makes a skipped part an error
  * *lua bench01.lua [MB]* - throughput (not a test)
