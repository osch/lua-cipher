# cipher.des Documentation
<!-- ---------------------------------------------------------------------------------------- -->
##   Contents
<!-- ---------------------------------------------------------------------------------------- -->

   * [Overview](#overview)
   * [Data and Keys](#data-and-keys)
   * [Modes](#modes)
   * [Module Functions](#module-functions)
        * [des.encrypt()](#des_encrypt)
        * [des.decrypt()](#des_decrypt)
        * [des.encryptor()](#des_encryptor)
        * [des.decryptor()](#des_decryptor)
        * [des.newkey()](#des_newkey)
        * [des.version()](#des_version)
        * [des._VERSION](#des__VERSION)
   * [Options](#options)
   * [Encryptor Methods](#encryptor-methods)
        * [encryptor:update()](#encryptor_update)
        * [encryptor:finish()](#encryptor_finish)
        * [encryptor:tag()](#encryptor_tag)
   * [Decryptor Methods](#decryptor-methods)
        * [decryptor:update()](#decryptor_update)
        * [decryptor:finish()](#decryptor_finish)
   * [Key Object Methods](#key-object-methods)
        * [key:encryptblock()](#key_encryptblock)
        * [key:decryptblock()](#key_decryptblock)
   * [Security](#security)
   * [Implementation and Side Channels](#implementation-and-side-channels)
   * [Performance](#performance)
   * [Compatibility](#compatibility)
   * [Errors](#errors)
   * [Thread safety / multiple Lua states](#thread-safety--multiple-lua-states)
   * [Building](#building)

<!-- ---------------------------------------------------------------------------------------- -->
##   Overview
<!-- ---------------------------------------------------------------------------------------- -->

The [Lua] module *cipher.des* of [lua-cipher](../README.md) provides the block cipher DES
([FIPS 46-3]) and Triple DES (TDEA, EDE, [NIST SP 800-67]) with two or three keys in the 
modes of operation ECB, CBC, CFB, CFB8, OFB and CTR ([NIST SP 800-38A], [FIPS 81]), in 
self-contained C code without an external library, with the API of 
[cipher.aes](aes.md). **DES is broken** (its 56 bit key can be found by exhaustive 
search) and Triple DES is deprecated (NIST SP 800-131A, 64 bit blocks): the module is 
meant for reading and writing legacy formats that use them, e.g. PKCS#12 and PKCS#8 
files with *pbeWithSHAAnd3-KeyTripleDES-CBC* or older S/MIME and OpenPGP messages, not for
protecting new data.

  * [des.encrypt()](#des_encrypt) and [des.decrypt()](#des_decrypt) process the whole 
    data in one call.
  * [des.encryptor()](#des_encryptor) and [des.decryptor()](#des_decryptor) create stream
    objects that take the data in pieces.
  * [des.newkey()](#des_newkey) creates a key object: the key schedule computed once, 
    usable instead of the key in all functions, and with the block functions 
    [encryptblock()](#key_encryptblock) / [decryptblock()](#key_decryptblock).
  * The S-boxes are evaluated without table lookups, see [Implementation and Side 
    Channels](#implementation-and-side-channels).

Data may be Lua strings or [carray] objects, see [Data and Keys](#data-and-keys). Errors
are raised with *error()*, see [Errors](#errors). The module follows the 
[Common Conventions](README.md#common-conventions) of lua-cipher for block cipher modules.

The module name to require is *"cipher.des"*; it is also available as 
*require("cipher").des* through the [meta module](README.md#the-meta-module-cipher):

```lua
local des = require("cipher.des")

local key = ("k"):rep(24)                       -- Triple DES with three keys
local iv  = ("i"):rep(8)                        -- random and new for each message in real use
local ct  = des.encrypt("secret", key, { iv = iv })            -- CBC with PKCS#7 padding
assert(des.decrypt(ct, key, { iv = iv }) == "secret")
```

This module works with Lua 5.1 up to 5.5 and LuaJIT. The [carray] module is optional: 
cipher.des neither links against it nor requires it, carray objects are recognized 
through the [Carray C API]. The rock *cipher.des* depends on nothing but Lua and can be
installed without the other rocks of lua-cipher.

The metatable names (*getmetatable()*) are *"cipher.des"*, *"cipher.des.encryptor"*, 
*"cipher.des.decryptor"* and *"cipher.des.key"*; the latter three also appear in 
*tostring()* of the objects.

[Lua]:             https://www.lua.org
[FIPS 46-3]:       https://csrc.nist.gov/pubs/fips/46-3/final
[FIPS 81]:         https://csrc.nist.gov/pubs/fips/81/final
[NIST SP 800-67]:  https://csrc.nist.gov/pubs/sp/800/67/r2/final
[NIST SP 800-38A]: https://csrc.nist.gov/pubs/sp/800/38/a/final
[NIST SP 800-20]:  https://csrc.nist.gov/pubs/sp/800/20/final
[NIST CAVP]:       https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
[carray]:          https://github.com/osch/lua-carray
[Carray C API]:    https://github.com/lua-capis/lua-carray-capi

<!-- ---------------------------------------------------------------------------------------- -->
##   Data and Keys
<!-- ---------------------------------------------------------------------------------------- -->

The data (argument *data*, and *chunk* of the stream methods) and the option *iv* may be
a Lua string (for the data also a number, converted as in the string library) or a 
carray object with elements of 1 byte size, read directly from its buffer, without 
copying.

The **key** is a string or carray, or a key object of [des.newkey()](#des_newkey); its 
length selects the cipher:

| Key length | Cipher                                   | Keying option (SP 800-67) | Effective strength |
|------------|------------------------------------------|---------------------------|--------------------|
| 8 bytes    | DES                                      | -                         | 56 bit (broken)    |
| 16 bytes   | Triple DES with two keys: K1, K2, K3 = K1 | 2                        | about 80 bit       |
| 24 bytes   | Triple DES with three keys: K1, K2, K3   | 1                         | about 112 bit      |

Other lengths raise *invalid key length (N)*. Triple DES encrypts with 
*E(K3, D(K2, E(K1, block)))* and decrypts with *D(K1, E(K2, D(K3, block)))*.

  * **Parity bits**: the lowest bit of each key byte is a parity bit in DES; it is 
    ignored (as by OpenSSL and the standard): keys that differ only in these bits are the
    same key. Keys with wrong parity are accepted.
  * **Weak keys**: the four weak keys of DES (e.g. *0101010101010101*, 
    *fefefefefefefefe*), whose encryption is its own inverse, and the twelve semi-weak 
    keys are accepted, as by OpenSSL and the other implementations the tests compare 
    with. A 24 byte key with K1 = K2 or K2 = K3, and a 16 byte key with K1 = K2, is 
    single DES (with the other key); these keys are accepted as well (pycryptodome 
    rejects them). Keys from a key derivation function or a random source are weak with 
    negligible probability; an application that must reject them checks the key itself.

The result is a Lua string. Every function and method can instead append its output to 
a carray given as its last argument *out* (see 
[Output](README.md#output-string-or-carray) in the Common Conventions): 
*des.encrypt(data, key, opts, out)*, *e:update(chunk, out)*, *e:finish(nil, out)*, 
*k:encryptblock(data, out)*; *out* must not be the input carray, and if a call raises 
an error, the carray is set back to its previous length.

<!-- ---------------------------------------------------------------------------------------- -->
##   Modes
<!-- ---------------------------------------------------------------------------------------- -->

The option [*mode*](#option_mode) selects the mode of operation; the block size is 8 
bytes:

| mode     | Standard                    | iv       | Padding               | Output length |
|----------|-----------------------------|----------|-----------------------|---------------|
| *"ecb"*  | SP 800-38A, FIPS 81         | none     | pkcs7 (default), none | blocks        |
| *"cbc"*  | SP 800-38A, FIPS 81         | 8 bytes  | pkcs7 (default), none | blocks        |
| *"cfb"*  | SP 800-38A, CFB64           | 8 bytes  | -                     | = input       |
| *"cfb8"* | SP 800-38A, CFB8            | 8 bytes  | -                     | = input       |
| *"ofb"*  | SP 800-38A, OFB             | 8 bytes  | -                     | = input       |
| *"ctr"*  | SP 800-38A                  | 8 bytes: the first counter block | - | = input |

The default mode is *"cbc"*, the mode of *openssl enc -des-ede3-cbc* and of most 
formats that use DES.

  * **ecb** encrypts each block on its own: equal plaintext blocks give equal ciphertext
    blocks.
  * **cbc** xors each plaintext block with the previous ciphertext block (the first with
    the IV) before the encryption.
  * **cfb** feeds back 64 bits (the whole block, as *openssl enc -des-cfb*), **cfb8** 1 
    byte at a time (one block encryption per byte).
  * **ofb** encrypts the IV again and again and xors the data with the result.
  * **ctr** encrypts the counter blocks *iv*, *iv + 1*, ...: the counter is the whole 8 
    byte block as a big endian number and wraps around from *ff...ff* to *00...00*. With 
    64 bit blocks the keystream repeats after 2^64 blocks, but CTR with DES is rare: 
    there is no *des-ctr* in *openssl enc*.

Padding: ECB and CBC use PKCS#7 by default (for 8 byte blocks also called PKCS#5): 1 to 
8 bytes, each with the number of bytes added, so that *#ciphertext = #plaintext - 
#plaintext % 8 + 8*. With *padding = "none"* the data must be a multiple of 8 bytes. The
other modes have no padding; the output has the length of the input.

<!-- ---------------------------------------------------------------------------------------- -->
##   Module Functions
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_encrypt">**`des.encrypt(data, key[, opts][, out])
  `**</span>
  
  Encrypts *data* and returns the ciphertext as string, or appended to the carray *out*,
  which is returned.
  
  * *data* - string or carray, see [Data and Keys](#data-and-keys). May be empty.
  * *key* - string or carray of 8, 16 or 24 bytes, or a key object.
  * *opts* - table with the [options](#options) *mode*, *iv* and *padding*. As the 
    default mode *"cbc"* needs an *iv*, the options are always given in practice.
  * *out* - optional carray.

  ```lua
  local ct = des.encrypt(data, key, { iv = iv })                     -- cbc, pkcs7
  local ct2 = des.encrypt(data, key, { mode = "ecb", padding = "none" })
  ```

  Raises an error for *padding = "none"* if the length of *data* is not a multiple of 
  8 (ECB, CBC).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_decrypt">**`des.decrypt(data, key[, opts][, out])
  `**</span>
  
  Decrypts *data* and returns the plaintext as string, or appended to the carray *out*,
  which is returned.
  
  * *data* - the ciphertext, string or carray.
  * *key* - string or carray of 8, 16 or 24 bytes, or a key object.
  * *opts* - table with the [options](#options) *mode*, *iv* and *padding*.
  * *out* - optional carray.

  Raises *invalid padding* if the PKCS#7 padding is not valid (also for empty data) and 
  *data length (N) is not a multiple of the block size (8)* for ECB and CBC.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_encryptor">**`des.encryptor(key[, opts])
  `**</span>
  
  Creates an encryptor stream object, see [Encryptor Methods](#encryptor-methods).
  
  * *key* - string or carray of 8, 16 or 24 bytes, or a key object (the stream copies its
    key schedule).
  * *opts* - optional table with the [options](#options) *mode*, *iv* and *padding*.

  The state (about 450 bytes, with the key schedule) is part of the userdata; it is 
  overwritten with zeros by *finish()* and when the object is collected.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_decryptor">**`des.decryptor(key[, opts])
  `**</span>
  
  Creates a decryptor stream object, see [Decryptor Methods](#decryptor-methods), with 
  the same arguments as [des.encryptor()](#des_encryptor).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_newkey">**`des.newkey(key)
  `**</span>
  
  Creates a key object: the key schedule of *key* (string or carray of 8, 16 or 24 bytes,
  or another key object, which is copied). A key object can be given instead of the key 
  to all functions; this saves the key schedule in each call, and its methods 
  [encryptblock()](#key_encryptblock) and [decryptblock()](#key_decryptblock) are the raw
  block cipher (DES or Triple DES, by the length of the key). The key schedule takes a 
  few microseconds for a 24 byte key; it is overwritten with zeros when the key object 
  is collected.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="des_version">**`des.version()
  `**</span>
  
  Returns the version of the module, the same as [des._VERSION](#des__VERSION): there is 
  no external library.

* <span id="des__VERSION">**`des._VERSION
  `**</span>
  
  The version of the module cipher.des as string, e.g. *"0.0.1"*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Options
<!-- ---------------------------------------------------------------------------------------- -->

Options are given as a table (see [Options](README.md#conv-options) of the Common 
Conventions). Unknown names (also *aad*, *tag* and *taglen*: DES has no authenticated 
mode) and options that the mode does not take raise errors.

* <span id="option_mode">**`mode`**</span> - *"ecb"*, *"cbc"* (default), *"cfb"*, 
  *"cfb8"*, *"ofb"* or *"ctr"*, see [Modes](#modes). Other values: *invalid mode value*.

* <span id="option_iv">**`iv`**</span> - string or carray of 8 bytes: the IV, for CTR the
  first counter block. Required for all modes except ECB (*option 'iv' is required for 
  mode 'cbc'*), not allowed for ECB; other lengths raise *invalid iv length (N)*.

* <span id="option_padding">**`padding`**</span> - *"pkcs7"* (default for ECB and CBC) or
  *"none"*. *"pkcs7"* is only allowed for ECB and CBC, *"none"* for all modes.

<!-- ---------------------------------------------------------------------------------------- -->
##   Encryptor Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="encryptor_update">**`encryptor:update(chunk[, out])
  `**</span>
  
  Encrypts *chunk* (string or carray). Returns the output so far as string, or *nil* if
  there is none yet: ECB and CBC output whole blocks only and keep an incomplete block 
  for the next call; the other modes output as many bytes as given. With the carray 
  *out* the output is appended to it, and *out* is returned.

* <span id="encryptor_finish">**`encryptor:finish([chunk][, out])
  `**</span>
  
  Encrypts the optional last *chunk*, ends the stream and returns the rest of the output
  as string (also *""*), or appended to *out*. ECB and CBC add the padding here (with 
  *padding = "none"* the whole data must have been a multiple of 8 bytes). Afterwards 
  the object is closed: every call raises *encryptor is closed*.

* <span id="encryptor_tag">**`encryptor:tag()
  `**</span>
  
  DES has no authenticated mode: raises *mode 'cbc' has no tag* (with the name of the 
  mode), as cipher.aes does for its modes without a tag.

<!-- ---------------------------------------------------------------------------------------- -->
##   Decryptor Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="decryptor_update">**`decryptor:update(chunk[, out])
  `**</span>
  
  Decrypts *chunk*. Returns the output so far as string, or *nil* if there is none yet:
  ECB and CBC output whole blocks only, and with padding they hold back the last whole 
  block until *finish()*, since it contains the padding.

* <span id="decryptor_finish">**`decryptor:finish([chunk][, out])
  `**</span>
  
  Decrypts the optional last *chunk*, ends the stream, checks the padding (ECB, CBC) and
  returns the rest of the output as string, or appended to *out*. As in cipher.aes the 
  third argument is the position of the tag of authenticated modes: a string there 
  raises *mode 'cbc' has no tag*, and *d:finish(chunk, out)* and *d:finish(chunk, nil, 
  out)* are the same. Raises *invalid padding* or *data length (N) is not a multiple of 
  the block size (8)*; the object is closed afterwards in any case.

<!-- ---------------------------------------------------------------------------------------- -->
##   Key Object Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="key_encryptblock">**`key:encryptblock(data[, out])
  `**</span>
  
  Encrypts *data*, whose length must be a multiple of 8 (one or more blocks, each 
  encrypted on its own, as ECB without padding; empty data gives *""*), and returns the 
  result as string, or appended to *out*.

* <span id="key_decryptblock">**`key:decryptblock(data[, out])
  `**</span>
  
  Decrypts the blocks of *data* (a multiple of 8 bytes).

```lua
-- Triple DES from three single DES keys, by hand: E(K3, D(K2, E(K1, block)))
local k1, k2, k3 = des.newkey(key1), des.newkey(key2), des.newkey(key3)
assert(k3:encryptblock(k2:decryptblock(k1:encryptblock(block)))
       == des.newkey(key1 .. key2 .. key3):encryptblock(block))
```

<!-- ---------------------------------------------------------------------------------------- -->
##   Security
<!-- ---------------------------------------------------------------------------------------- -->

  * DES keys can be found by exhaustive search in a short time with dedicated hardware; 
    Triple DES with two keys has about 80 bit and with three keys about 112 bit of 
    security against the known attacks. NIST disallows Triple DES for encryption after 
    2023.
  * The block size of 64 bits limits the data per key: after about 2^32 blocks (32 GB) 
    with the same key, collisions of ciphertext blocks reveal information about the 
    plaintext (Sweet32); SP 800-67 limits the data per key to 2^20 blocks.
  * CBC with padding and without a MAC is open to padding oracle attacks, see 
    [Security](README.md#conv-security) of the Common Conventions.
  * Key schedules and stream states are overwritten with zeros when they are no longer 
    needed (also on errors and by the garbage collector); copies that Lua makes of 
    strings (keys given as strings, plaintexts) are beyond the module's control.

<!-- ---------------------------------------------------------------------------------------- -->
##   Implementation and Side Channels
<!-- ---------------------------------------------------------------------------------------- -->

cipher.des is written in portable C after FIPS 46-3, without assembly.

  * **S-boxes without tables**: table based DES implementations combine the S-boxes with
    the permutation P into eight tables of 64 words ("SP-boxes"), indexed with key and 
    data dependent values, which is open to cache timing attacks. cipher.des holds each 
    S-box as four 64 bit constants, one for each of its four output bits: bit *x* of the
    constant is the output bit for the 6 bit input *x*, so an output bit is the constant
    shifted right by *x* and masked. The bit is moved directly to its place after P with
    a constant shift. Every memory access and every branch is the same for all keys and 
    all data.
  * **Shifts by a variable amount** take the same time for every amount on current 
    processors (a barrel shifter). On 32 bit platforms, where a compiler may implement 
    a 64 bit shift with a branch on bit 5 of the amount, the code shifts the two 32 bit 
    halves and selects with a mask instead.
  * The **initial and final permutations** are computed with fixed masked swaps, the 
    **key schedule** with fixed bit moves (PC-1, rotations, PC-2): no table is indexed with
    a secret value.
  * **Padding** is checked without branches on the individual bytes; only the final 
    result (valid or not) decides. The error of an invalid padding is an observable 
    event, see [Security](#security).
  * **Limits of this statement**: constant time in C depends on the compiler and the 
    processor; no guarantee is given that the implementation is free of timing side 
    channels on a particular platform. Power analysis and fault attacks are out of scope.
  * The evaluation without tables is slower than SP-box tables (about two to three 
    times), see [Performance](#performance); for legacy formats this is rarely relevant.

<!-- ---------------------------------------------------------------------------------------- -->
##   Performance
<!-- ---------------------------------------------------------------------------------------- -->

Orders of magnitude on a current x86-64 processor (one core, *tests/des/bench01.lua*):

| Cipher                                   | All modes (encryption and decryption) |
|------------------------------------------|---------------------------------------|
| DES                                      | about 35 MB/s                         |
| Triple DES (two or three keys)           | about 13 MB/s                         |
| *des.newkey()* of a 24 byte key          | about 3 µs                            |

The modes are all sequential (one block at a time), CFB8 encrypts one block per byte 
(eight times slower). Table based implementations (OpenSSL) are about two to three times
as fast.

<!-- ---------------------------------------------------------------------------------------- -->
##   Compatibility
<!-- ---------------------------------------------------------------------------------------- -->

The results are those of the standards; the test suite compares them with other 
implementations byte for byte ([tests/des/test04.lua](../tests/des/test04.lua)):

| cipher.des                     | OpenSSL                          | Python                                | Perl                                  |
|--------------------------------|----------------------------------|---------------------------------------|---------------------------------------|
| 8 byte keys                    | *enc -des-ecb*, *-des-cbc*, *-des-cfb*, *-des-cfb8*, *-des-ofb* (legacy provider of OpenSSL 3) | *DES* (pycryptodome); *TripleDES* with an 8 byte key (cryptography) | *Crypt::Mode::\** with *'DES'* (CryptX), *Crypt::DES*, *Crypt::CBC* |
| 16 byte keys                   | *-des-ede-ecb*, *-des-ede-cbc*, *-des-ede-cfb*, *-des-ede-ofb* | *DES3*, *TripleDES*        | *Crypt::Mode::\** with *'DES_EDE'*     |
| 24 byte keys                   | *-des-ede3-ecb*, *-des-ede3-cbc*, *-des-ede3-cfb*, *-des-ede3-cfb8*, *-des-ede3-ofb* | *DES3*, *TripleDES* | *Crypt::Mode::\** with *'DES_EDE'*, *Crypt::DES_EDE3*, *Crypt::CBC* |
| *"cfb"*, *"cfb8"*              | *-cfb*, *-cfb8*                  | *MODE_CFB* with *segment_size* 64, 8; *CFB*, *CFB8* | *Crypt::Mode::CFB* (64 bit)  |
| *"ctr"*, *iv* = first counter block | (no DES in CTR mode)        | *MODE_CTR* with *nonce = b""*, *initial_value = iv* (pycryptodome) | *Crypt::Mode::CTR->new('DES_EDE', 1, 8)* |

*openssl enc* without *-K* derives key and IV from a password and writes a *Salted__* 
header; cipher.des has no key derivation, give the key and IV in hex with *-K* and *-iv*
to exchange data with it.

<!-- ---------------------------------------------------------------------------------------- -->
##   Errors
<!-- ---------------------------------------------------------------------------------------- -->

All errors are raised with *error()* as strings:

  * argument errors: *bad argument #2 to 'encrypt' (invalid key length (12))*, *string, 
    carray or des key expected, got number*, *invalid iv length (16)*, *option 'iv' is 
    required for mode 'cbc'*, *option 'iv' is not supported by mode 'ecb'*, *option 
    'padding' is not supported by mode 'ctr'*, *invalid mode value*, *unknown option 
    'aad'*, *mode 'cbc' has no tag*, the errors of *out* (see [Output: string or 
    carray](README.md#output-string-or-carray)); they are raised before anything is 
    done, a stream stays usable;
  * errors of the data: *invalid padding*, *data length (N) is not a multiple of the 
    block size (8)*; a stream is closed afterwards;
  * *encryptor is closed* / *decryptor is closed*: the stream was finished or failed.

<!-- ---------------------------------------------------------------------------------------- -->
##   Thread safety / multiple Lua states
<!-- ---------------------------------------------------------------------------------------- -->

cipher.des has no global mutable data: the module can be loaded into several Lua states 
of the same process, also used in parallel OS threads (one thread per Lua state). Key 
objects, stream objects and the cache of the Carray C API belong to their Lua state.

<!-- ---------------------------------------------------------------------------------------- -->
##   Building
<!-- ---------------------------------------------------------------------------------------- -->

With LuaRocks from the repository root:

```
luarocks make rockspecs/cipher.des-scm-0.rockspec
```

No external library is needed, only a C compiler. Without LuaRocks, the Makefile in 
*src* builds *src/build/lua$(LUA_VERSION)/cipher/des.so* (*make des*), and 
*src/activate.sh* sets the Lua paths for using it from the source tree.

The tests are run from the *tests/des* directory:

  * *lua test01.lua* - string data: the known answer tests of [NIST SP 800-20] (variable
    plaintext, inverse permutation, variable key, permutation operation and substitution 
    table tests, from the files of [NIST CAVP]), the TDEA multi-block message tests of 
    NIST CAVP (TECBMMT, TCBCMMT, TCFB64MMT, TCFB8MMT, TOFBMMT with two and three keys, 
    encryption and decryption), the examples of FIPS 81 (ECB, CBC, CFB, CFB8, OFB) and 
    SP 800-67, Triple DES as EDE of single DES, parity bits, one-shot functions, streams 
    with all chunk sizes (also 1 byte), key objects, PKCS#7 padding and its errors, the 
    CTR counter and its wrap-around, option and argument errors
  * *lua test02.lua* - carray data, keys and IVs, carray output of all functions and 
    methods; read-only and non-resizable carrays with the test helper module 
    *cipher_testcarray* (skipped if carray or the helper is not installed)
  * *lua test03.lua* - several Lua states in parallel threads (test helper module 
    *cipher_multistate*, skipped if it is not installed)
  * *lua test04.lua* - comparison with *openssl enc* (DES with the legacy provider, two 
    and three key Triple DES; ECB, CBC, CFB, CFB8, OFB, with and without padding), 
    Python's *cryptography* and *pycryptodome* (helper *test04.py*), Perl's CryptX 
    (*Crypt::Mode::\**), *Crypt::DES*, *Crypt::DES_EDE3* and *Crypt::CBC* (helper 
    *test04.pl*), in both directions; each part is skipped if the tool or module is not 
    installed, *CIPHER_TEST_REQUIRE* (e.g. *openssl,cryptography,pycryptodome,cryptx,des,
    cbc*) makes a skipped part an error
  * *lua bench01.lua [MB]* - throughput of all modes (not a test)
