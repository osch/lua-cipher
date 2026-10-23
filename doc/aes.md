# cipher.aes Documentation
<!-- ---------------------------------------------------------------------------------------- -->
##   Contents
<!-- ---------------------------------------------------------------------------------------- -->

   * [Overview](#overview)
   * [Data and Keys](#data-and-keys)
   * [Modes](#modes)
   * [Module Functions](#module-functions)
        * [aes.encrypt()](#aes_encrypt)
        * [aes.decrypt()](#aes_decrypt)
        * [aes.encryptor()](#aes_encryptor)
        * [aes.decryptor()](#aes_decryptor)
        * [aes.newkey()](#aes_newkey)
        * [aes.version()](#aes_version)
        * [aes._VERSION](#aes__VERSION)
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
   * [GCM](#gcm)
   * [Implementation and Side Channels](#implementation-and-side-channels)
   * [Performance](#performance)
   * [Compatibility](#compatibility)
   * [Errors](#errors)
   * [Thread safety / multiple Lua states](#thread-safety--multiple-lua-states)
   * [Building](#building)

<!-- ---------------------------------------------------------------------------------------- -->
##   Overview
<!-- ---------------------------------------------------------------------------------------- -->

The [Lua] module *cipher.aes* of [lua-cipher](../README.md) provides the block cipher AES
([FIPS 197]) with keys of 128, 192 and 256 bits in the modes of operation of 
[NIST SP 800-38A] (ECB, CBC, CFB, CFB8, OFB, CTR) and GCM ([NIST SP 800-38D]), in 
self-contained C code without an external library:

  * [aes.encrypt()](#aes_encrypt) and [aes.decrypt()](#aes_decrypt) process the whole 
    data in one call; GCM gives and checks the authentication tag.
  * [aes.encryptor()](#aes_encryptor) and [aes.decryptor()](#aes_decryptor) create 
    stream objects that take the data in pieces.
  * [aes.newkey()](#aes_newkey) creates a key object: the key schedule computed once, 
    usable instead of the key in all functions, and with the block functions 
    [encryptblock()](#key_encryptblock) / [decryptblock()](#key_decryptblock) for 
    callers that implement modes of their own.
  * The implementation is bitsliced: no table lookups and no branches that depend on the
    key or the data, see [Implementation and Side 
    Channels](#implementation-and-side-channels).

Data may be Lua strings or [carray] objects, see [Data and Keys](#data-and-keys). Errors
are raised with *error()*, see [Errors](#errors). The module follows the 
[Common Conventions](README.md#common-conventions) of lua-cipher.

The module name to require is *"cipher.aes"*; it is also available as 
*require("cipher").aes* through the [meta module](README.md#the-meta-module-cipher):

```lua
local aes = require("cipher.aes")

local key = ("k"):rep(32)                       -- AES-256
local iv  = ("i"):rep(16)                       -- random and new for each message in real use
local ct  = aes.encrypt("secret", key, { iv = iv })            -- CBC with PKCS#7 padding
assert(aes.decrypt(ct, key, { iv = iv }) == "secret")

local nonce = ("n"):rep(12)
local gct, tag = aes.encrypt("secret", key, { mode = "gcm", iv = nonce, aad = "header" })
assert(aes.decrypt(gct, key, { mode = "gcm", iv = nonce, aad = "header", tag = tag }) == "secret")
```

This module works with Lua 5.1 up to 5.5 and LuaJIT. The [carray] module is optional: 
cipher.aes neither links against it nor requires it, carray objects are recognized 
through the [Carray C API]. The rock *cipher.aes* depends on nothing but Lua and can be
installed without the other rocks of lua-cipher.

The metatable names (*getmetatable()*) are *"cipher.aes"*, *"cipher.aes.encryptor"*, 
*"cipher.aes.decryptor"* and *"cipher.aes.key"*; the latter three also appear in 
*tostring()* of the objects.

[Lua]:             https://www.lua.org
[FIPS 197]:        https://csrc.nist.gov/pubs/fips/197/final
[NIST SP 800-38A]: https://csrc.nist.gov/pubs/sp/800/38/a/final
[NIST SP 800-38D]: https://csrc.nist.gov/pubs/sp/800/38/d/final
[carray]:          https://github.com/osch/lua-carray
[Carray C API]:    https://github.com/lua-capis/lua-carray-capi

<!-- ---------------------------------------------------------------------------------------- -->
##   Data and Keys
<!-- ---------------------------------------------------------------------------------------- -->

The data (argument *data*, and *chunk* of the stream methods) and the binary options 
*iv*, *aad* and *tag* may be

  * a Lua string (for the data also a number, converted as in the string library), or
  * a carray object with elements of 1 byte size (element types *"char"*, *"uchar"*, 
    *"schar"*, *"int8"*, *"uint8"*). Other element types raise an error. A carray is read
    directly from its buffer, without copying; read-only carrays are accepted.

The **key** is a string or carray of 16, 24 or 32 bytes (AES-128, AES-192, AES-256), or a
key object of [aes.newkey()](#aes_newkey). Other lengths raise *invalid key length (N)*.

The result is a Lua string. Every function and method can instead append its output to 
a carray given as its last argument *out* (see 
[Output](README.md#output-string-or-carray) in the Common Conventions):

  * the carray must have 1 byte elements and be writable and resizable, and must not be
    the same object as the input data of the call;
  * the output is appended after the carray's content, the carray is resized as needed 
    and returned instead of a string (also when nothing was appended); its capacity is 
    kept, so *buf:reset()* before a call reuses a carray without reallocation;
  * the one-shot functions take *out* after the options: *aes.encrypt(data, key, opts,
    out)* (a carray as third argument would be *out* without options, but cipher.aes 
    always needs options: the default mode needs an IV);
  * the stream methods take *out* after *chunk* (and after the *tag* of 
    [decryptor:finish()](#decryptor_finish)); without a chunk *nil* is given: 
    *e:finish(nil, out)*;
  * if a call raises an error, the carray is set back to its previous length.

```lua
local buf = carray.new("char")
aes.encrypt(data, key, { mode = "ctr", iv = iv }, buf)   -- buf contains the ciphertext
buf:reset()                                               -- empty again, keeps the capacity
local e = aes.encryptor(key, { iv = iv })
for chunk in inputFile:lines(65536) do
    e:update(chunk, buf)                                  -- appended to buf
end
e:finish(nil, buf)
```

<!-- ---------------------------------------------------------------------------------------- -->
##   Modes
<!-- ---------------------------------------------------------------------------------------- -->

The option [*mode*](#option_mode) selects the mode of operation:

| mode     | Standard            | iv                 | Padding         | Output length | Parallel   |
|----------|---------------------|--------------------|-----------------|---------------|------------|
| *"ecb"*  | SP 800-38A          | none               | pkcs7 (default), none | blocks  | both       |
| *"cbc"*  | SP 800-38A          | 16 bytes           | pkcs7 (default), none | blocks  | decryption |
| *"cfb"*  | SP 800-38A, CFB128  | 16 bytes           | -               | = input       | decryption |
| *"cfb8"* | SP 800-38A, CFB8    | 16 bytes           | -               | = input       | -          |
| *"ofb"*  | SP 800-38A          | 16 bytes           | -               | = input       | -          |
| *"ctr"*  | SP 800-38A          | 16 bytes: the first counter block | - | = input       | both       |
| *"gcm"*  | SP 800-38D          | 1 byte or more, usually 12 (nonce) | - | = input + tag | both  |

The default mode is *"cbc"*. "Parallel" are the directions in which four blocks are 
processed at once, which is about four times as fast (see [Performance](#performance)).

  * **ecb** encrypts each block on its own: equal plaintext blocks give equal ciphertext
    blocks. For single blocks and modes of one's own, see also [key 
    objects](#key-object-methods).
  * **cbc** xors each plaintext block with the previous ciphertext block (the first with
    the IV) before the encryption. The IV must be unpredictable.
  * **cfb** (CFB128) and **cfb8** feed the ciphertext back into the cipher, 16 bytes or 1 
    byte at a time; CFB8 encrypts one block per byte (16 times slower).
  * **ofb** encrypts the IV again and again and xors the data with the result.
  * **ctr** encrypts the counter blocks *iv*, *iv + 1*, *iv + 2*, ... and xors the data 
    with them. The counter is the whole 16 byte block as a big endian number and wraps 
    around from *ff...ff* to *00...00* (as in OpenSSL). With an 8 byte nonce and an 8 
    byte counter starting at 0 (pycryptodome's default), the IV is *nonce .. 
    ("\0"):rep(8)*; the low 64 bits overflow into the nonce only after 2^64 blocks.
  * **gcm** is CTR with a 32 bit counter plus the GHASH authentication, see [GCM](#gcm).

Padding: ECB and CBC use PKCS#7 by default: 1 to 16 bytes, each with the number of bytes
added, so that *#ciphertext = #plaintext - #plaintext % 16 + 16*. With 
*padding = "none"* the data must be a multiple of 16 bytes. The other modes have no 
padding; the output has the length of the input.

<!-- ---------------------------------------------------------------------------------------- -->
##   Module Functions
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_encrypt">**`aes.encrypt(data, key[, opts][, out])
  `**</span>
  
  Encrypts *data* and returns the ciphertext as string, or appended to the carray *out*,
  which is returned; for GCM the tag as second result.
  
  * *data* - string or carray, see [Data and Keys](#data-and-keys). May be empty.
  * *key* - string or carray of 16, 24 or 32 bytes, or a key object.
  * *opts* - table with the [options](#options) *mode*, *iv*, *padding*, *aad* and 
    *taglen*. As the default mode *"cbc"* needs an *iv*, the options are always given in
    practice.
  * *out* - optional carray, see [Data and Keys](#data-and-keys).

  ```lua
  local ct = aes.encrypt(data, key, { iv = iv })                     -- cbc, pkcs7
  local ct2 = aes.encrypt(data, key, { mode = "ctr", iv = counter0 })
  local gct, tag = aes.encrypt(data, key, { mode = "gcm", iv = nonce, aad = header })
  ```

  Raises an error for *padding = "none"* if the length of *data* is not a multiple of 
  16 (ECB, CBC).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_decrypt">**`aes.decrypt(data, key[, opts][, out])
  `**</span>
  
  Decrypts *data* and returns the plaintext as string, or appended to the carray *out*,
  which is returned.
  
  * *data* - the ciphertext, string or carray.
  * *key* - string or carray of 16, 24 or 32 bytes, or a key object.
  * *opts* - table with the [options](#options) *mode*, *iv*, *padding*, *aad*, *taglen*
    and *tag* (required for GCM).
  * *out* - optional carray.

  Raises *invalid padding* if the PKCS#7 padding is not valid (also for empty data), 
  *data length (N) is not a multiple of the block size (16)* for ECB and CBC, and for 
  GCM *authentication failed* if the tag does not match; GCM checks the tag before 
  anything is decrypted, so nothing of unauthenticated data is output.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_encryptor">**`aes.encryptor(key[, opts])
  `**</span>
  
  Creates an encryptor stream object, see [Encryptor Methods](#encryptor-methods).
  
  * *key* - string or carray of 16, 24 or 32 bytes, or a key object (the stream copies 
    its key schedule).
  * *opts* - optional table with the [options](#options) *mode*, *iv*, *padding*, *aad*
    and *taglen*. A carray for the output is given to the methods, not to 
    *encryptor()*.

  The state (about 1.3 KB, with the expanded key) is part of the userdata; it is 
  overwritten with zeros by *finish()* and when the object is collected.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_decryptor">**`aes.decryptor(key[, opts])
  `**</span>
  
  Creates a decryptor stream object, see [Decryptor Methods](#decryptor-methods).
  
  * *key* - string or carray of 16, 24 or 32 bytes, or a key object.
  * *opts* - optional table with the [options](#options) *mode*, *iv*, *padding*, *aad*,
    *taglen* and *tag* (for GCM; may instead be given to 
    [decryptor:finish()](#decryptor_finish)).

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_newkey">**`aes.newkey(key)
  `**</span>
  
  Creates a key object: the expanded key schedule of *key* (string or carray of 16, 24 
  or 32 bytes, or another key object, which is copied). A key object can be given 
  instead of the key to all functions; this saves the key expansion in each call, and 
  its methods [encryptblock()](#key_encryptblock) and 
  [decryptblock()](#key_decryptblock) are the raw block cipher.

  The key schedule is computed with the same bitsliced S-box as the encryption (no 
  tables). Creating a key object takes about a microsecond, and it can be used by any 
  number of calls at the same time; for many short messages with changing keys (e.g. a 
  key per object of a document) it is fine to create one per key, or to give the key 
  itself to [aes.decrypt()](#aes_decrypt). The key schedule is overwritten with zeros 
  when the key object is collected.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes_version">**`aes.version()
  `**</span>
  
  Returns the version of the module, the same as [aes._VERSION](#aes__VERSION): there is 
  no external library.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="aes__VERSION">**`aes._VERSION
  `**</span>
  
  The version of the module cipher.aes as string, e.g. *"0.0.1"*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Options
<!-- ---------------------------------------------------------------------------------------- -->

Options are given as a table (see [Options](README.md#conv-options) of the Common 
Conventions). Unknown names, options that the function does not take (*tag* for 
*encrypt* and *encryptor*) and options that the mode does not take raise errors.

* <span id="option_mode">**`mode`**</span> - *"ecb"*, *"cbc"* (default), *"cfb"*, 
  *"cfb8"*, *"ofb"*, *"ctr"* or *"gcm"*, see [Modes](#modes). Other values: *invalid mode 
  value*.

* <span id="option_iv">**`iv`**</span> - string or carray: the IV, for CTR the first 
  counter block, for GCM the nonce. Required for all modes except ECB (*option 'iv' is 
  required for mode 'cbc'*), not allowed for ECB. 16 bytes, for GCM any length from 1 
  byte (12 bytes is the length the standard recommends and the fast path: other 
  lengths are hashed with GHASH); else *invalid iv length (N)*.

* <span id="option_padding">**`padding`**</span> - *"pkcs7"* (default for ECB and CBC) or
  *"none"*. *"pkcs7"* is only allowed for ECB and CBC, *"none"* for all modes.

* <span id="option_aad">**`aad`**</span> - GCM: string or carray, the additional 
  authenticated data (default empty). For streams it is given to *encryptor()* / 
  *decryptor()* and processed there.

* <span id="option_taglen">**`taglen`**</span> - GCM: the length of the tag in bytes: 16 
  (default), 15, 14, 13, 12, 8 or 4 (the lengths of SP 800-38D; 8 and 4 only for special
  applications). A shorter tag is the beginning of the full tag.

* <span id="option_tag">**`tag`**</span> - GCM, *decrypt* and *decryptor*: the expected 
  tag, string or carray of one of the lengths of *taglen* (*invalid tag length (N)*); if
  *taglen* is given too, the lengths must be the same.

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
  as string (also *""*), or appended to *out*; for GCM the tag as second result. ECB and
  CBC add the padding here (with *padding = "none"* the whole data must have been a 
  multiple of 16 bytes). Afterwards the object is closed: every call except *tag()* 
  raises *encryptor is closed*.

* <span id="encryptor_tag">**`encryptor:tag()
  `**</span>
  
  GCM: returns the tag again after *finish()*; before: *the tag is only available after 
  finish()*; other modes: *mode 'cbc' has no tag*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Decryptor Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="decryptor_update">**`decryptor:update(chunk[, out])
  `**</span>
  
  Decrypts *chunk*. Returns the output so far as string, or *nil* if there is none yet:
  ECB and CBC output whole blocks only, and with padding they hold back the last whole 
  block until *finish()*, since it contains the padding. **GCM: the output is not 
  authenticated yet**, see [GCM](#gcm).

* <span id="decryptor_finish">**`decryptor:finish([chunk][, tag][, out])
  `**</span>
  
  Decrypts the optional last *chunk*, ends the stream, checks the padding (ECB, CBC) or 
  the tag (GCM), and returns the rest of the output as string, or appended to *out*. 
  *tag* (GCM only, a string; a carray at this position is *out*) is the expected tag; 
  it replaces the option *tag* of *decryptor()*, one of both is required (*no tag given 
  for mode 'gcm'*). *d:finish(chunk, out)* and *d:finish(chunk, nil, out)* are the 
  same. Raises *invalid padding*, *data length (N) is not a multiple of the block size 
  (16)* or *authentication failed*; the object is closed afterwards in any case.

<!-- ---------------------------------------------------------------------------------------- -->
##   Key Object Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="key_encryptblock">**`key:encryptblock(data[, out])
  `**</span>
  
  Encrypts *data*, whose length must be a multiple of 16 (one or more blocks, each 
  encrypted on its own, as ECB without padding; empty data gives *""*), and returns the 
  result as string, or appended to *out*. Four blocks are encrypted at once, so giving 
  several blocks in one call is faster than one call per block.

* <span id="key_decryptblock">**`key:decryptblock(data[, out])
  `**</span>
  
  Decrypts the blocks of *data* (a multiple of 16 bytes).

```lua
-- CBC decryption by hand, e.g. for a format with its own block handling (Lua 5.3+)
local function xor16(a, b)
    local t = {}
    for i = 1, 16 do t[i] = string.char(a:byte(i) ~ b:byte(i)) end
    return table.concat(t)
end
local k = aes.newkey(key)
local prev, out = iv, {}
for i = 1, #ciphertext, 16 do
    local c = ciphertext:sub(i, i + 15)
    out[#out + 1] = xor16(k:decryptblock(c), prev)
    prev = c
end
```

<!-- ---------------------------------------------------------------------------------------- -->
##   GCM
<!-- ---------------------------------------------------------------------------------------- -->

The Galois/Counter Mode ([NIST SP 800-38D]) encrypts with CTR and authenticates the 
ciphertext and the additional authenticated data *aad* with GHASH:

  * **IV (nonce)**: never use the same IV twice with the same key: this reveals the xor 
    of the plaintexts and allows forgeries. 12 bytes is the recommended length (the IV 
    and a 32 bit counter starting at 1); other lengths are allowed and are hashed into 
    the first counter block.
  * **Data limit**: at most 2^36 - 32 bytes (about 64 GB) per IV; more raises *data 
    exceeds the limit of mode 'gcm'*.
  * **One-shot**: *ct, tag = aes.encrypt(pt, key, { mode = "gcm", iv = nonce, aad = 
    a })*; *aes.decrypt(ct, key, { mode = "gcm", iv = nonce, aad = a, tag = tag })* 
    checks the tag first and decrypts only if it matches, so nothing is output for 
    unauthenticated data (and nothing is appended to *out*).
  * **Streams**: the AAD is given to *encryptor()* / *decryptor()*. *encryptor:finish()*
    returns the tag as second result (also by *encryptor:tag()*). The decryptor gets the 
    expected tag as option or as argument of *finish()*; **its *update()* returns 
    plaintext before the tag is checked**, as every streaming AEAD decryption must. A 
    caller that must not act on unauthenticated data keeps the output until *finish()* 
    has succeeded, or uses *aes.decrypt()*.
  * **Tags**: 16 bytes by default; *taglen* selects a shorter one (the first bytes of 
    the full tag). The comparison does not depend on where the tags differ (constant 
    time).
  * The ciphertext and the tag are separate results; a format that appends the tag to 
    the ciphertext (WebCrypto, Go's *Seal*, RFC 5116) is *ct .. tag*, and is split with
    *data:sub(1, -17)*, *data:sub(-16)* for decryption.

<!-- ---------------------------------------------------------------------------------------- -->
##   Implementation and Side Channels
<!-- ---------------------------------------------------------------------------------------- -->

cipher.aes is written in portable C, without assembly and without the AES instructions 
of current processors (AES-NI, ARMv8 Crypto Extensions): there is no external library and
no platform specific code.

  * **AES** is bitsliced, adapted from the *aes_ct64* implementation of [BearSSL] (MIT 
    licence, see [LICENSE](../LICENSE)): the state of four blocks is held in eight 64 bit 
    words, the S-box is computed with the Boyar-Peralta circuit of logical operations, 
    and the key schedule uses the same circuit. There are no table lookups and no 
    branches that depend on the key or the data, so the implementation is not open to 
    the cache timing attacks that table based AES implementations (T-tables) are known 
    for.
  * **GHASH** of GCM is adapted from BearSSL's *ghash_ctmul64*: the multiplication in 
    GF(2^128) uses integer multiplications with the data bits spread out, no tables.
  * **Padding and tags** are checked without branches on the individual bytes; only the
    final result (valid or not) decides.
  * **Limits of this statement**: constant time in C depends on the compiler and the 
    processor. The code is written so that the compiler has no reason to add branches, 
    but this is not verified for every compiler and platform; the 64 bit integer 
    multiplications of GHASH are not constant time on some older or small processors 
    (e.g. some 32 bit ARM cores, where they are library calls). No guarantee is given 
    that the implementation is free of timing side channels on a particular platform. 
    Power analysis and fault attacks are out of scope.
  * The error of an invalid padding is an observable event: CBC decryption without 
    authentication is open to padding oracle attacks by its construction, whatever the 
    implementation; use GCM or authenticate the ciphertext (encrypt-then-MAC).
  * Key schedules and stream states are overwritten with zeros when they are no longer 
    needed (also on errors and by the garbage collector); copies that Lua makes of 
    strings (keys given as strings, plaintexts) are beyond the module's control.

[BearSSL]: https://bearssl.org/

<!-- ---------------------------------------------------------------------------------------- -->
##   Performance
<!-- ---------------------------------------------------------------------------------------- -->

The bitsliced implementation processes four blocks in about the time a table based one 
needs for four to eight blocks; it is fastest where four blocks can be encrypted at once
(ECB, CBC and CFB decryption, CTR, GCM). CBC, CFB and OFB encryption are sequential: each 
block needs the result of the previous one, so only one of the four slots is used.

Orders of magnitude on a current x86-64 processor (one core, 16 MB of data, 
*tests/aes/bench01.lua*):

| Mode                                     | AES-128         | AES-256         |
|------------------------------------------|-----------------|-----------------|
| CTR, ECB, CBC/CFB decryption             | 140 - 190 MB/s  | 105 - 145 MB/s  |
| GCM (encryption and decryption)          | about 120 MB/s  | about 100 MB/s  |
| CBC, CFB, OFB encryption (sequential)    | about 45 MB/s   | about 35 MB/s   |
| CFB8                                     | about 3 MB/s    | about 2 MB/s    |
| a short message (48 bytes, CBC) with a new key | about 2 µs per message |  |

A pure Lua AES-128 (table based, Lua 5.5) reaches about 6 MB/s in CBC encryption on the 
same machine, the sequential case of cipher.aes is about seven times as fast, the 
parallel modes about 25 times. Implementations with AES-NI (OpenSSL) are one to two 
orders of magnitude faster than cipher.aes; where throughput matters more than 
self-containedness, they are the better choice.

<!-- ---------------------------------------------------------------------------------------- -->
##   Compatibility
<!-- ---------------------------------------------------------------------------------------- -->

The results are those of the standards; the test suite compares them with other 
implementations byte for byte ([tests/aes/test04.lua](../tests/aes/test04.lua)):

| cipher.aes                         | OpenSSL                     | Python                             | Perl                                    |
|------------------------------------|-----------------------------|------------------------------------|-----------------------------------------|
| *{ iv = iv }* (cbc, pkcs7)         | *enc -aes-256-cbc -K -iv*   | *modes.CBC* + *PKCS7(128)*; *AES.MODE_CBC* + *pad* | *Crypt::CBC* (*-header 'none'*, literal key), *Crypt::Mode::CBC* |
| *padding = "none"*                 | *-nopad*                    | without padding                    | *Crypt::Rijndael* (*MODE_CBC*, ...)    |
| *"cfb"*, *"cfb8"*, *"ofb"*         | *-aes-\*-cfb*, *-cfb8*, *-ofb* | *CFB*, *CFB8*, *OFB*; *MODE_CFB* (*segment_size*), *MODE_OFB* | *Crypt::Mode::CFB*, *::OFB* |
| *"ctr"*, *iv* = first counter block | *-aes-\*-ctr -iv*          | *modes.CTR(iv)*; *MODE_CTR* with *nonce = b""*, *initial_value = iv* | *Crypt::Mode::CTR->new('AES', 1, 16)* |
| *"gcm"*, *iv*, *aad*, *tag*        | (not in *enc*)              | *modes.GCM*, *AESGCM*; *MODE_GCM* (*nonce*, *mac_len*) | *Crypt::AuthEnc::GCM*                |

*openssl enc* without *-K* derives key and IV from a password and writes a *Salted__* 
header; cipher.aes has no key derivation, give the key and IV in hex with *-K* and 
*-iv* (and *-nosalt*) to exchange data with it.

<!-- ---------------------------------------------------------------------------------------- -->
##   Errors
<!-- ---------------------------------------------------------------------------------------- -->

All errors are raised with *error()* as strings:

  * argument errors: *bad argument #2 to 'encrypt' (invalid key length (5))*, *invalid 
    iv length (8)*, *option 'iv' is required for mode 'cbc'*, *option 'iv' is not 
    supported by mode 'ecb'*, *option 'padding' is not supported by mode 'ctr'*, 
    *option 'tag' is not supported by encrypt()*, *option 'tag' is required for mode 
    'gcm'*, *invalid tag length (3)*, *tag length contradicts taglen*, *invalid mode 
    value*, *unknown option 'name'*, the errors of *out* (see [Output: string or 
    carray](README.md#output-string-or-carray)); they are raised before anything is 
    done, a stream stays usable;
  * errors of the data: *invalid padding*, *data length (N) is not a multiple of the 
    block size (16)*, *authentication failed*, *data exceeds the limit of mode 'gcm'*, 
    *no tag given for mode 'gcm'*; a stream is closed afterwards;
  * *encryptor is closed* / *decryptor is closed*: the stream was finished or failed.

<!-- ---------------------------------------------------------------------------------------- -->
##   Thread safety / multiple Lua states
<!-- ---------------------------------------------------------------------------------------- -->

cipher.aes has no global mutable data: the module can be loaded into several Lua states 
of the same process, also used in parallel OS threads (one thread per Lua state). Key 
objects, stream objects and the cache of the Carray C API belong to their Lua state.

<!-- ---------------------------------------------------------------------------------------- -->
##   Building
<!-- ---------------------------------------------------------------------------------------- -->

With LuaRocks from the repository root:

```
luarocks make rockspecs/cipher.aes-scm-0.rockspec
```

No external library is needed, only a C compiler (gcc, clang, MSVC in a Visual Studio 
developer prompt, MinGW/MSYS2). Without LuaRocks, the Makefile in *src* builds 
*src/build/lua$(LUA_VERSION)/cipher/aes.so* (settings can be overridden in 
*src/sandbox.mk*); *src/activate.sh* sets the Lua paths for using the module from the 
source tree:

```
cd src
make aes LUA_VERSION=5.4 COPTS=-I/usr/include/lua5.4
. activate.sh
```

The tests are run from the *tests/aes* directory:

  * *lua test01.lua* - string data: the test vectors of FIPS 197 (Appendix C), NIST SP 
    800-38A (Appendix F: ECB, CBC, CFB8, CFB128, OFB, CTR with all key sizes) and of the
    GCM specification (test cases 1 to 18, the vectors of SP 800-38D: IVs of 8, 12 and 
    60 bytes, with and without AAD), one-shot functions, streams with all chunk sizes 
    (also 1 byte), key objects, PKCS#7 padding and its errors, truncated and wrong 
    tags, counter wrap-around, option and argument errors, 10 MB
  * *lua test02.lua* - carray data, keys, IVs, AAD and tags, carray output of all 
    functions and methods (appending, reuse after reset, returned object, errors), 
    carray chunks (skipped if carray is not installed); the error cases for read-only 
    and non-resizable carrays need the test helper module *cipher_testcarray* 
    (*luarocks make tests/cipher_testcarray-scm-0.rockspec* from the repository root, 
    or *make testcarray* in *src*), skipped if it is not installed
  * *lua test03.lua* - several Lua states in parallel threads; needs the test helper 
    module *cipher_multistate* (*luarocks make tests/cipher_multistate-scm-0.rockspec*
    from the repository root, or *make multistate* in *src*), skipped if it is not 
    installed
  * *lua test04.lua* - comparison with *openssl enc* (ECB, CBC, CFB, CFB8, OFB, CTR, all
    key sizes, with and without padding), Python's *cryptography* and *pycryptodome* 
    (all modes, helper *test04.py*) and Perl's CryptX (*Crypt::Mode::\**, 
    *Crypt::AuthEnc::GCM*), *Crypt::Rijndael* and *Crypt::CBC* (helper *test04.pl*), 
    in both directions. Each part is skipped if the tool or module is not installed; 
    *CIPHER_TEST_REQUIRE* (e.g. *openssl,cryptography,pycryptodome,cryptx*) makes a 
    skipped part an error, *CIPHER_TEST_OPENSSL*, *CIPHER_TEST_PYTHON* and 
    *CIPHER_TEST_PERL* name the programs
  * *lua bench01.lua [MB]* - throughput of all modes and of a pure Lua AES (not a test)
