# lua-cipher Documentation
<!-- ---------------------------------------------------------------------------------------- -->
##   Contents
<!-- ---------------------------------------------------------------------------------------- -->

   * [Overview](#overview)
   * [Modules and Rocks](#modules-and-rocks)
   * [The Meta Module cipher](#the-meta-module-cipher)
        * [cipher.\<name\>](#cipher_name)
        * [cipher.names](#cipher_names)
        * [cipher._VERSION](#cipher__VERSION)
   * [Common Conventions](#common-conventions)
        * [Functions and methods](#functions-and-methods)
        * [Data](#conv-data)
        * [Keys](#conv-keys)
        * [Output: string or carray](#output-string-or-carray)
        * [Options](#conv-options)
        * [Modes and padding](#conv-modes)
        * [Authenticated encryption](#conv-aead)
        * [Errors](#conv-errors)
        * [Security](#conv-security)
        * [Thread safety](#conv-threads)
   * [Building](#building)

<!-- ---------------------------------------------------------------------------------------- -->
##   Overview
<!-- ---------------------------------------------------------------------------------------- -->

*lua-cipher* is a collection of [Lua] modules for symmetric encryption, each one written 
in self-contained C code without an external crypto library. All modules share the same 
conventions (see [Common Conventions](#common-conventions)):

  * data, keys, IVs and tags may be Lua strings or [carray] objects; a carray is read 
    directly from its buffer, without copying,
  * the output is a new Lua string, or is appended in place to a carray given as the 
    last argument of a call,
  * there are functions that process the whole data in one call, and stream objects 
    that take the data in pieces,
  * errors are raised with *error()*.

The modules work with Lua 5.1 up to 5.5 and LuaJIT. The [carray] module is optional: no
module links against it or requires it, carray objects are recognized through the 
[Carray C API].

[Lua]:          https://www.lua.org
[carray]:       https://github.com/osch/lua-carray
[Carray C API]: https://github.com/lua-capis/lua-carray-capi

<!-- ---------------------------------------------------------------------------------------- -->
##   Modules and Rocks
<!-- ---------------------------------------------------------------------------------------- -->

Each module is a rock of its own, with the module name as rock name:

| Rock / module                       | Cipher                                                          |
|-------------------------------------|-----------------------------------------------------------------|
| [cipher.aes](aes.md)                | AES: ECB, CBC, CFB, CFB8, OFB, CTR, GCM                         |
| [cipher.rc4](rc4.md)                | RC4 (ARCFOUR), RC4-drop[n]                                      |
| [cipher.chacha20](chacha20.md)      | ChaCha20, XChaCha20, ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305, Poly1305 |
| [cipher.des](des.md)                | DES, Triple DES (EDE, two and three keys): ECB, CBC, CFB, CFB8, OFB, CTR |
| *cipher* (meta rock)                | -                                                               |

  * A module rock *cipher.\<name\>* depends on nothing but Lua: the cipher is implemented
    in the module itself, there is no external library. It can be installed alone, e.g. 
    *luarocks install cipher.aes*, and is then used with *require("cipher.aes")*. The 
    module rocks do not depend on each other; the helper sources they have in common 
    (Lua compatibility, Carray C API header) are compiled into each module, there is no 
    shared runtime module.
  * The meta rock *cipher* depends on all module rocks and installs the pure Lua module 
    *cipher*, see [below](#the-meta-module-cipher). It is the only rock that contains 
    *cipher.lua*.

A module *cipher.\<name\>* is a C module (entry point *luaopen_cipher_\<name\>*), 
installed as *cipher/\<name\>.so* (*cipher/\<name\>.dll* on Windows) in the Lua C module 
path.

<!-- ---------------------------------------------------------------------------------------- -->
##   The Meta Module cipher
<!-- ---------------------------------------------------------------------------------------- -->

The pure Lua module *cipher* of the meta rock gives access to all modules under one name.
Each module is loaded on its first access only:

```lua
local cipher = require("cipher")

local aes = cipher.aes                    -- loads "cipher.aes" now
assert(aes == require("cipher.aes"))      -- the same object
```

* <span id="cipher_name">**`cipher.<name>`
  `**</span>

  For a name listed in [cipher.names](#cipher_names): the module *"cipher.\<name\>"*. On
  the first access it is loaded with *require()* and stored in the table *cipher*, so 
  *require("cipher").aes* and *require("cipher.aes")* are the same object (it is also in 
  *package.loaded*). Errors of *require()*, e.g. for a module that is not installed, are
  raised on the access and nothing is stored, so a later access tries again.

  Any other key gives *nil*, as for an ordinary table: no module is looked up for it. 
  A misspelled module name therefore gives *nil*, not an error; *cipher.names* tells 
  which names are modules. (Raising an error for unknown keys was not chosen, because 
  generic code that inspects tables, e.g. serializers or *if cipher.x then*, must not 
  fail on it.)

* <span id="cipher_names">**`cipher.names`
  `**</span>

  The names of the modules the meta module knows, as a list of strings in the order of
  [Modules and Rocks](#modules-and-rocks): *{ "aes", "rc4", "chacha20", "des" }*. These 
  are the modules the meta rock depends on.

* <span id="cipher__VERSION">**`cipher._VERSION`
  `**</span>

  The version of the meta module as string, e.g. *"0.0.1"*. The modules have their own
  *_VERSION* (all rocks of lua-cipher are released with the same version number).

The metatable of the table *cipher* is protected: *getmetatable(cipher)* gives the 
string *"cipher"*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Common Conventions
<!-- ---------------------------------------------------------------------------------------- -->

These conventions hold for all modules: [cipher.aes](aes.md), [cipher.rc4](rc4.md), 
[cipher.chacha20](chacha20.md) and [cipher.des](des.md) follow them and describe them in 
detail. A module documents only what is specific to its cipher: key sizes, modes and 
options.

### Functions and methods

There are two kinds of modules: **block cipher modules** (aes, des), which have modes of
operation, padding and, where the cipher has it, authenticated encryption, and 
**stream cipher modules** (rc4, chacha20), which xor the data with a keystream, so that 
encryption and decryption are the same operation.

Block cipher modules (and the AEAD functions of stream cipher modules, e.g. 
ChaCha20-Poly1305):

| Call                                         | Result                                           |
|----------------------------------------------|--------------------------------------------------|
| *M.encrypt(data, key[, opts][, out])*        | ciphertext [, tag]                               |
| *M.decrypt(data, key[, opts][, out])*        | plaintext                                        |
| *M.encryptor(key[, opts])*                   | encryptor stream object                          |
| *M.decryptor(key[, opts])*                   | decryptor stream object                          |
| *encryptor:update(chunk[, out])*             | output so far                                    |
| *encryptor:finish([chunk][, out])*           | the rest of the output [, tag]; ends the stream  |
| *encryptor:tag()*                            | the tag (authenticated modes, after *finish()*)  |
| *decryptor:update(chunk[, out])*             | output so far                                    |
| *decryptor:finish([chunk][, tag][, out])*    | the rest of the output; checks padding and tag   |
| *M.newkey(key)*                              | key object: the key schedule, computed once (block ciphers) |
| *key:encryptblock(data[, out])*              | the encrypted blocks (the raw block function)    |
| *key:decryptblock(data[, out])*              | the decrypted blocks                             |
| *M.version()*, *M._VERSION*                  | version of the module                            |

Stream cipher modules:

| Call                                         | Result                                           |
|----------------------------------------------|--------------------------------------------------|
| *M.crypt(data, key[, opts][, out])*          | the data xor the keystream                       |
| *M.new(key[, opts])*                         | stream object                                    |
| *stream:crypt(chunk[, out])*                 | the chunk xor the next bytes of the keystream    |
| *M.version()*, *M._VERSION*                  | version of the module                            |

*M.encrypt()*, *M.decrypt()* and *M.crypt()* process the whole data in one call; the 
stream objects take it in pieces, the output of all calls concatenated is the same. 
*finish()* ends the stream; afterwards, and after a data error of *update()* or 
*finish()* (padding, tag, length, limit), every call raises *encryptor is closed* / 
*decryptor is closed*. Argument errors (and errors of the output carray) are raised 
before anything is done and leave the stream usable. A stream cipher object 
(*M.new()*) has no end: *crypt()* can be called again and again.

The modules have no external library: *M.version()* gives the version of the module, the
same as *M._VERSION*.

<span id="conv-data"></span>
### Data

*data* and *chunk* are a Lua string (a number is converted to a string, as in the 
string library) or a carray with 1 byte elements (*"char"*, *"uchar"*, *"schar"*, 
*"int8"*, *"uint8"*), read directly from its buffer, without copying; read-only carrays 
are accepted. Data may contain arbitrary bytes including NUL. The same holds for the 
binary options (*iv*, *aad*, *tag*), except that numbers are not accepted there.

<span id="conv-keys"></span>
### Keys

*key* is a string or a carray of one of the key lengths of the cipher (numbers are not 
accepted), or, for block cipher modules, a key object of *M.newkey()*. A key object holds
the expanded key schedule; giving it instead of the key saves the key expansion in each 
call, e.g. for many short messages with the same key. Key objects are immutable and can 
be used by any number of calls and streams at the same time; a stream copies the key 
schedule, so the key object may be collected while the stream is in use. Key schedules 
are overwritten with zeros when a key object or stream is collected or finished.

### Output: string or carray

**The output of every call is a new Lua string, unless the call is given a carray: then
the output is appended to the carray and the carray is returned.** This holds for the 
one-shot functions and for all stream and key methods alike:

  * **Without a carray**: the one-shot functions, *finish()*, *crypt()* and the block
    functions return a string (never *nil*, *""* if there is no output); *update()* 
    returns a string, or *nil* if there is no output yet (a block mode holds back an 
    incomplete block, a decryptor with padding the last block).
  * **With a carray**: the output is appended after the content the carray has; nothing
    is replaced. The call returns the carray, also when nothing was appended. Reusing a
    buffer is the caller's business: *buf:reset()* empties a carray and keeps its 
    capacity (see [carray]), so that a buffer used again and again is not reallocated 
    once it is large enough. There is no buffer bound to a stream object: each call 
    names its own carray (or none).
  * **Further results** (the tag of an authenticated encryption) come after the output: 
    *ct, tag = M.encrypt(...)*, *buf, tag = M.encrypt(..., buf)*.
  * **Position**: the carray is always an argument of its own, the last one:
      * One-shot functions, whose *data* and *key* are required: the third argument is 
        the options table if it is a table (or *nil*), and *out* if it is a carray; so 
        *M.crypt(data, key, out)* is *M.crypt(data, key, nil, out)*, and 
        *M.encrypt(data, key, opts, out)* gives both. Any other type raises the argument
        error *table or carray expected, got string*.
      * Stream methods: the arguments are positional, *chunk* always comes first, also 
        where it is optional. A carray at the position of *chunk* is the chunk (input 
        data); to give *out* without a chunk, pass *nil*: *e:finish(nil, out)*. The 
        optional *tag* of *decryptor:finish(chunk, tag, out)* is told from *out* by its
        type: a string is the tag, a carray is *out*; *d:finish(chunk, out)* and 
        *d:finish(chunk, nil, out)* are the same.
      * *nil* as *out* is the same as no *out*: the result is a string.
  * **Requirements**: the carray has 1 byte elements and is writable and resizable 
    (else *out: carray elements must be 1 byte in size*, *out: carray is not writable*,
    *cannot resize carray*); it must not be the same object as the input data of the 
    call (*out: carray must not be the input data*); encryption in place is not 
    supported. Errors of *out* are argument errors of its position, e.g. 
    *bad argument #3 to 'update' (out: carray expected, got string)*.
  * **Not an option**: *out* is no option; *out* in an options table raises 
    *option 'out' is not supported: pass the carray as the last argument*.
  * **Errors**: if a call fails, the carray is set back to the length it had before the
    call: it keeps its previous content, including what earlier successful calls of the
    same stream appended, and nothing of the failed call; the bytes that the failed call
    had written behind that length are overwritten with zeros. Argument errors are 
    raised before anything is written.

<span id="conv-options"></span>
### Options

Options are given as a table; numbers must be integers (or floats with an integral 
value). A name that is no option of the module raises *unknown option 'name'*, an option
of the module that the function does not take raises *option 'name' is not supported by
encrypt()* (e.g. *tag* for *encrypt*), an option that the selected mode does not take 
raises *option 'name' is not supported by mode 'cbc'*; keys that are no strings raise 
*option names must be strings*. Option names are the same in all modules:

  * **mode** - the mode of operation of a block cipher, a lower case string: *"ecb"*, 
    *"cbc"*, *"cfb"* (CFB with 128 bit segments, for 64 bit block ciphers 64 bit), 
    *"cfb8"*, *"ofb"*, *"ctr"*, and *"gcm"* where the cipher has it. The default is 
    *"cbc"*, the mode of *openssl enc* and of Perl's *Crypt::CBC*.
  * **iv** - the initialization vector, the nonce of authenticated modes and of 
    ChaCha20, the initial counter block of CTR. Required for every mode except ECB (and 
    always for ChaCha20), never generated: there is no random number generator in 
    lua-cipher.
  * **padding** - *"pkcs7"* (the default for ECB and CBC) or *"none"* (the data must be a
    multiple of the block size). Only ECB and CBC have padding; *"none"* is accepted by 
    every mode.
  * **aad** - additional authenticated data of authenticated modes (default empty).
  * **taglen** - the length of the tag in bytes (AES-GCM; the tags of ChaCha20-Poly1305
    are always 16 bytes).
  * **tag** - the expected tag, for *decrypt* and *decryptor* of authenticated modes.
  * **drop** - stream ciphers: the number of keystream bytes to discard first.
  * **counter** - stream ciphers with a block counter (ChaCha20): the initial counter.

<span id="conv-modes"></span>
### Modes and padding

Block modes (ECB, CBC) process whole blocks: with *padding = "pkcs7"* the encryption 
appends 1 to *blocksize* bytes, each with the number of bytes appended (PKCS#7, for 8 
byte blocks also called PKCS#5), so the ciphertext is always longer than the plaintext; 
the decryption checks and removes them (*invalid padding*). With *padding = "none"* the 
length of the data must be a multiple of the block size (*data length (17) is not a 
multiple of the block size (16)*). Streams of block modes buffer an incomplete block; 
a decryptor with padding holds back the last whole block until *finish()*.

The other modes (CFB, CFB8, OFB, CTR, GCM) produce one byte of output per byte of input, 
streams return the output at once. CTR increments the whole counter block as one big 
endian number (as OpenSSL, *Crypt::Mode::CTR* in big endian mode and pycryptodome with 
*initial_value*); GCM increments its lower 32 bits, as the standard says.

<span id="conv-aead"></span>
### Authenticated encryption

Authenticated modes (AES-GCM of cipher.aes, ChaCha20-Poly1305 and XChaCha20-Poly1305 of 
cipher.chacha20) give a tag that authenticates the ciphertext and the additional data 
*aad*:

  * *ct, tag = M.encrypt(data, key, { mode = ..., iv = nonce, aad = ... })* (without 
    *mode* for cipher.chacha20): the tag is the second result (for AES-GCM the first 
    *taglen* bytes of the full tag). *encryptor:finish()* 
    returns the tag as second result, *encryptor:tag()* returns it again after 
    *finish()* (before: *the tag is only available after finish()*).
  * *M.decrypt(data, key, { ..., tag = tag })*: the tag is required; it is checked 
    before anything is decrypted, and a mismatch raises *authentication failed* without
    output. The length of the tag gives *taglen*.
  * *decryptor:finish([chunk][, tag][, out])*: the expected tag as option *tag* of 
    *M.decryptor()* or as argument of *finish()* (which then wins); without one 
    *finish()* raises *no tag given for mode 'gcm'* (cipher.chacha20: *no tag given*). **The output of 
    *decryptor:update()* is not authenticated before *finish()* has checked the tag**: 
    a caller that must not use unauthenticated data uses *M.decrypt()* or keeps the 
    output until *finish()* succeeded.
  * The tags are compared in constant time.

<span id="conv-errors"></span>
### Errors

Errors are raised with *error()* as strings. Argument errors are raised as such 
(*bad argument #2 to 'encrypt' (invalid key length (5))*); errors of the data have fixed 
messages: *invalid padding*, *authentication failed*, *data length (N) is not a multiple 
of the block size (16)*, *data exceeds the limit of mode 'gcm'*, *data exceeds the limit 
of the counter* (ChaCha20).

<span id="conv-security"></span>
### Security

lua-cipher implements the ciphers, nothing around them: it creates no keys, IVs or 
nonces (they come from the caller, e.g. from a key derivation function and a random 
source), and it has no key derivation and no message authentication of its own besides 
the authenticated modes. A few rules that the modules cannot enforce:

  * Never use a nonce (*iv* of GCM, CTR, OFB, CFB, ChaCha20) twice with the same key.
    CBC needs an unpredictable IV.
  * CBC with padding and without a MAC is open to padding oracle attacks if an attacker 
    can learn whether the decryption of a manipulated ciphertext failed; prefer an 
    authenticated mode for new formats.
  * ECB shows equal blocks of the plaintext; RC4 and DES are broken and only for legacy
    formats.
  * Implementations without table lookups or branches that depend on secret data are 
    preferred: AES is bitsliced, ChaCha20 and Poly1305 use only arithmetic, the S-boxes 
    of DES are evaluated with shifts of constants; RC4 cannot be implemented this way. 
    The documentation of each module says what holds for it. Hardware instructions 
    (AES-NI) and SIMD instructions are not used.

<span id="conv-threads"></span>
### Thread safety

No module has global mutable data. The modules can be loaded into several independent 
Lua states of the same process that run in different OS threads. A key object, stream 
object or carray belongs to its Lua state.

<!-- ---------------------------------------------------------------------------------------- -->
##   Building
<!-- ---------------------------------------------------------------------------------------- -->

With [LuaRocks](https://luarocks.org) from the repository root, each module rock first, 
then the meta rock:

```
luarocks make rockspecs/cipher.aes-scm-0.rockspec
luarocks make rockspecs/cipher.rc4-scm-0.rockspec
luarocks make rockspecs/cipher.chacha20-scm-0.rockspec
luarocks make rockspecs/cipher.des-scm-0.rockspec
luarocks make rockspecs/cipher-scm-0.rockspec
```

No external library is needed, only a C compiler (gcc, clang, MSVC, MinGW). The 
rockspecs are in *rockspecs/*: *cipher.\<name\>-\<version\>.rockspec* for the module 
rocks, *cipher-\<version\>.rockspec* for the meta rock, each as release and as *scm-0*.
*rockspecs/setversion.lua \<version\>* (run in *rockspecs/*) sets the version of all 
release rockspecs and the *_VERSION* of the meta module.

Without LuaRocks, the Makefile in *src* builds the modules into 
*src/build/lua$(LUA_VERSION)/cipher/* (*make* builds all modules, *make aes*, *make rc4*,
*make chacha20* or *make des* one of them; settings can be overridden in 
*src/sandbox.mk*), and 
*src/activate.sh* sets the Lua paths for using the modules and the meta module from the 
source tree:

```
cd src
make LUA_VERSION=5.4 COPTS=-I/usr/include/lua5.4
. activate.sh
```

Source layout: *src/cipher.lua* (meta module), *src/\<name\>/* (the C sources of a 
module), *src/common/* (sources compiled into every module: *util.h*, *compat-5.3.\**, 
*carray_capi.h*, and *data.h* with the handling of string and carray data that all 
modules share). The tests are in *tests/\<name\>/* and are run from that directory, 
e.g. *cd tests/aes; lua test01.lua*; *tests/cipher/test01.lua* tests the meta module. 
Two test helper modules are shared by the tests of all modules: *cipher_testcarray* 
(read-only and non-resizable carrays) and *cipher_multistate* (several Lua states in 
parallel threads), installed with *luarocks make tests/cipher_testcarray-scm-0.rockspec*
and *luarocks make tests/cipher_multistate-scm-0.rockspec* (or *make testcarray* and 
*make multistate* in *src*); tests that need them are skipped if they are not installed.
