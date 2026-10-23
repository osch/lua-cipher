# cipher.rc4 Documentation
<!-- ---------------------------------------------------------------------------------------- -->
##   Contents
<!-- ---------------------------------------------------------------------------------------- -->

   * [Overview](#overview)
   * [Data and Keys](#data-and-keys)
   * [Module Functions](#module-functions)
        * [rc4.crypt()](#rc4_crypt)
        * [rc4.new()](#rc4_new)
        * [rc4.version()](#rc4_version)
        * [rc4._VERSION](#rc4__VERSION)
   * [Options](#options)
   * [Stream Methods](#stream-methods)
        * [stream:crypt()](#stream_crypt)
   * [Security](#security)
   * [Compatibility](#compatibility)
   * [Errors](#errors)
   * [Thread safety / multiple Lua states](#thread-safety--multiple-lua-states)
   * [Building](#building)

<!-- ---------------------------------------------------------------------------------------- -->
##   Overview
<!-- ---------------------------------------------------------------------------------------- -->

The [Lua] module *cipher.rc4* of [lua-cipher](../README.md) provides the stream cipher 
RC4 (also known as ARCFOUR), in self-contained C code without an external library. 
**RC4 is broken** (its keystream has statistical biases that allow attacks on many 
protocols, see [RFC 7465]): it is meant for reading and writing legacy formats that use 
it, e.g. the encryption of older PDF files, not for protecting new data.

  * [rc4.crypt()](#rc4_crypt) encrypts or decrypts the whole data in one call: 
    encryption and decryption are the same operation, the data xor the keystream.
  * [rc4.new()](#rc4_new) creates a stream object whose [crypt()](#stream_crypt) 
    continues the keystream from call to call.
  * The option [*drop*](#option_drop) discards the first bytes of the keystream 
    ("RC4-drop[n]", e.g. 768 or 3072 bytes).

Data may be Lua strings or [carray] objects, see [Data and Keys](#data-and-keys). Errors
are raised with *error()*, see [Errors](#errors). The module follows the 
[Common Conventions](README.md#common-conventions) of lua-cipher for stream cipher 
modules.

The module name to require is *"cipher.rc4"*; it is also available as 
*require("cipher").rc4* through the [meta module](README.md#the-meta-module-cipher):

```lua
local rc4 = require("cipher.rc4")

local encrypted = rc4.crypt("Plaintext", "Key")
assert(encrypted == "\xbb\xf3\x16\xe8\xd9\x40\xaf\x0a\xd3")   -- Lua 5.2+ escapes
assert(rc4.crypt(encrypted, "Key") == "Plaintext")
```

This module works with Lua 5.1 up to 5.5 and LuaJIT. The [carray] module is optional: 
cipher.rc4 neither links against it nor requires it, carray objects are recognized 
through the [Carray C API]. The rock *cipher.rc4* depends on nothing but Lua and can be
installed without the other rocks of lua-cipher.

The metatable names (*getmetatable()*) are *"cipher.rc4"* and *"cipher.rc4.stream"*; 
the latter also appears in *tostring()* of the stream objects.

[Lua]:          https://www.lua.org
[RFC 6229]:     https://www.rfc-editor.org/rfc/rfc6229
[RFC 7465]:     https://www.rfc-editor.org/rfc/rfc7465
[carray]:       https://github.com/osch/lua-carray
[Carray C API]: https://github.com/lua-capis/lua-carray-capi

<!-- ---------------------------------------------------------------------------------------- -->
##   Data and Keys
<!-- ---------------------------------------------------------------------------------------- -->

The data (argument *data* of [rc4.crypt()](#rc4_crypt) and *chunk* of 
[stream:crypt()](#stream_crypt)) may be a Lua string (or a number, converted as in the 
string library) or a carray with elements of 1 byte size, read directly from its buffer 
without copying. The **key** is a string or carray of 1 to 256 bytes (*invalid key 
length (N)* otherwise); all of its bytes are used, as by the key scheduling of RC4 (a 
40 bit key is 5 bytes, a 128 bit key 16 bytes).

The result is a Lua string of the length of the input, or, with a carray *out* as last 
argument, the output is appended to it and *out* is returned (see 
[Output](README.md#output-string-or-carray) in the Common Conventions): 
*rc4.crypt(data, key, out)* is *rc4.crypt(data, key, nil, out)*, *stream:crypt(chunk, 
out)*. *out* must not be the input carray: encryption in place is not supported.

<!-- ---------------------------------------------------------------------------------------- -->
##   Module Functions
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="rc4_crypt">**`rc4.crypt(data, key[, opts][, out])
  `**</span>
  
  Returns *data* xor the RC4 keystream of *key* (after *drop* bytes): the encryption of 
  plaintext, and the decryption of ciphertext. The result is a string of the length of 
  *data* (*""* for empty data), or appended to the carray *out*, which is returned.
  
  * *data* - string or carray, see [Data and Keys](#data-and-keys).
  * *key* - string or carray of 1 to 256 bytes.
  * *opts* - optional table with the [option](#options) *drop*.
  * *out* - optional carray; may also be given as third argument when there are no 
    options.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="rc4_new">**`rc4.new(key[, opts])
  `**</span>
  
  Creates a stream object with the state of RC4 after the key scheduling (and after 
  discarding *drop* bytes), see [Stream Methods](#stream-methods). The state (258 bytes)
  is part of the userdata and is overwritten with zeros when the object is collected.
  
  * *key* - string or carray of 1 to 256 bytes.
  * *opts* - optional table with the [option](#options) *drop*.

<!-- ---------------------------------------------------------------------------------------- -->

* <span id="rc4_version">**`rc4.version()
  `**</span>
  
  Returns the version of the module, the same as [rc4._VERSION](#rc4__VERSION): there is 
  no external library.

* <span id="rc4__VERSION">**`rc4._VERSION
  `**</span>
  
  The version of the module cipher.rc4 as string, e.g. *"0.0.1"*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Options
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="option_drop">**`drop`**</span> - the number of keystream bytes to discard 
  before the data, an integer >= 0 (default 0). Recommended values in the literature are 
  768 and 3072 ("RC4-drop[768]", "RC4-drop[3072]"); formats that use plain RC4 (PDF, 
  WEP, TLS before RFC 7465) need 0. The keystream bytes are generated and thrown away, so
  very large values take time.

Other names raise *unknown option 'name'*.

<!-- ---------------------------------------------------------------------------------------- -->
##   Stream Methods
<!-- ---------------------------------------------------------------------------------------- -->

* <span id="stream_crypt">**`stream:crypt(chunk[, out])
  `**</span>
  
  Returns *chunk* xor the next *#chunk* bytes of the keystream, as string or appended to
  the carray *out*. The calls continue one keystream: the output of all calls 
  concatenated is *rc4.crypt()* of all chunks concatenated. A stream object has no end 
  and needs no *finish()*. An error of *out* (e.g. *cannot resize carray*) is raised 
  before the keystream is advanced.

```lua
local st = rc4.new(key)
for chunk in inputFile:lines(65536) do
    outputFile:write(st:crypt(chunk))
end
```

<!-- ---------------------------------------------------------------------------------------- -->
##   Security
<!-- ---------------------------------------------------------------------------------------- -->

  * RC4 has known biases, especially in the first bytes of the keystream, and related 
    key weaknesses (WEP). Never use the same key for two messages: the xor of two 
    ciphertexts is the xor of the plaintexts. Formats that combine a key with a nonce 
    (e.g. PDF: a hash of the file key and the object number) take care of this.
  * RC4 is inherently not constant time: the state is indexed with secret values, so 
    cache timing reveals information about the key and the keystream. This cannot be 
    avoided without giving up its speed.
  * The state is overwritten with zeros when the stream object is collected and at the 
    end of [rc4.crypt()](#rc4_crypt).

<!-- ---------------------------------------------------------------------------------------- -->
##   Compatibility
<!-- ---------------------------------------------------------------------------------------- -->

The keystream is that of the test vectors of [RFC 6229] (all key lengths and offsets of 
the RFC are in the tests). The test suite compares the output with *openssl enc -rc4* 
and *-rc4-40* (legacy provider of OpenSSL 3), Python's *cryptography* (*ARC4*, only key 
lengths 40 to 256 bits in its list) and *pycryptodome* (*ARC4.new(key, drop=n)*), and 
Perl's *Crypt::RC4* and CryptX (*Crypt::Stream::RC4*, keys of 5 bytes and more); *drop* 
is the same as encrypting *drop* zero bytes first and throwing the result away.

<!-- ---------------------------------------------------------------------------------------- -->
##   Errors
<!-- ---------------------------------------------------------------------------------------- -->

RC4 has no errors of the data; all errors are argument errors, raised with *error()* 
before anything is done: *invalid key length (0)*, *string or carray expected, got 
table*, *invalid drop value*, *unknown option 'name'*, the errors of *out* (see [Output: 
string or carray](README.md#output-string-or-carray)).

<!-- ---------------------------------------------------------------------------------------- -->
##   Thread safety / multiple Lua states
<!-- ---------------------------------------------------------------------------------------- -->

cipher.rc4 has no global mutable data: the module can be loaded into several Lua states 
of the same process, also used in parallel OS threads (one thread per Lua state). Stream
objects belong to their Lua state.

<!-- ---------------------------------------------------------------------------------------- -->
##   Building
<!-- ---------------------------------------------------------------------------------------- -->

With LuaRocks from the repository root:

```
luarocks make rockspecs/cipher.rc4-scm-0.rockspec
```

No external library is needed, only a C compiler. Without LuaRocks, the Makefile in 
*src* builds *src/build/lua$(LUA_VERSION)/cipher/rc4.so* (*make rc4*), and 
*src/activate.sh* sets the Lua paths for using it from the source tree.

The tests are run from the *tests/rc4* directory:

  * *lua test01.lua* - string data: the test vectors of [RFC 6229] (keys of 40 to 256 
    bits, keystream offsets 0 to 4096, also as *drop*), one-shot function and streams 
    with all chunk sizes (also 1 byte), argument errors, 10 MB
  * *lua test02.lua* - carray data and keys, carray output (appending, returned object, 
    errors); read-only and non-resizable carrays with the test helper module 
    *cipher_testcarray* (skipped if carray or the helper is not installed)
  * *lua test03.lua* - several Lua states in parallel threads (test helper module 
    *cipher_multistate*, skipped if it is not installed)
  * *lua test04.lua* - comparison with *openssl enc -rc4*, Python's *cryptography* and 
    *pycryptodome* (helper *test04.py*), Perl's *Crypt::RC4* and *Crypt::Stream::RC4* 
    of CryptX (helper *test04.pl*); each part is skipped if the tool or module is not 
    installed, *CIPHER_TEST_REQUIRE* (e.g. *openssl,pycryptodome,rc4*) makes a skipped 
    part an error
