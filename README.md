# lua-cipher 
[![Licence](http://img.shields.io/badge/Licence-MIT-brightgreen.svg)](LICENSE)
[![build status](https://github.com/osch/lua-cipher/workflows/test/badge.svg)](https://github.com/osch/lua-cipher/actions/workflows/test.yml)
[![Install](https://img.shields.io/badge/Install-LuaRocks-brightgreen.svg)](https://luarocks.org/modules/osch/cipher)

<!-- ---------------------------------------------------------------------------------------- -->

Symmetric ciphers for [Lua], each in self-contained C code without an external crypto 
library, all with the same API: in one call or as a stream, for Lua strings and 
[carray] objects. A carray is read directly from its buffer, without copying, and a 
carray given as last argument of a call receives the output in place: it is appended.

| Module                                   | Cipher                                        |
|------------------------------------------|-----------------------------------------------|
| [cipher.aes](./doc/aes.md)               | AES-128/192/256: ECB, CBC, CFB, CFB8, OFB, CTR, GCM |
| [cipher.chacha20](./doc/chacha20.md)     | ChaCha20, XChaCha20, ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305, Poly1305 |
| [cipher.des](./doc/des.md)               | DES, Triple DES (two and three keys): ECB, CBC, CFB, CFB8, OFB, CTR |
| [cipher.rc4](./doc/rc4.md)               | RC4 (ARCFOUR), RC4-drop[n]                    |

Each module is a rock of its own that needs nothing but Lua; the meta rock *cipher* 
installs all of them and the module *cipher*, which loads them on first access: 
*require("cipher").aes* is *require("cipher.aes")*.

   * [Documentation](./doc/README.md#lua-cipher-documentation)
   * [cipher.aes](./doc/aes.md#cipheraes-documentation)
   * [cipher.chacha20](./doc/chacha20.md#cipherchacha20-documentation)
   * [cipher.des](./doc/des.md#cipherdes-documentation)
   * [cipher.rc4](./doc/rc4.md#cipherrc4-documentation)

[Lua]:          https://www.lua.org
[carray]:       https://github.com/osch/lua-carray

<!-- ---------------------------------------------------------------------------------------- -->

## First Example

 ```lua
local aes = require("cipher.aes")    -- or: require("cipher").aes

-- keys of 16, 24 or 32 bytes; in real use the key comes from a key derivation function,
-- the IV is random and new for each message (lua-cipher has no random number generator)
local key = "0123456789abcdef0123456789abcdef"
local iv  = "fedcba9876543210"

-- one call: the default mode "cbc" with PKCS#7 padding, as "openssl enc -aes-256-cbc"
local text = string.rep("lua-cipher encrypts strings and carrays. ", 100)
local encrypted = aes.encrypt(text, key, { iv = iv })
assert(aes.decrypt(encrypted, key, { iv = iv }) == text)

-- other modes: "ecb", "cfb", "cfb8", "ofb", "ctr" and "gcm"; GCM authenticates the
-- ciphertext and additional data, the tag is the second result
local nonce = "unique nonce"                          -- 12 bytes, never twice per key
local ct, tag = aes.encrypt(text, key, { mode = "gcm", iv = nonce, aad = "header" })
assert(aes.decrypt(ct, key, { mode = "gcm", iv = nonce, aad = "header", tag = tag }) == text)
local ok, err = pcall(aes.decrypt, ct, key, { mode = "gcm", iv = nonce, aad = "other", tag = tag })
assert(not ok and err == "authentication failed")

-- streaming: data in pieces
local e = aes.encryptor(key, { iv = iv })
local parts = {}
for i = 1, 10 do
    parts[#parts + 1] = e:update("line " .. i .. "\n")   -- string, or nil if nothing yet
end
parts[#parts + 1] = e:finish()
local d = aes.decryptor(key, { iv = iv })
local out = {}
for _, part in ipairs(parts) do
    out[#out + 1] = d:update(part)
end
out[#out + 1] = d:finish()
assert(table.concat(out):match("^line 1\nline 2\n"))

-- a key object: the key schedule computed once; and the raw block function
local k = aes.newkey(key)
assert(aes.decrypt(encrypted, k, { iv = iv }) == text)
assert(k:decryptblock(k:encryptblock("sixteen byte blk")) == "sixteen byte blk")

-- carray objects are read without copying; a carray as last argument receives the output
-- in place: it is appended, and the carray is returned
local carray = require("carray")
local src = carray.new("char"):append(text)
local buf = carray.new("char")
assert(aes.encrypt(src, key, { iv = iv }, buf) == buf)
src:reset()                                -- empty, keeps the capacity for reuse
aes.decrypt(buf, key, { iv = iv }, src)
assert(src:tostring() == text)

-- cipher.chacha20: ChaCha20-Poly1305 of RFC 8439 (32 byte keys, 12 byte nonces; 24 byte
-- nonces give XChaCha20-Poly1305), with the same API as AES-GCM, and ChaCha20 alone
local chacha20 = require("cipher.chacha20")   -- or: require("cipher").chacha20
local cnonce = "chacha nonce"                         -- 12 bytes, never twice per key
local cct, ctag = chacha20.encrypt(text, key, { iv = cnonce, aad = "header" })
assert(chacha20.decrypt(cct, key, { iv = cnonce, aad = "header", tag = ctag }) == text)
local cs = chacha20.crypt(text, key, { iv = "stream nonce", counter = 1 })
assert(chacha20.crypt(cs, key, { iv = "stream nonce", counter = 1 }) == text)

-- cipher.des: DES and Triple DES for legacy formats, with the API of cipher.aes
local des = require("cipher.des")             -- or: require("cipher").des
local key3 = "a 24 byte Triple DES key"
local d3 = des.encrypt(text, key3, { iv = "8 bytes!" })   -- cbc, as "openssl enc -des-ede3-cbc"
assert(des.decrypt(d3, key3, { iv = "8 bytes!" }) == text)

-- cipher.rc4: for legacy formats; encryption and decryption are the same operation
local rc4 = require("cipher.rc4")             -- or: require("cipher").rc4
local r = rc4.crypt(text, "secret key")
assert(rc4.crypt(r, "secret key") == text)
local st = rc4.new("secret key", { drop = 768 })   -- RC4-drop[768], as a stream
assert(rc4.crypt(st:crypt(text), "secret key", { drop = 768 }) == text)
```

<!-- ---------------------------------------------------------------------------------------- -->

## Installation

```
luarocks install cipher              # all modules and the meta module cipher
luarocks install cipher.aes          # only cipher.aes
luarocks install cipher.chacha20     # only cipher.chacha20
luarocks install cipher.des          # only cipher.des
luarocks install cipher.rc4          # only cipher.rc4
```

No external library is needed, only a C compiler. The modules work with Lua 5.1 up to 
5.5 and LuaJIT; [carray] is optional. For building from source see 
[Building](./doc/README.md#building).

<!-- ---------------------------------------------------------------------------------------- -->

## Security Notes

lua-cipher implements the ciphers, not a protocol: keys, IVs and nonces come from the 
caller. AES is bitsliced (no table lookups, no branches on secret data, adapted from 
BearSSL), but portable C without AES-NI; the limits of this are described in 
[Implementation and Side Channels](./doc/aes.md#implementation-and-side-channels). 
ChaCha20 and Poly1305 use only arithmetic, without tables 
([cipher.chacha20](./doc/chacha20.md#implementation-and-side-channels)), and the DES 
S-boxes are evaluated without tables as well 
([cipher.des](./doc/des.md#implementation-and-side-channels)). RC4 and DES are broken and
Triple DES is deprecated: they are only meant for legacy formats. See also 
[Security](./doc/README.md#conv-security).

<!-- ---------------------------------------------------------------------------------------- -->
