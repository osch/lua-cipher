-- The meta module cipher: all modules of lua-cipher under one name, each loaded on its
-- first access.
local cipher = require("cipher")

-- cipher.aes is the module "cipher.aes", loaded on first access
local aes = cipher.aes
assert(aes == require("cipher.aes"))

local key = string.rep("k", 32)              -- AES-256 (16, 24 or 32 bytes)
local iv  = string.rep("i", 16)              -- random and new for each message in real use
local text = string.rep("lua-cipher: one API for several ciphers. ", 100)
local encrypted = aes.encrypt(text, key, { iv = iv })          -- mode "cbc", PKCS#7 padding
assert(aes.decrypt(encrypted, key, { iv = iv }) == text)

-- cipher.rc4, cipher.chacha20 and cipher.des likewise
local rc4 = cipher.rc4
assert(rc4 == require("cipher.rc4"))
assert(rc4.crypt(rc4.crypt(text, "secret"), "secret") == text)

local chacha20 = cipher.chacha20                          -- ChaCha20-Poly1305
local nonce = string.rep("n", 12)                         -- never twice with the same key
local ct, tag = chacha20.encrypt(text, key, { iv = nonce })
assert(chacha20.decrypt(ct, key, { iv = nonce, tag = tag }) == text)

local des = cipher.des                                    -- Triple DES with a 24 byte key
local key3 = string.rep("k", 24)
assert(des.decrypt(des.encrypt(text, key3, { iv = "8 bytes!" }), key3, { iv = "8 bytes!" }) == text)

-- the module names this version knows; any other key gives nil
for _, name in ipairs(cipher.names) do
    assert(cipher[name] == require("cipher." .. name))
end
assert(cipher.unknown == nil)

print("cipher " .. cipher._VERSION .. " (" .. table.concat(cipher.names, ", ") .. "): OK.")
