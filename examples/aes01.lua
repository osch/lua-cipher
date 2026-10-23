local aes = require("cipher.aes")

-- keys of 16, 24 or 32 bytes (AES-128, AES-192, AES-256); in real use the key comes from
-- a key derivation function and the IV is random and new for each message
local key  = "0123456789abcdef0123456789abcdef"
local iv   = "fedcba9876543210"
local text = string.rep("AES in Lua. ", 100)

-- one call: the default mode "cbc" with PKCS#7 padding, as "openssl enc -aes-256-cbc"
local encrypted = aes.encrypt(text, key, { iv = iv })
assert(#encrypted == #text + 16 - #text % 16)
assert(aes.decrypt(encrypted, key, { iv = iv }) == text)

-- wrong padding (e.g. a wrong key) raises an error
local ok, err = pcall(aes.decrypt, encrypted, ("x"):rep(32), { iv = iv })
assert(not ok)

-- the other modes: "ecb", "cfb", "cfb8", "ofb", "ctr" (no padding: the output has the
-- length of the input)
local ctr = aes.encrypt(text, key, { mode = "ctr", iv = iv })
assert(#ctr == #text and aes.decrypt(ctr, key, { mode = "ctr", iv = iv }) == text)

-- authenticated encryption with GCM: a 12 byte IV (nonce, never twice with the same key),
-- additional authenticated data, the tag as second result
local nonce = "unique nonce"
local ct, tag = aes.encrypt("secret message", key, { mode = "gcm", iv = nonce, aad = "header" })
assert(#ct == 14 and #tag == 16)
assert(aes.decrypt(ct, key, { mode = "gcm", iv = nonce, aad = "header", tag = tag }) == "secret message")
assert(not pcall(aes.decrypt, ct, key, { mode = "gcm", iv = nonce, aad = "other", tag = tag }))

-- streaming: data in pieces
local e = aes.encryptor(key, { iv = iv })
local parts = {}
for i = 1, 10 do
    parts[#parts + 1] = e:update("line " .. i .. "\n")   -- string, or nil if nothing yet
end
parts[#parts + 1] = e:finish()                           -- the last block with the padding
local d = aes.decryptor(key, { iv = iv })
local out = {}
for _, part in ipairs(parts) do
    out[#out + 1] = d:update(part)
end
out[#out + 1] = d:finish()
assert(table.concat(out):match("^line 1\nline 2\n"))

-- GCM streams: the tag from finish() (and tag()); the decryptor gets the expected tag as
-- option or as argument of finish()
local ge = aes.encryptor(key, { mode = "gcm", iv = nonce })
local c1 = ge:update("part 1, ")
local c2, tag2 = ge:finish("part 2")
local gd = aes.decryptor(key, { mode = "gcm", iv = nonce })
assert(gd:update(c1) .. gd:finish(c2, tag2) == "part 1, part 2")

-- a key object: the key schedule computed once, for many messages with the same key,
-- and the block function for modes of one's own
local k = aes.newkey(key)
assert(aes.decrypt(aes.encrypt(text, k, { iv = iv }), k, { iv = iv }) == text)
local block = k:encryptblock("exactly16bytes!!")
assert(#block == 16 and k:decryptblock(block) == "exactly16bytes!!")

-- carray objects are read without copying; a carray as last argument receives the output
-- in place: it is appended, and the carray is returned
local hasCarray, carray = pcall(require, "carray")
if hasCarray then
    local src = carray.new("char"):append(text)
    local buf = carray.new("char")
    assert(aes.encrypt(src, key, { iv = iv }, buf) == buf)
    local back = carray.new("char"):append("> ")
    aes.decrypt(buf, key, { iv = iv }, back)
    assert(back:tostring() == "> " .. text)
    back:reset()                                         -- empty, keeps the capacity
    local d2 = aes.decryptor(key, { iv = iv })
    d2:update(buf, back)                                 -- stream methods: carray last
    d2:finish(nil, back)
    assert(back:tostring() == text)
end

print("cipher.aes " .. aes._VERSION .. ": OK.")
