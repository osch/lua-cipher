local chacha20 = require("cipher.chacha20")

-- 32 byte keys; in real use the key comes from a key derivation function and the nonce
-- is new for each message (lua-cipher has no random number generator)
local key   = "0123456789abcdef0123456789abcdef"
local nonce = "unique nonce"                     -- 12 bytes: never twice with the same key
local text  = string.rep("ChaCha20 in Lua. ", 100)

-- authenticated encryption with ChaCha20-Poly1305 (RFC 8439): the ciphertext has the
-- length of the plaintext, the 16 byte tag is the second result
local ct, tag = chacha20.encrypt(text, key, { iv = nonce, aad = "header" })
assert(#ct == #text and #tag == 16)
assert(chacha20.decrypt(ct, key, { iv = nonce, aad = "header", tag = tag }) == text)
local ok, err = pcall(chacha20.decrypt, ct, key, { iv = nonce, aad = "other", tag = tag })
assert(not ok and err:match("authentication failed"))

-- XChaCha20-Poly1305: 24 byte nonces, which may be chosen at random
local xnonce = "a 24 byte random nonce.."
local xct, xtag = chacha20.encrypt(text, key, { iv = xnonce })
assert(chacha20.decrypt(xct, key, { iv = xnonce, tag = xtag }) == text)

-- streaming: data in pieces, the tag from finish(); the decryptor gets the expected tag
-- as option or as argument of finish() (its update() output is not yet authenticated)
local e = chacha20.encryptor(key, { iv = nonce })
local c1 = e:update("part 1, ")
local c2, tag2 = e:finish("part 2")
local d = chacha20.decryptor(key, { iv = nonce })
assert(d:update(c1) .. d:finish(c2, tag2) == "part 1, part 2")

-- the plain stream cipher ChaCha20 (no authentication): encryption and decryption are
-- the same operation; nonces of 12 bytes (RFC 8439), 8 bytes (the original ChaCha20) or
-- 24 bytes (XChaCha20), and the initial block counter
local s = chacha20.crypt(text, key, { iv = nonce, counter = 1 })
assert(chacha20.crypt(s, key, { iv = nonce, counter = 1 }) == text)
local st = chacha20.new(key, { iv = nonce, counter = 1 })
local parts = {}
for i = 1, #text, 100 do
    parts[#parts + 1] = st:crypt(text:sub(i, i + 99))
end
assert(table.concat(parts) == s)

-- the one-time authenticator Poly1305 alone (a 32 byte key, never used twice)
assert(#chacha20.poly1305("message", key) == 16)

-- carray objects are read without copying; a carray as last argument receives the output
-- in place: it is appended, and the carray is returned
local hasCarray, carray = pcall(require, "carray")
if hasCarray then
    local buf = carray.new("char")
    local r, t = chacha20.encrypt(carray.new("char"):append(text), key, { iv = nonce }, buf)
    assert(r == buf and t == select(2, chacha20.encrypt(text, key, { iv = nonce })))
    local back = carray.new("char")
    chacha20.decrypt(buf, key, { iv = nonce, tag = t }, back)
    assert(back:tostring() == text)
end

print("cipher.chacha20 " .. chacha20._VERSION .. ": OK.")
