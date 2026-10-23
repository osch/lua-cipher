local des = require("cipher.des")

-- DES and Triple DES are only for reading and writing legacy formats. Keys of 8 bytes
-- (DES), 16 bytes (two key Triple DES: K1, K2, K1) or 24 bytes (three key Triple DES);
-- the parity bits are ignored. The IV is 8 bytes, random and new for each message.
local key  = "0123456789abcdefFEDCBA98"            -- 24 bytes: Triple DES (EDE)
local iv   = "8 bytes!"
local text = string.rep("Triple DES in Lua. ", 100)

-- one call: the default mode "cbc" with PKCS#7 padding, as "openssl enc -des-ede3-cbc"
local encrypted = des.encrypt(text, key, { iv = iv })
assert(#encrypted == #text + 8 - #text % 8)
assert(des.decrypt(encrypted, key, { iv = iv }) == text)

-- the other modes: "ecb", "cfb", "cfb8", "ofb", "ctr" (no padding except ecb)
local ctr = des.encrypt(text, key, { mode = "ctr", iv = iv })
assert(#ctr == #text and des.decrypt(ctr, key, { mode = "ctr", iv = iv }) == text)

-- single DES with an 8 byte key, e.g. the example of FIPS 81
local block = des.encrypt("Now is t", "\1\35\69\103\137\171\205\239", { mode = "ecb", padding = "none" })
assert(block == "\63\164\14\138\152\77\72\21")

-- streaming: data in pieces
local e = des.encryptor(key, { iv = iv })
local parts = {}
for i = 1, 10 do
    parts[#parts + 1] = e:update("line " .. i .. "\n")   -- string, or nil if nothing yet
end
parts[#parts + 1] = e:finish()                           -- the last block with the padding
local d = des.decryptor(key, { iv = iv })
local out = {}
for _, part in ipairs(parts) do
    out[#out + 1] = d:update(part)
end
out[#out + 1] = d:finish()
assert(table.concat(out):match("^line 1\nline 2\n"))

-- a key object: the key schedule computed once, and the block function
local k = des.newkey(key)
assert(des.decrypt(encrypted, k, { iv = iv }) == text)
assert(k:decryptblock(k:encryptblock("8 bytes!")) == "8 bytes!")

-- carray objects are read without copying; a carray as last argument receives the output
-- in place: it is appended, and the carray is returned
local hasCarray, carray = pcall(require, "carray")
if hasCarray then
    local buf = carray.new("char")
    assert(des.encrypt(carray.new("char"):append(text), key, { iv = iv }, buf) == buf)
    local back = carray.new("char")
    des.decrypt(buf, key, { iv = iv }, back)
    assert(back:tostring() == text)
end

print("cipher.des " .. des._VERSION .. ": OK.")
