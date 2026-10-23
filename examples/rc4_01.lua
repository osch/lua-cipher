local rc4 = require("cipher.rc4")

-- RC4 is broken and only for reading and writing legacy formats (e.g. old PDF
-- encryption); encryption and decryption are the same operation
local key  = "a key of 1 to 256 bytes"
local text = string.rep("RC4 in Lua. ", 100)
local encrypted = rc4.crypt(text, key)
assert(#encrypted == #text)
assert(rc4.crypt(encrypted, key) == text)

-- RC4-drop[n]: the first n bytes of the keystream are discarded
local dropped = rc4.crypt(text, key, { drop = 768 })
assert(rc4.crypt(dropped, key, { drop = 768 }) == text)

-- streaming: the keystream continues from call to call
local st = rc4.new(key)
local parts = {}
for i = 1, #text, 100 do
    parts[#parts + 1] = st:crypt(text:sub(i, i + 99))
end
assert(table.concat(parts) == encrypted)

-- carray objects are read without copying; a carray as last argument receives the output
-- in place: it is appended, and the carray is returned
local hasCarray, carray = pcall(require, "carray")
if hasCarray then
    local buf = carray.new("char")
    assert(rc4.crypt(carray.new("char"):append(text), key, buf) == buf)
    assert(buf:tostring() == encrypted)
    local st2 = rc4.new(key)
    buf:reset()
    st2:crypt(encrypted, buf)
    assert(buf:tostring() == text)
end

print("cipher.rc4 " .. rc4._VERSION .. ": OK.")
