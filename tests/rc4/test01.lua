-- cipher.rc4 with string data: the test vectors of RFC 6229 (all key lengths and
-- offsets, also as drop counts), one-shot function, streams (also fed byte by byte),
-- option and argument errors.

local rc4 = require("cipher.rc4")

local vectors = dofile("vectors.lua")

local format = string.format

local function PRINT(s)
    print(s.." ("..debug.getinfo(2).currentline..")")
end
local function assertError(pattern, f, ...)
    local ok, err = pcall(f, ...)
    assert(not ok, "error expected")
    assert(tostring(err):find(pattern, 1, true), format("unexpected error message: %s", tostring(err)))
end

local function fromhex(h)
    return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

local function newRandom(seed)
    local x = seed
    return function(n)
        x = (x * 16807) % 2147483647
        return x % n
    end
end

local function randomBytes(n, seed)
    local rnd = newRandom(seed or 1)
    local t = {}
    for i = 1, n do
        t[i] = string.char(rnd(256))
    end
    return table.concat(t)
end

PRINT("==================================================================================")
do
    PRINT(format("cipher.rc4 %s, version() %s", rc4._VERSION, rc4.version()))
    assert(type(rc4._VERSION) == "string" and rc4.version() == rc4._VERSION)
    assert(getmetatable(rc4) == "cipher.rc4")
end
PRINT("==================================================================================")
do
    -- RFC 6229: the keystream (encryption of zero bytes) at the offsets 0 .. 4096
    local zeros = ("\0"):rep(4112)
    for _, v in ipairs(vectors) do
        local key = fromhex(v.key)
        local ks = rc4.crypt(zeros, key)
        assert(#ks == #zeros)
        for _, s in ipairs(v.stream) do
            local off, expect = s[1], fromhex(s[2])
            assert(ks:sub(off + 1, off + 16) == expect, format("key %s offset %d", v.key, off))
            -- RC4-drop[off]: the keystream starts at the offset
            assert(rc4.crypt(("\0"):rep(16), key, { drop = off }) == expect)
            local st = rc4.new(key, { drop = off })
            assert(st:crypt(("\0"):rep(16)) == expect)
        end
        -- streams: byte by byte and in pieces
        for _, chunk in ipairs({ 1, 2, 3, 7, 16, 100, 1000, 5000 }) do
            local st = rc4.new(key)
            local out = {}
            for i = 1, #zeros, chunk do
                out[#out + 1] = st:crypt(zeros:sub(i, i + chunk - 1))
            end
            assert(table.concat(out) == ks)
        end
        PRINT(format("RFC 6229 key %-66s ok (%d offsets)", v.key, #v.stream))
    end
end
PRINT("==================================================================================")
do
    -- encryption and decryption are the same operation
    local data = randomBytes(100000, 5)
    for _, n in ipairs({ 1, 5, 16, 32, 255, 256 }) do
        local key = randomBytes(n, n)
        local c = rc4.crypt(data, key)
        assert(c ~= data and #c == #data)
        assert(rc4.crypt(c, key) == data)
        assert(rc4.crypt(c, key, { drop = 768 }) ~= data)
        assert(rc4.crypt(rc4.crypt(data, key, { drop = 3072 }), key, { drop = 3072 }) == data)
        -- the keystream of a stream object continues across calls
        local st = rc4.new(key)
        local rnd = newRandom(n)
        local parts, pos = {}, 1
        while pos <= #data do
            local len = rnd(2000)
            local r = st:crypt(data:sub(pos, pos + len - 1))
            assert(type(r) == "string" and #r == math.min(len, #data - pos + 1))
            parts[#parts + 1] = r
            pos = pos + len
        end
        assert(table.concat(parts) == c)
    end
    -- drop: the first bytes of the keystream are discarded
    local key = "Key"
    local ks = rc4.crypt(("\0"):rep(1100), key)
    for _, d in ipairs({ 0, 1, 255, 256, 257, 1024 }) do
        assert(rc4.crypt(("\0"):rep(76), key, { drop = d }) == ks:sub(d + 1, d + 76))
    end
    -- the classic examples ("Key", "Wiki", "Secret")
    assert(rc4.crypt("Plaintext", "Key") == fromhex("bbf316e8d940af0ad3"))
    assert(rc4.crypt("pedia", "Wiki") == fromhex("1021bf0420"))
    assert(rc4.crypt("Attack at dawn", "Secret") == fromhex("45a01f645fc35b383552544b9bf5"))
    -- empty data, numbers
    assert(rc4.crypt("", "k") == "")
    assert(rc4.new("k"):crypt("") == "")
    assert(rc4.crypt(1234, "k") == rc4.crypt("1234", "k"))
end
PRINT("==================================================================================")
do
    -- argument and option errors
    assertError("invalid key length (0)", rc4.crypt, "x", "")
    assertError("invalid key length (257)", rc4.crypt, "x", ("k"):rep(257))
    assertError("invalid key length (0)", rc4.new, "")
    assertError("string or carray expected, got no value", rc4.crypt, "x")
    assertError("string or carray expected, got number", rc4.new, 12345)
    assertError("string or carray expected, got nil", rc4.crypt, nil, "k")
    assertError("string or carray expected, got table", rc4.crypt, {}, "k")
    assertError("invalid drop value", rc4.crypt, "x", "k", { drop = -1 })
    assertError("invalid drop value", rc4.crypt, "x", "k", { drop = 1.5 })
    assertError("invalid drop value", rc4.new, "k", { drop = "768" })
    assertError("unknown option 'skip'", rc4.crypt, "x", "k", { skip = 1 })
    assertError("option names must be strings", rc4.new, "k", { 1 })
    assertError("option 'out' is not supported: pass the carray as the last argument", rc4.crypt,
                "x", "k", { out = {} })
    assertError("table or carray expected, got string", rc4.crypt, "x", "k", "drop")
    assertError("table expected, got number", rc4.new, "k", 768)
    local st = rc4.new("k")
    assertError("string or carray expected, got no value", st.crypt, st)
    assertError("bad argument #1", st.crypt, {}, "x")
    assert(tostring(st):match("^cipher%.rc4%.stream: "))
    assert(getmetatable(st) == "cipher.rc4.stream")
end
PRINT("==================================================================================")
do
    -- larger data: 10 MB
    local data = randomBytes(65536, 21):rep(160)
    local t0 = os.clock()
    local c = rc4.crypt(data, "a key of 16 byte")
    local t1 = os.clock()
    assert(rc4.crypt(c, "a key of 16 byte") == data)
    PRINT(format("10 MB: %.2f s", t1 - t0))
end
PRINT("==================================================================================")
print("OK.")
