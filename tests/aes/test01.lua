-- cipher.aes with string data: the test vectors of FIPS 197, NIST SP 800-38A and the GCM
-- specification for all modes, one-shot functions, streams (also fed byte by byte), key
-- objects, PKCS#7 padding and its errors, GCM tags, option and argument errors.

local aes = require("cipher.aes")

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
local function tohex(s)
    return (s:gsub(".", function(c) return format("%02x", c:byte()) end))
end

-- deterministic pseudo random numbers (Park-Miller), exact also with doubles (Lua 5.1)
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

local function with(base, extra)
    local o = {}
    for k, v in pairs(base or {}) do o[k] = v end
    for k, v in pairs(extra or {}) do o[k] = v end
    return o
end

-- streaming helpers: feed data in chunks of the given size; returns output [, tag]
local function streamEncrypt(data, key, opts, chunk)
    local e = aes.encryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = e:update(data:sub(i, i + chunk - 1))
        assert(r == nil or (type(r) == "string" and #r > 0))
        out[#out + 1] = r
    end
    local r, tag = e:finish()
    assert(type(r) == "string")
    out[#out + 1] = r
    if tag then
        assert(e:tag() == tag)
    end
    return table.concat(out), tag
end

local function streamDecrypt(data, key, opts, chunk, tag)
    local d = aes.decryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = d:update(data:sub(i, i + chunk - 1))
        assert(r == nil or (type(r) == "string" and #r > 0))
        out[#out + 1] = r
    end
    out[#out + 1] = d:finish(nil, tag)
    return table.concat(out)
end

local CHUNKS = { 1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 100, 1000 }

PRINT("==================================================================================")
do
    PRINT(format("cipher.aes %s, version() %s", aes._VERSION, aes.version()))
    assert(type(aes._VERSION) == "string" and aes.version() == aes._VERSION)
    assert(getmetatable(aes) == "cipher.aes")
end
PRINT("==================================================================================")
do
    -- FIPS 197, Appendix C: single blocks with key objects and with ECB
    for _, v in ipairs(vectors.FIPS197) do
        local key, pt, ct = fromhex(v.key), fromhex(v.plaintext), fromhex(v.ciphertext)
        local k = aes.newkey(key)
        assert(k:encryptblock(pt) == ct)
        assert(k:decryptblock(ct) == pt)
        assert(aes.encrypt(pt, key, { mode = "ecb", padding = "none" }) == ct)
        assert(aes.decrypt(ct, key, { mode = "ecb", padding = "none" }) == pt)
        assert(aes.encrypt(pt, k, { mode = "ecb", padding = "none" }) == ct)
        -- several blocks at once: each one on its own
        assert(k:encryptblock(pt .. ct .. pt) == ct .. k:encryptblock(ct) .. ct)
        assert(k:decryptblock(ct .. ct .. ct .. ct .. ct) == pt:rep(5))
        assert(k:encryptblock("") == "")
        -- a key object from a key object
        local k2 = aes.newkey(k)
        assert(k2 ~= k and k2:encryptblock(pt) == ct)
        PRINT(format("FIPS 197 AES-%d: %s", #key * 8, tohex(ct)))
    end
end
PRINT("==================================================================================")
do
    -- NIST SP 800-38A, Appendix F: ECB, CBC, CFB8, CFB128, OFB, CTR with all key sizes
    for _, v in ipairs(vectors.SP80038A) do
        local key, pt, ct = fromhex(v.key), fromhex(v.plaintext), fromhex(v.ciphertext)
        local opts = { mode = v.mode, iv = v.iv and fromhex(v.iv) }
        if v.mode == "ecb" or v.mode == "cbc" then
            opts.padding = "none"
        end
        assert(aes.encrypt(pt, key, opts) == ct, v.name)
        assert(aes.decrypt(ct, key, opts) == pt, v.name)
        local k = aes.newkey(key)
        assert(aes.encrypt(pt, k, opts) == ct, v.name)
        assert(aes.decrypt(ct, k, opts) == pt, v.name)
        for _, chunk in ipairs(CHUNKS) do
            assert(streamEncrypt(pt, key, opts, chunk) == ct, v.name)
            assert(streamDecrypt(ct, key, opts, chunk) == pt, v.name)
            assert(streamEncrypt(pt, k, opts, chunk) == ct, v.name)
        end
        -- the stream modes: any prefix of the data gives the prefix of the result
        if v.mode ~= "ecb" and v.mode ~= "cbc" then
            for n = 0, #pt do
                assert(aes.encrypt(pt:sub(1, n), key, opts) == ct:sub(1, n), v.name)
                assert(aes.decrypt(ct:sub(1, n), key, opts) == pt:sub(1, n), v.name)
            end
        end
        PRINT(format("SP 800-38A %-12s ok", v.name))
    end
end
PRINT("==================================================================================")
do
    -- GCM specification, test cases 1-18 (the vectors of NIST SP 800-38D)
    for _, v in ipairs(vectors.GCM) do
        local key, iv, aad = fromhex(v.key), fromhex(v.iv), fromhex(v.aad)
        local pt, ct, tag = fromhex(v.plaintext), fromhex(v.ciphertext), fromhex(v.tag)
        local opts = { mode = "gcm", iv = iv, aad = aad }
        local c, t = aes.encrypt(pt, key, opts)
        assert(c == ct and t == tag, v.case)
        assert(aes.decrypt(ct, key, with(opts, { tag = tag })) == pt, v.case)
        for _, chunk in ipairs(CHUNKS) do
            local c2, t2 = streamEncrypt(pt, key, opts, chunk)
            assert(c2 == ct and t2 == tag, v.case)
            -- the expected tag as option or as argument of finish()
            assert(streamDecrypt(ct, key, with(opts, { tag = tag }), chunk) == pt, v.case)
            assert(streamDecrypt(ct, key, opts, chunk, tag) == pt, v.case)
        end
        -- truncated tags: the first taglen bytes
        for _, n in ipairs({ 4, 8, 12, 13, 14, 15, 16 }) do
            local c3, t3 = aes.encrypt(pt, key, with(opts, { taglen = n }))
            assert(c3 == ct and t3 == tag:sub(1, n), v.case)
            assert(aes.decrypt(ct, key, with(opts, { tag = t3 })) == pt, v.case)
            assert(aes.decrypt(ct, key, with(opts, { tag = t3, taglen = n })) == pt, v.case)
        end
        -- any change is detected
        local bad = string.char((tag:byte(1) + 1) % 256) .. tag:sub(2)
        assertError("authentication failed", aes.decrypt, ct, key, with(opts, { tag = bad }))
        assertError("authentication failed", aes.decrypt, ct, key, with(opts, { tag = tag, aad = aad .. "x" }))
        if #ct > 0 then
            local ct2 = ct:sub(1, -2) .. string.char((ct:byte(-1) + 128) % 256)
            assertError("authentication failed", aes.decrypt, ct2, key, with(opts, { tag = tag }))
            assertError("authentication failed", aes.decrypt, ct:sub(1, -2), key, with(opts, { tag = tag }))
        end
        assertError("authentication failed", aes.decrypt, ct .. "\0", key, with(opts, { tag = tag }))
        local d = aes.decryptor(key, opts)
        d:update(ct)
        assertError("authentication failed", d.finish, d, nil, bad)
        assertError("decryptor is closed", d.finish, d)
        PRINT(format("GCM test case %2d ok (key %d, iv %d, aad %d, data %d bytes)", v.case, #key, #iv,
                     #aad, #pt))
    end
end
PRINT("==================================================================================")
do
    -- PKCS#7 padding (default of ecb and cbc): 1 to 16 bytes of the value n
    local key, iv = randomBytes(16, 3), randomBytes(16, 4)
    for _, mode in ipairs({ "ecb", "cbc" }) do
        local opts = { mode = mode, iv = mode == "cbc" and iv or nil }
        local raw = with(opts, { padding = "none" })
        for n = 0, 70 do
            local pt = randomBytes(n, n + 10)
            local ct = aes.encrypt(pt, key, opts)
            assert(#ct == (math.floor(n / 16) + 1) * 16)
            local pad = 16 - n % 16
            assert(aes.decrypt(ct, key, raw) == pt .. string.char(pad):rep(pad))
            assert(aes.encrypt(pt .. string.char(pad):rep(pad), key, raw) == ct)
            assert(aes.decrypt(ct, key, opts) == pt)
            assert(aes.encrypt(pt, key, with(opts, { padding = "pkcs7" })) == ct)
            for _, chunk in ipairs({ 1, 5, 16, 17, 64 }) do
                assert(streamEncrypt(pt, key, opts, chunk) == ct)
                assert(streamDecrypt(ct, key, opts, chunk) == pt)
            end
        end
        -- invalid padding
        local function encRaw(s) return aes.encrypt(s, key, raw) end
        local block = ("x"):rep(15)
        for _, last in ipairs({ 0, 17, 255 }) do
            assertError("invalid padding", aes.decrypt, encRaw(block .. string.char(last)), key, opts)
        end
        assertError("invalid padding", aes.decrypt, encRaw(("x"):rep(13) .. "\2\3\3"), key, opts)
        assertError("invalid padding", aes.decrypt, encRaw(("x"):rep(14) .. "\3\3"), key, opts)
        assertError("invalid padding", aes.decrypt, encRaw("x" .. ("\15"):rep(13) .. "\16\15"), key, opts)
        assert(aes.decrypt(encRaw(("\15"):rep(16)), key, opts) == "\15")
        assert(aes.decrypt(encRaw(("\16"):rep(16)), key, opts) == "")
        assert(aes.decrypt(encRaw(("y"):rep(16) .. ("\16"):rep(16)), key, opts) == ("y"):rep(16))
        assert(aes.decrypt(encRaw(("x"):rep(14) .. "\2\2"), key, opts) == ("x"):rep(14))
        assert(aes.decrypt(encRaw(("x"):rep(15) .. "\1"), key, opts) == ("x"):rep(15))
        assertError("invalid padding", aes.decrypt, "", key, opts)
        assert(aes.decrypt("", key, raw) == "")
        assert(aes.encrypt("", key, raw) == "")
        -- lengths that are no multiple of the block size
        assertError("data length (17) is not a multiple of the block size (16)", aes.decrypt,
                    ("a"):rep(17), key, opts)
        assertError("data length (15) is not a multiple of the block size (16)", aes.decrypt,
                    ("a"):rep(15), key, raw)
        assertError("data length (1) is not a multiple of the block size (16)", aes.encrypt,
                    "a", key, raw)
        -- streams: the error of finish() closes the stream
        local d = aes.decryptor(key, opts)
        assert(d:update(encRaw(block .. "\0")) == nil)
        assertError("invalid padding", d.finish, d)
        assertError("decryptor is closed", d.update, d, "x")
        local e = aes.encryptor(key, raw)
        assert(e:update(("a"):rep(20)) == aes.encrypt(("a"):rep(16), key, raw))
        assertError("data length (20) is not a multiple of the block size (16)", e.finish, e)
        assertError("encryptor is closed", e.finish, e)
        d = aes.decryptor(key, opts)
        d:update("abc")
        assertError("data length (20) is not a multiple of the block size (16)", d.finish, d,
                    ("x"):rep(17))
        d = aes.decryptor(key, opts)
        assertError("invalid padding", d.finish, d)
    end
end
PRINT("==================================================================================")
do
    -- one-shot and streams give the same results for larger data, all modes and key sizes
    local data = randomBytes(100000, 7)
    for _, mode in ipairs({ "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr", "gcm" }) do
        for _, klen in ipairs({ 16, 24, 32 }) do
            local key = randomBytes(klen, klen)
            local opts = { mode = mode, iv = mode ~= "ecb" and randomBytes(mode == "gcm" and 12 or 16, 5) or nil,
                           aad = mode == "gcm" and "header" or nil }
            local n = (mode == "cfb8") and 5000 or #data
            local pt = data:sub(1, n)
            local ct, tag = aes.encrypt(pt, key, opts)
            assert(ct ~= pt and #ct >= #pt)
            local dopts = with(opts, { tag = tag })
            assert(aes.decrypt(ct, key, dopts) == pt)
            local rnd = newRandom(klen + #mode)
            local e = aes.encryptor(key, opts)
            local d = aes.decryptor(key, dopts)
            local parts, back, pos = {}, {}, 1
            while pos <= n do
                local len = rnd(3000)
                parts[#parts + 1] = e:update(pt:sub(pos, pos + len - 1))
                pos = pos + len
            end
            local last, tag2 = e:finish()
            parts[#parts + 1] = last
            assert(table.concat(parts) == ct and tag2 == tag)
            pos = 1
            while pos <= #ct do
                local len = rnd(3000)
                back[#back + 1] = d:update(ct:sub(pos, pos + len - 1))
                pos = pos + len
            end
            back[#back + 1] = d:finish()
            assert(table.concat(back) == pt)
        end
        PRINT(format("%-4s: one-shot = stream", mode))
    end
end
PRINT("==================================================================================")
do
    -- CTR: the counter is the whole block as 128 bit big endian number and wraps around
    local key = randomBytes(16, 9)
    local k = aes.newkey(key)
    local ivs = {
        { fromhex("ffffffffffffffffffffffffffffffff"), fromhex("00000000000000000000000000000000") },
        { fromhex("000000000000000000000000ffffffff"), fromhex("00000000000000000000000100000000") },
        { fromhex("00000000000000ffffffffffffffffff"), fromhex("00000000000001000000000000000000") },
    }
    for _, v in ipairs(ivs) do
        local ks = aes.encrypt(("\0"):rep(32), key, { mode = "ctr", iv = v[1] })
        assert(ks == k:encryptblock(v[1]) .. k:encryptblock(v[2]))
    end
    -- OFB and CFB keystreams from the block function
    local iv = randomBytes(16, 11)
    local o1 = k:encryptblock(iv)
    local o2 = k:encryptblock(o1)
    assert(aes.encrypt(("\0"):rep(32), key, { mode = "ofb", iv = iv }) == o1 .. o2)
    local c1 = aes.encrypt(("\0"):rep(16), key, { mode = "cfb", iv = iv })
    assert(c1 == o1)
    assert(aes.encrypt(("\0"):rep(32), key, { mode = "cfb", iv = iv }) == o1 .. k:encryptblock(o1))
    -- a 96 bit GCM IV starts with the counter 2 (J0 = IV || 1, data from inc32(J0))
    local giv = randomBytes(12, 12)
    local g = aes.encrypt(("\0"):rep(16), key, { mode = "gcm", iv = giv })
    assert(g == k:encryptblock(giv .. "\0\0\0\2"))
end
PRINT("==================================================================================")
do
    -- stream results: update() gives nil while there is no output
    local key, iv = randomBytes(16, 13), randomBytes(16, 14)
    local e = aes.encryptor(key, { iv = iv })                     -- cbc, pkcs7
    assert(e:update("") == nil)
    assert(e:update(("a"):rep(15)) == nil)
    local r1 = e:update("bc")
    assert(#r1 == 16)
    local r2 = e:finish()
    assert(#r2 == 16 and r1 .. r2 == aes.encrypt(("a"):rep(15) .. "bc", key, { iv = iv }))
    assertError("encryptor is closed", e.update, e, "x")
    assertError("encryptor is closed", e.finish, e)
    assertError("mode 'cbc' has no tag", e.tag, e)
    -- decryption with padding holds back the last block
    local ct = aes.encrypt(("z"):rep(32), key, { iv = iv, padding = "none" })
    local d = aes.decryptor(key, { iv = iv, padding = "none" })
    assert(d:update(ct:sub(1, 16)) == ("z"):rep(16))
    d = aes.decryptor(key, { iv = iv })
    assert(d:update(ct:sub(1, 16)) == nil)
    assert(d:update(ct:sub(17, 20)) == ("z"):rep(16))
    -- finish(chunk) is update(chunk) and finish()
    local all = aes.encrypt(("q"):rep(40), key, { iv = iv })
    e = aes.encryptor(key, { iv = iv })
    assert(e:finish(("q"):rep(40)) == all)
    d = aes.decryptor(key, { iv = iv })
    assert(d:finish(all) == ("q"):rep(40))
    -- stream modes: the output has the length of the input
    for _, mode in ipairs({ "ctr", "cfb", "cfb8", "ofb", "gcm" }) do
        local opts = { mode = mode, iv = iv }
        e = aes.encryptor(key, opts)
        assert(e:update("") == nil)
        assert(#e:update("abc") == 3)
        local f, tag = e:finish()
        assert(f == "")
        if mode == "gcm" then
            assert(#tag == 16 and e:tag() == tag)
        else
            assert(tag == nil)
            assertError(format("mode '%s' has no tag", mode), e.tag, e)
        end
        assert(tostring(e):match("^cipher%.aes%.encryptor: "))
    end
    -- GCM: the tag only after finish()
    e = aes.encryptor(key, { mode = "gcm", iv = iv, taglen = 12 })
    assertError("the tag is only available after finish()", e.tag, e)
    e:update("data")
    local _, t = e:finish("more")
    assert(#t == 12 and e:tag() == t)
    assert(select(2, aes.encrypt("datamore", key, { mode = "gcm", iv = iv, taglen = 12 })) == t)
    assert(aes.decrypt(aes.encrypt("datamore", key, { mode = "gcm", iv = iv }), key,
                       { mode = "gcm", iv = iv, tag = select(2, aes.encrypt("datamore", key,
                                                                    { mode = "gcm", iv = iv })) })
           == "datamore")
    -- GCM decryptor without a tag
    d = aes.decryptor(key, { mode = "gcm", iv = iv })
    d:update("abc")
    assertError("no tag given for mode 'gcm'", d.finish, d)
    assertError("decryptor is closed", d.finish, d)
    d = aes.decryptor(key, { mode = "gcm", iv = iv, taglen = 12 })
    assertError("tag length contradicts taglen", d.finish, d, nil, ("t"):rep(16))
    assertError("invalid tag length (3)", d.finish, d, nil, "abc")
    d = aes.decryptor(key, { iv = iv })
    assertError("mode 'cbc' has no tag", d.finish, d, nil, ("t"):rep(16))
    assert(tostring(d):match("^cipher%.aes%.decryptor: "))
    assert(getmetatable(d) == "cipher.aes.decryptor")
    assert(getmetatable(aes.encryptor(key, { iv = iv })) == "cipher.aes.encryptor")
    local k = aes.newkey(key)
    assert(getmetatable(k) == "cipher.aes.key")
    assert(tostring(k):match("^cipher%.aes%.key: "))
end
PRINT("==================================================================================")
do
    -- the GCM IV: any length from 1 byte; 12 bytes is the usual one
    local key = randomBytes(32, 15)
    local seen = {}
    for _, n in ipairs({ 1, 8, 11, 12, 13, 16, 17, 60, 100 }) do
        local c, t = aes.encrypt("plaintext", key, { mode = "gcm", iv = randomBytes(n, 16) })
        assert(aes.decrypt(c, key, { mode = "gcm", iv = randomBytes(n, 16), tag = t }) == "plaintext")
        assert(not seen[t])
        seen[t] = true
    end
    -- AAD only: an authentication tag (GMAC)
    local c, t = aes.encrypt("", key, { mode = "gcm", iv = ("i"):rep(12), aad = randomBytes(1000, 3) })
    assert(c == "" and #t == 16)
    assert(aes.decrypt("", key, { mode = "gcm", iv = ("i"):rep(12), aad = randomBytes(1000, 3), tag = t }) == "")
    assertError("authentication failed", aes.decrypt, "", key,
                { mode = "gcm", iv = ("i"):rep(12), aad = randomBytes(1000, 4), tag = t })
end
PRINT("==================================================================================")
do
    -- argument and option errors
    local key, iv = ("k"):rep(16), ("i"):rep(16)
    for _, n in ipairs({ 0, 1, 15, 17, 23, 25, 31, 33, 64 }) do
        assertError(format("invalid key length (%d)", n), aes.encrypt, "x", ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), aes.encryptor, ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), aes.decryptor, ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), aes.newkey, ("k"):rep(n))
    end
    assertError("string, carray or aes key expected, got no value", aes.encrypt, "x")
    assertError("string, carray or aes key expected, got number", aes.newkey, 1234567890123456)
    assertError("string, carray or aes key expected, got table", aes.decryptor, {})
    assertError("string or carray expected, got nil", aes.encrypt, nil, key)
    assertError("string or carray expected, got table", aes.decrypt, {}, key)
    assertError("bad argument #1", aes.encrypt, true, key)
    assert(aes.encrypt(1234, key, { mode = "ctr", iv = iv }) == aes.encrypt("1234", key, { mode = "ctr", iv = iv }))

    assertError("option 'iv' is required for mode 'cbc'", aes.encrypt, "x", key)
    assertError("option 'iv' is required for mode 'cbc'", aes.encryptor, key)
    assertError("option 'iv' is required for mode 'ctr'", aes.decrypt, "x", key, { mode = "ctr" })
    assertError("option 'iv' is required for mode 'gcm'", aes.decryptor, key, { mode = "gcm" })
    assertError("option 'iv' is not supported by mode 'ecb'", aes.encrypt, "x", key, { mode = "ecb", iv = iv })
    for _, mode in ipairs({ "cbc", "cfb", "cfb8", "ofb", "ctr" }) do
        for _, n in ipairs({ 0, 1, 8, 12, 15, 17, 32 }) do
            assertError(format("invalid iv length (%d)", n), aes.encrypt, "x", key, { mode = mode, iv = ("i"):rep(n) })
        end
    end
    assertError("invalid iv length (0)", aes.encrypt, "x", key, { mode = "gcm", iv = "" })
    assertError("invalid iv value", aes.encrypt, "x", key, { iv = 1234567890123456 })
    assertError("invalid iv value", aes.encrypt, "x", key, { iv = {} })
    assertError("invalid mode value", aes.encrypt, "x", key, { mode = "xts", iv = iv })
    assertError("invalid mode value", aes.encrypt, "x", key, { mode = "CBC", iv = iv })
    assertError("invalid mode value", aes.encrypt, "x", key, { mode = 1 })
    assertError("invalid padding value", aes.encrypt, "x", key, { iv = iv, padding = "zero" })
    assertError("invalid padding value", aes.encrypt, "x", key, { iv = iv, padding = true })
    assertError("option 'padding' is not supported by mode 'ctr'", aes.encrypt, "x", key,
                { mode = "ctr", iv = iv, padding = "pkcs7" })
    assert(aes.encrypt("x", key, { mode = "ctr", iv = iv, padding = "none" }) ==
           aes.encrypt("x", key, { mode = "ctr", iv = iv }))
    assertError("option 'aad' is not supported by mode 'cbc'", aes.encrypt, "x", key, { iv = iv, aad = "a" })
    assertError("option 'taglen' is not supported by mode 'ctr'", aes.encrypt, "x", key,
                { mode = "ctr", iv = iv, taglen = 16 })
    assertError("option 'tag' is not supported by mode 'cbc'", aes.decrypt, ("x"):rep(16), key,
                { iv = iv, tag = ("t"):rep(16) })
    assertError("option 'tag' is not supported by encrypt()", aes.encrypt, "x", key,
                { mode = "gcm", iv = iv, tag = ("t"):rep(16) })
    assertError("option 'tag' is not supported by encryptor()", aes.encryptor, key,
                { mode = "gcm", iv = iv, tag = ("t"):rep(16) })
    assertError("option 'tag' is required for mode 'gcm'", aes.decrypt, "x", key, { mode = "gcm", iv = iv })
    for _, n in ipairs({ 0, 1, 3, 5, 7, 9, 10, 11, 17, 32 }) do
        assertError("invalid taglen value", aes.encrypt, "x", key, { mode = "gcm", iv = iv, taglen = n })
        assertError(format("invalid tag length (%d)", n), aes.decrypt, "x", key,
                    { mode = "gcm", iv = iv, tag = ("t"):rep(n) })
    end
    assertError("invalid taglen value", aes.encrypt, "x", key, { mode = "gcm", iv = iv, taglen = 12.5 })
    assertError("tag length contradicts taglen", aes.decrypt, "x", key,
                { mode = "gcm", iv = iv, tag = ("t"):rep(16), taglen = 12 })
    assertError("unknown option 'foo'", aes.encrypt, "x", key, { iv = iv, foo = 1 })
    assertError("unknown option 'IV'", aes.encrypt, "x", key, { IV = iv })
    assertError("option names must be strings", aes.encrypt, "x", key, { iv = iv, [1] = 2 })
    assertError("option 'out' is not supported: pass the carray as the last argument", aes.encrypt,
                "x", key, { iv = iv, out = {} })
    assertError("table or carray expected, got string", aes.encrypt, "x", key, "cbc")
    assertError("table expected, got string", aes.encryptor, key, "cbc")
    assertError("bad argument #3", aes.encrypt, "x", key, { foo = 1 })
    assertError("bad argument #2", aes.encryptor, key, { foo = 1 })
    -- options: nil and an empty table are no options
    assert(aes.encrypt("x", key, { mode = "ecb" }, nil) == aes.encrypt("x", key, { mode = "ecb" }))
    assert(aes.encrypt("x", key, { mode = "ecb" }) == aes.encrypt("x", key, { mode = "ecb", padding = "pkcs7" }))
    -- block functions of key objects
    local k = aes.newkey(key)
    assertError("data length (15) is not a multiple of the block size (16)", k.encryptblock, k, ("x"):rep(15))
    assertError("data length (17) is not a multiple of the block size (16)", k.decryptblock, k, ("x"):rep(17))
    assertError("string or carray expected, got no value", k.encryptblock, k)
    assertError("bad argument #1", k.encryptblock, {}, ("x"):rep(16))
    assertError("bad argument #1", aes.encryptor(key, { iv = iv }).update, k, "x")
    -- a stream method with the object of the other kind
    local e = aes.encryptor(key, { iv = iv })
    assertError("bad argument #1", aes.decryptor(key, { iv = iv }).update, e, "x")
    assertError("string or carray expected, got no value", e.update, e)
    -- argument errors do not close the stream
    assert(#e:finish("abc") == 16)
end
PRINT("==================================================================================")
do
    -- larger data: 10 MB in all modes that process blocks in parallel
    local data = randomBytes(65536, 21):rep(160)
    local key, iv = randomBytes(32, 22), randomBytes(16, 23)
    for _, mode in ipairs({ "cbc", "ctr", "gcm" }) do
        local t0 = os.clock()
        local ct, tag = aes.encrypt(data, key, { mode = mode, iv = iv })
        local t1 = os.clock()
        assert(aes.decrypt(ct, key, { mode = mode, iv = iv, tag = tag }) == data)
        local t2 = os.clock()
        PRINT(format("%s 10 MB: encrypt %.2f s, decrypt %.2f s", mode, t1 - t0, t2 - t1))
    end
end
PRINT("==================================================================================")
print("OK.")
