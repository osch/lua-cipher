-- cipher.des with string data: the known answer tests of NIST SP 800-20 (variable
-- plaintext, inverse permutation, variable key, permutation operation, substitution
-- table), the TDEA multi-block message tests of NIST CAVP (ECB, CBC, CFB64, CFB8, OFB with
-- two and three keys), the examples of FIPS 81 and SP 800-67, one-shot functions, streams
-- (also fed byte by byte), key objects, PKCS#7 padding and its errors, CTR, option and
-- argument errors.

local des = require("cipher.des")

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

-- the bytes of s with the lowest bit (the parity bit of DES keys) flipped
local function flipParity(s)
    return (s:gsub(".", function(c)
        local b = c:byte()
        return string.char(b % 2 == 0 and b + 1 or b - 1)
    end))
end

-- streaming helpers: feed data in chunks of the given size
local function streamEncrypt(data, key, opts, chunk)
    local e = des.encryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = e:update(data:sub(i, i + chunk - 1))
        assert(r == nil or (type(r) == "string" and #r > 0))
        out[#out + 1] = r
    end
    local r, tag = e:finish()
    assert(type(r) == "string" and tag == nil)
    out[#out + 1] = r
    return table.concat(out)
end

local function streamDecrypt(data, key, opts, chunk)
    local d = des.decryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = d:update(data:sub(i, i + chunk - 1))
        assert(r == nil or (type(r) == "string" and #r > 0))
        out[#out + 1] = r
    end
    out[#out + 1] = d:finish()
    return table.concat(out)
end

local CHUNKS = { 1, 2, 3, 7, 8, 9, 15, 16, 17, 24, 25, 100 }

PRINT("==================================================================================")
do
    PRINT(format("cipher.des %s, version() %s", des._VERSION, des.version()))
    assert(type(des._VERSION) == "string" and des.version() == des._VERSION)
    assert(getmetatable(des) == "cipher.des")
end
PRINT("==================================================================================")
do
    -- NIST SP 800-20: the known answer tests of DES (single blocks, ECB)
    for _, name in ipairs({ "vartext", "invperm", "varkey", "permop", "subtab" }) do
        local list = vectors.KAT[name]
        for i, v in ipairs(list) do
            local key, pt, ct = fromhex(v[1]), fromhex(v[2]), fromhex(v[3])
            local k = des.newkey(key)
            assert(k:encryptblock(pt) == ct, name .. " " .. i)
            assert(k:decryptblock(ct) == pt, name .. " " .. i)
            assert(des.encrypt(pt, key, { mode = "ecb", padding = "none" }) == ct, name .. " " .. i)
            assert(des.decrypt(ct, key, { mode = "ecb", padding = "none" }) == pt, name .. " " .. i)
            -- as Triple DES with K1 = K2 = K3 (keying option 3) and K1 = K2 (16 bytes)
            assert(des.newkey(key:rep(3)):encryptblock(pt) == ct, name .. " " .. i)
            assert(des.newkey(key:rep(2)):decryptblock(ct) == pt, name .. " " .. i)
            -- the parity bits are ignored
            assert(des.newkey(flipParity(key)):encryptblock(pt) == ct, name .. " " .. i)
        end
        PRINT(format("SP 800-20 %-8s: %d vectors ok", name, #list))
    end
end
PRINT("==================================================================================")
do
    -- NIST CAVP: TDEA multi-block message tests, two and three keys
    local counts = {}
    for i, v in ipairs(vectors.MMT) do
        local key, pt, ct = fromhex(v.key), fromhex(v.plaintext), fromhex(v.ciphertext)
        local opts = { mode = v.mode, iv = v.iv and fromhex(v.iv) }
        if v.mode == "ecb" or v.mode == "cbc" then
            opts.padding = "none"
        end
        local k = des.newkey(key)
        if v.decrypt then
            assert(des.decrypt(ct, key, opts) == pt, i)
            assert(des.decrypt(ct, k, opts) == pt, i)
        else
            assert(des.encrypt(pt, key, opts) == ct, i)
            assert(des.encrypt(pt, k, opts) == ct, i)
        end
        for _, chunk in ipairs({ 1, 3, 8, 13 }) do
            assert(streamEncrypt(pt, key, opts, chunk) == ct, i)
            assert(streamDecrypt(ct, k, opts, chunk) == pt, i)
        end
        local name = format("%s, %d byte keys", v.mode, #key)
        counts[name] = (counts[name] or 0) + 1
    end
    local names = {}
    for name in pairs(counts) do names[#names + 1] = name end
    table.sort(names)
    for _, name in ipairs(names) do
        PRINT(format("CAVP TDEA MMT %-20s: %d vectors ok", name, counts[name]))
    end
end
PRINT("==================================================================================")
do
    -- FIPS 81, Appendix B: ECB, CBC, CFB (64 bit), OFB (64 bit) and 8 bit CFB
    local v = vectors.FIPS81
    local key, iv, pt = fromhex(v.key), fromhex(v.iv), fromhex(v.plaintext)
    assert(pt == "Now is the time for all ")
    for _, mode in ipairs({ "ecb", "cbc", "cfb", "ofb" }) do
        local opts = { mode = mode, iv = mode ~= "ecb" and iv or nil }
        if mode == "ecb" or mode == "cbc" then opts.padding = "none" end
        local ct = fromhex(v[mode])
        assert(des.encrypt(pt, key, opts) == ct, mode)
        assert(des.decrypt(ct, key, opts) == pt, mode)
        for _, chunk in ipairs(CHUNKS) do
            assert(streamEncrypt(pt, key, opts, chunk) == ct, mode)
            assert(streamDecrypt(ct, key, opts, chunk) == pt, mode)
        end
    end
    local p8, c8 = fromhex(v.cfb8.plaintext), fromhex(v.cfb8.ciphertext)
    assert(des.encrypt(p8, key, { mode = "cfb8", iv = iv }) == c8)
    assert(des.decrypt(c8, key, { mode = "cfb8", iv = iv }) == p8)
    PRINT("FIPS 81 examples ok")
    -- SP 800-67 Rev. 1, Appendix B: TDEA with three keys
    local s = vectors.SP80067
    local key3, pt3, ct3 = fromhex(s.key), fromhex(s.plaintext), fromhex(s.ciphertext)
    assert(des.encrypt(pt3, key3, { mode = "ecb", padding = "none" }) == ct3)
    assert(des.newkey(key3):decryptblock(ct3) == pt3)
    PRINT("SP 800-67 example ok")
end
PRINT("==================================================================================")
do
    -- Triple DES: EDE of the single DES operations, keying options 1 to 3
    local k1, k2, k3 = randomBytes(8, 1), randomBytes(8, 2), randomBytes(8, 3)
    local d1, d2, d3 = des.newkey(k1), des.newkey(k2), des.newkey(k3)
    local blocks = randomBytes(64, 4)
    local ede3 = d3:encryptblock(d2:decryptblock(d1:encryptblock(blocks)))
    assert(des.newkey(k1 .. k2 .. k3):encryptblock(blocks) == ede3)
    assert(des.newkey(k1 .. k2 .. k3):decryptblock(ede3) == blocks)
    local ede2 = d1:encryptblock(d2:decryptblock(d1:encryptblock(blocks)))
    assert(des.newkey(k1 .. k2):encryptblock(blocks) == ede2)
    assert(des.newkey(k1 .. k2 .. k1):encryptblock(blocks) == ede2)
    assert(des.newkey(k1 .. k2):decryptblock(ede2) == blocks)
    -- K1 = K2 = K3 and K1 = K2 are single DES
    assert(des.newkey(k1 .. k1 .. k1):encryptblock(blocks) == d1:encryptblock(blocks))
    assert(des.newkey(k1 .. k1):encryptblock(blocks) == d1:encryptblock(blocks))
    assert(des.newkey(k1 .. k1 .. k3):encryptblock(blocks) == d3:encryptblock(blocks))
    -- weak keys are accepted: their encryption is its own inverse
    local weak = fromhex("0101010101010101")
    local w = des.newkey(weak)
    assert(w:encryptblock(w:encryptblock(blocks)) == blocks)
    -- a key object from a key object
    local d4 = des.newkey(d1)
    assert(d4 ~= d1 and d4:encryptblock(blocks) == d1:encryptblock(blocks))
    assert(d1:encryptblock("") == "")
    PRINT("Triple DES ok")
end
PRINT("==================================================================================")
do
    -- PKCS#7 padding (default of ecb and cbc): 1 to 8 bytes of the value n
    local key, iv = randomBytes(24, 5), randomBytes(8, 6)
    for _, mode in ipairs({ "ecb", "cbc" }) do
        local opts = { mode = mode, iv = mode == "cbc" and iv or nil }
        local raw = with(opts, { padding = "none" })
        for n = 0, 40 do
            local pt = randomBytes(n, n + 10)
            local ct = des.encrypt(pt, key, opts)
            assert(#ct == (math.floor(n / 8) + 1) * 8)
            local pad = 8 - n % 8
            assert(des.decrypt(ct, key, raw) == pt .. string.char(pad):rep(pad))
            assert(des.encrypt(pt .. string.char(pad):rep(pad), key, raw) == ct)
            assert(des.decrypt(ct, key, opts) == pt)
            assert(des.encrypt(pt, key, with(opts, { padding = "pkcs7" })) == ct)
            for _, chunk in ipairs({ 1, 5, 8, 9, 32 }) do
                assert(streamEncrypt(pt, key, opts, chunk) == ct)
                assert(streamDecrypt(ct, key, opts, chunk) == pt)
            end
        end
        -- invalid padding
        local function encRaw(s) return des.encrypt(s, key, raw) end
        local block = ("x"):rep(7)
        for _, last in ipairs({ 0, 9, 16, 255 }) do
            assertError("invalid padding", des.decrypt, encRaw(block .. string.char(last)), key, opts)
        end
        assertError("invalid padding", des.decrypt, encRaw(("x"):rep(5) .. "\2\3\3"), key, opts)
        assertError("invalid padding", des.decrypt, encRaw(("x"):rep(6) .. "\3\3"), key, opts)
        assertError("invalid padding", des.decrypt, encRaw("x" .. ("\7"):rep(5) .. "\8\7"), key, opts)
        assert(des.decrypt(encRaw(("\7"):rep(8)), key, opts) == "\7")
        assert(des.decrypt(encRaw(("\8"):rep(8)), key, opts) == "")
        assert(des.decrypt(encRaw(("y"):rep(8) .. ("\8"):rep(8)), key, opts) == ("y"):rep(8))
        assert(des.decrypt(encRaw(("x"):rep(6) .. "\2\2"), key, opts) == ("x"):rep(6))
        assert(des.decrypt(encRaw(("x"):rep(7) .. "\1"), key, opts) == ("x"):rep(7))
        assertError("invalid padding", des.decrypt, "", key, opts)
        assert(des.decrypt("", key, raw) == "")
        assert(des.encrypt("", key, raw) == "")
        -- lengths that are no multiple of the block size
        assertError("data length (9) is not a multiple of the block size (8)", des.decrypt,
                    ("a"):rep(9), key, opts)
        assertError("data length (7) is not a multiple of the block size (8)", des.decrypt,
                    ("a"):rep(7), key, raw)
        assertError("data length (1) is not a multiple of the block size (8)", des.encrypt,
                    "a", key, raw)
        -- streams: the error of finish() closes the stream
        local d = des.decryptor(key, opts)
        assert(d:update(encRaw(block .. "\0")) == nil)
        assertError("invalid padding", d.finish, d)
        assertError("decryptor is closed", d.update, d, "x")
        local e = des.encryptor(key, raw)
        assert(e:update(("a"):rep(12)) == des.encrypt(("a"):rep(8), key, raw))
        assertError("data length (12) is not a multiple of the block size (8)", e.finish, e)
        assertError("encryptor is closed", e.finish, e)
        d = des.decryptor(key, opts)
        d:update("abc")
        assertError("data length (12) is not a multiple of the block size (8)", d.finish, d,
                    ("x"):rep(9))
        d = des.decryptor(key, opts)
        assertError("invalid padding", d.finish, d)
    end
end
PRINT("==================================================================================")
do
    -- one-shot and streams give the same results for larger data, all modes and key sizes
    local data = randomBytes(30000, 7)
    for _, mode in ipairs({ "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr" }) do
        for _, klen in ipairs({ 8, 16, 24 }) do
            local key = randomBytes(klen, klen)
            local opts = { mode = mode, iv = mode ~= "ecb" and randomBytes(8, 5) or nil }
            local n = (mode == "cfb8") and 3000 or #data
            local pt = data:sub(1, n)
            local ct = des.encrypt(pt, key, opts)
            assert(ct ~= pt and #ct >= #pt)
            assert(des.decrypt(ct, key, opts) == pt)
            local rnd = newRandom(klen + #mode)
            local e = des.encryptor(key, opts)
            local d = des.decryptor(key, opts)
            local parts, back, pos = {}, {}, 1
            while pos <= n do
                local len = rnd(1000)
                parts[#parts + 1] = e:update(pt:sub(pos, pos + len - 1))
                pos = pos + len
            end
            parts[#parts + 1] = e:finish()
            assert(table.concat(parts) == ct)
            pos = 1
            while pos <= #ct do
                local len = rnd(1000)
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
    -- CTR: the counter is the whole block as 64 bit big endian number and wraps around
    local key = randomBytes(24, 9)
    local k = des.newkey(key)
    local ivs = {
        { fromhex("ffffffffffffffff"), fromhex("0000000000000000") },
        { fromhex("00000000ffffffff"), fromhex("0000000100000000") },
        { fromhex("0123456789abcdef"), fromhex("0123456789abcdf0") },
    }
    for _, v in ipairs(ivs) do
        local ks = des.encrypt(("\0"):rep(16), key, { mode = "ctr", iv = v[1] })
        assert(ks == k:encryptblock(v[1]) .. k:encryptblock(v[2]))
    end
    -- OFB and CFB keystreams from the block function
    local iv = randomBytes(8, 11)
    local o1 = k:encryptblock(iv)
    local o2 = k:encryptblock(o1)
    assert(des.encrypt(("\0"):rep(16), key, { mode = "ofb", iv = iv }) == o1 .. o2)
    assert(des.encrypt(("\0"):rep(16), key, { mode = "cfb", iv = iv }) == o1 .. k:encryptblock(o1))
    -- the stream modes: any prefix of the data gives the prefix of the result
    local pt = randomBytes(50, 12)
    for _, mode in ipairs({ "cfb", "cfb8", "ofb", "ctr" }) do
        local ct = des.encrypt(pt, key, { mode = mode, iv = iv })
        for n = 0, #pt do
            assert(des.encrypt(pt:sub(1, n), key, { mode = mode, iv = iv }) == ct:sub(1, n), mode)
            assert(des.decrypt(ct:sub(1, n), key, { mode = mode, iv = iv }) == pt:sub(1, n), mode)
        end
    end
end
PRINT("==================================================================================")
do
    -- stream results: update() gives nil while there is no output
    local key, iv = randomBytes(16, 13), randomBytes(8, 14)
    local e = des.encryptor(key, { iv = iv })                     -- cbc, pkcs7
    assert(e:update("") == nil)
    assert(e:update(("a"):rep(7)) == nil)
    local r1 = e:update("bc")
    assert(#r1 == 8)
    local r2 = e:finish()
    assert(#r2 == 8 and r1 .. r2 == des.encrypt(("a"):rep(7) .. "bc", key, { iv = iv }))
    assertError("encryptor is closed", e.update, e, "x")
    assertError("encryptor is closed", e.finish, e)
    assertError("mode 'cbc' has no tag", e.tag, e)
    -- decryption with padding holds back the last block
    local ct = des.encrypt(("z"):rep(16), key, { iv = iv, padding = "none" })
    local d = des.decryptor(key, { iv = iv, padding = "none" })
    assert(d:update(ct:sub(1, 8)) == ("z"):rep(8))
    d = des.decryptor(key, { iv = iv })
    assert(d:update(ct:sub(1, 8)) == nil)
    assert(d:update(ct:sub(9, 12)) == ("z"):rep(8))
    -- finish(chunk) is update(chunk) and finish()
    local all = des.encrypt(("q"):rep(20), key, { iv = iv })
    e = des.encryptor(key, { iv = iv })
    assert(e:finish(("q"):rep(20)) == all)
    d = des.decryptor(key, { iv = iv })
    assert(d:finish(all) == ("q"):rep(20))
    -- stream modes: the output has the length of the input
    for _, mode in ipairs({ "ctr", "cfb", "cfb8", "ofb" }) do
        e = des.encryptor(key, { mode = mode, iv = iv })
        assert(e:update("") == nil)
        assert(#e:update("abc") == 3)
        local f, tag = e:finish()
        assert(f == "" and tag == nil)
        assertError(format("mode '%s' has no tag", mode), e.tag, e)
        assert(tostring(e):match("^cipher%.des%.encryptor: "))
    end
    -- no tags
    d = des.decryptor(key, { iv = iv })
    assertError("mode 'cbc' has no tag", d.finish, d, nil, ("t"):rep(16))
    assert(d:finish(all) == ("q"):rep(20))
    assert(tostring(d):match("^cipher%.des%.decryptor: "))
    assert(getmetatable(d) == "cipher.des.decryptor")
    assert(getmetatable(des.encryptor(key, { iv = iv })) == "cipher.des.encryptor")
    local k = des.newkey(key)
    assert(getmetatable(k) == "cipher.des.key")
    assert(tostring(k):match("^cipher%.des%.key: "))
end
PRINT("==================================================================================")
do
    -- argument and option errors
    local key, iv = ("k"):rep(8), ("i"):rep(8)
    for _, n in ipairs({ 0, 1, 7, 9, 15, 17, 23, 25, 32 }) do
        assertError(format("invalid key length (%d)", n), des.encrypt, "x", ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), des.encryptor, ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), des.decryptor, ("k"):rep(n), { iv = iv })
        assertError(format("invalid key length (%d)", n), des.newkey, ("k"):rep(n))
    end
    assertError("string, carray or des key expected, got no value", des.encrypt, "x")
    assertError("string, carray or des key expected, got number", des.newkey, 12345678)
    assertError("string, carray or des key expected, got table", des.decryptor, {})
    assertError("string or carray expected, got nil", des.encrypt, nil, key)
    assertError("string or carray expected, got table", des.decrypt, {}, key)
    assertError("bad argument #1", des.encrypt, true, key)
    assert(des.encrypt(1234, key, { mode = "ctr", iv = iv }) == des.encrypt("1234", key, { mode = "ctr", iv = iv }))

    assertError("option 'iv' is required for mode 'cbc'", des.encrypt, "x", key)
    assertError("option 'iv' is required for mode 'cbc'", des.encryptor, key)
    assertError("option 'iv' is required for mode 'ctr'", des.decrypt, "x", key, { mode = "ctr" })
    assertError("option 'iv' is not supported by mode 'ecb'", des.encrypt, "x", key, { mode = "ecb", iv = iv })
    for _, mode in ipairs({ "cbc", "cfb", "cfb8", "ofb", "ctr" }) do
        for _, n in ipairs({ 0, 1, 7, 9, 12, 16 }) do
            assertError(format("invalid iv length (%d)", n), des.encrypt, "x", key, { mode = mode, iv = ("i"):rep(n) })
        end
    end
    assertError("invalid iv value", des.encrypt, "x", key, { iv = 12345678 })
    assertError("invalid iv value", des.encrypt, "x", key, { iv = {} })
    assertError("invalid mode value", des.encrypt, "x", key, { mode = "gcm", iv = iv })
    assertError("invalid mode value", des.encrypt, "x", key, { mode = "CBC", iv = iv })
    assertError("invalid mode value", des.encrypt, "x", key, { mode = 1 })
    assertError("invalid padding value", des.encrypt, "x", key, { iv = iv, padding = "zero" })
    assertError("invalid padding value", des.encrypt, "x", key, { iv = iv, padding = true })
    assertError("option 'padding' is not supported by mode 'ctr'", des.encrypt, "x", key,
                { mode = "ctr", iv = iv, padding = "pkcs7" })
    assert(des.encrypt("x", key, { mode = "ctr", iv = iv, padding = "none" }) ==
           des.encrypt("x", key, { mode = "ctr", iv = iv }))
    assertError("unknown option 'aad'", des.encrypt, "x", key, { iv = iv, aad = "a" })
    assertError("unknown option 'tag'", des.decrypt, ("x"):rep(8), key, { iv = iv, tag = ("t"):rep(16) })
    assertError("unknown option 'taglen'", des.encrypt, "x", key, { iv = iv, taglen = 16 })
    assertError("unknown option 'foo'", des.encrypt, "x", key, { iv = iv, foo = 1 })
    assertError("unknown option 'IV'", des.encrypt, "x", key, { IV = iv })
    assertError("option names must be strings", des.encrypt, "x", key, { iv = iv, [1] = 2 })
    assertError("option 'out' is not supported: pass the carray as the last argument", des.encrypt,
                "x", key, { iv = iv, out = {} })
    assertError("table or carray expected, got string", des.encrypt, "x", key, "cbc")
    assertError("table expected, got string", des.encryptor, key, "cbc")
    assertError("bad argument #3", des.encrypt, "x", key, { foo = 1 })
    assertError("bad argument #2", des.encryptor, key, { foo = 1 })
    -- options: nil and an empty table are no options
    assert(des.encrypt("x", key, { mode = "ecb" }, nil) == des.encrypt("x", key, { mode = "ecb" }))
    assert(des.encrypt("x", key, { mode = "ecb" }) == des.encrypt("x", key, { mode = "ecb", padding = "pkcs7" }))
    -- block functions of key objects
    local k = des.newkey(key)
    assertError("data length (7) is not a multiple of the block size (8)", k.encryptblock, k, ("x"):rep(7))
    assertError("data length (9) is not a multiple of the block size (8)", k.decryptblock, k, ("x"):rep(9))
    assertError("string or carray expected, got no value", k.encryptblock, k)
    assertError("bad argument #1", k.encryptblock, {}, ("x"):rep(8))
    assertError("bad argument #1", des.encryptor(key, { iv = iv }).update, k, "x")
    -- a stream method with the object of the other kind
    local e = des.encryptor(key, { iv = iv })
    assertError("bad argument #1", des.decryptor(key, { iv = iv }).update, e, "x")
    assertError("string or carray expected, got no value", e.update, e)
    -- argument errors do not close the stream
    assert(#e:finish("abc") == 8)
end
PRINT("==================================================================================")
do
    -- larger data: 2 MB
    local data = randomBytes(65536, 21):rep(32)
    for _, klen in ipairs({ 8, 24 }) do
        local key, iv = randomBytes(klen, 22), randomBytes(8, 23)
        for _, mode in ipairs({ "cbc", "ctr" }) do
            local t0 = os.clock()
            local ct = des.encrypt(data, key, { mode = mode, iv = iv })
            local t1 = os.clock()
            assert(des.decrypt(ct, key, { mode = mode, iv = iv }) == data)
            local t2 = os.clock()
            PRINT(format("%s %s 2 MB: encrypt %.2f s, decrypt %.2f s", klen == 8 and "DES " or "3DES",
                         mode, t1 - t0, t2 - t1))
        end
    end
end
PRINT("==================================================================================")
print("OK.")
