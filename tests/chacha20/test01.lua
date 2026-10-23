-- cipher.chacha20 with string data: the test vectors of RFC 8439 (block function,
-- encryption, Poly1305, Poly1305 key generation, AEAD) and of draft-irtf-cfrg-xchacha
-- (HChaCha20, XChaCha20, XChaCha20-Poly1305), the 64 bit nonce variant, block counters
-- and their limit, one-shot functions and streams (also fed byte by byte), tags, option
-- and argument errors.

local chacha20 = require("cipher.chacha20")

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

-- a 32 bit number as 4 bytes little endian
local function le32(n)
    local t = {}
    for i = 1, 4 do
        t[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(t)
end

-- streams: feed data in chunks of the given size
local function streamCrypt(data, key, opts, chunk)
    local st = chacha20.new(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = st:crypt(data:sub(i, i + chunk - 1))
        assert(type(r) == "string" and #r == math.min(chunk, #data - i + 1))
        out[#out + 1] = r
    end
    return table.concat(out)
end

local function streamEncrypt(data, key, opts, chunk)
    local e = chacha20.encryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = e:update(data:sub(i, i + chunk - 1))
        assert(type(r) == "string" and #r > 0)
        out[#out + 1] = r
    end
    local r, tag = e:finish()
    assert(r == "" and #tag == 16 and e:tag() == tag)
    return table.concat(out), tag
end

local function streamDecrypt(data, key, opts, chunk, tag)
    local d = chacha20.decryptor(key, opts)
    local out = {}
    for i = 1, #data, chunk do
        local r = d:update(data:sub(i, i + chunk - 1))
        assert(type(r) == "string" and #r > 0)
        out[#out + 1] = r
    end
    out[#out + 1] = d:finish(nil, tag)
    return table.concat(out)
end

local CHUNKS = { 1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000 }

PRINT("==================================================================================")
do
    PRINT(format("cipher.chacha20 %s, version() %s", chacha20._VERSION, chacha20.version()))
    assert(type(chacha20._VERSION) == "string" and chacha20.version() == chacha20._VERSION)
    assert(getmetatable(chacha20) == "cipher.chacha20")
end
PRINT("==================================================================================")
do
    -- RFC 8439 2.3.2 and A.1: the block function, i.e. the keystream of one block
    for i, v in ipairs(vectors.BLOCK) do
        local key, nonce, ks = fromhex(v.key), fromhex(v.nonce), fromhex(v.keystream)
        local opts = { iv = nonce, counter = v.counter }
        assert(chacha20.crypt(("\0"):rep(64), key, opts) == ks, i)
        assert(chacha20.new(key, opts):crypt(("\0"):rep(64)) == ks, i)
        -- the keystream of the next block starts with the next counter value
        if v.counter > 0 then
            local two = chacha20.crypt(("\0"):rep(128), key, { iv = nonce, counter = v.counter - 1 })
            assert(two:sub(65) == ks, i)
        end
    end
    PRINT(format("RFC 8439 block function: %d vectors ok", #vectors.BLOCK))

    -- RFC 8439 2.4.2 and A.2: encryption
    for i, v in ipairs(vectors.ENCRYPT) do
        local key, pt, ct = fromhex(v.key), fromhex(v.plaintext), fromhex(v.ciphertext)
        local opts = { iv = fromhex(v.nonce), counter = v.counter }
        assert(chacha20.crypt(pt, key, opts) == ct, i)
        assert(chacha20.crypt(ct, key, opts) == pt, i)
        for _, chunk in ipairs(CHUNKS) do
            assert(streamCrypt(pt, key, opts, chunk) == ct, i)
        end
        -- any prefix of the data gives the prefix of the result
        for n = 0, #pt, 7 do
            assert(chacha20.crypt(pt:sub(1, n), key, opts) == ct:sub(1, n), i)
        end
    end
    PRINT(format("RFC 8439 encryption: %d vectors ok", #vectors.ENCRYPT))

    -- RFC 8439 2.5.2 and A.3: Poly1305
    for i, v in ipairs(vectors.POLY1305) do
        assert(chacha20.poly1305(fromhex(v.message), fromhex(v.key)) == fromhex(v.tag), i)
    end
    PRINT(format("RFC 8439 Poly1305: %d vectors ok", #vectors.POLY1305))

    -- RFC 8439 2.6.2 and A.4: the one-time Poly1305 key is the first half of the block 0
    for i, v in ipairs(vectors.KEYGEN) do
        local otk = chacha20.crypt(("\0"):rep(32), fromhex(v.key), { iv = fromhex(v.nonce) })
        assert(otk == fromhex(v.otk), i)
    end
    PRINT(format("RFC 8439 Poly1305 key generation: %d vectors ok", #vectors.KEYGEN))
end
PRINT("==================================================================================")
do
    -- RFC 8439 2.8.2 and A.5: AEAD_CHACHA20_POLY1305; draft-irtf-cfrg-xchacha A.3.1
    local function pad16(s)
        return s .. ("\0"):rep((16 - #s % 16) % 16)
    end
    local all = {}
    for _, v in ipairs(vectors.AEAD) do all[#all + 1] = v end
    for _, v in ipairs(vectors.XAEAD) do all[#all + 1] = v end
    for i, v in ipairs(all) do
        local key, nonce, aad = fromhex(v.key), fromhex(v.nonce), fromhex(v.aad)
        local pt, ct, tag = fromhex(v.plaintext), fromhex(v.ciphertext), fromhex(v.tag)
        local opts = { iv = nonce, aad = aad }
        local c, t = chacha20.encrypt(pt, key, opts)
        assert(c == ct and t == tag, i)
        assert(chacha20.decrypt(ct, key, with(opts, { tag = tag })) == pt, i)
        -- the construction: the one-time key, the ciphertext from the counter 1, the tag
        -- as Poly1305 of aad, ciphertext and lengths
        local otk = fromhex(v.otk)
        assert(chacha20.crypt(("\0"):rep(32), key, { iv = nonce }) == otk, i)
        assert(chacha20.crypt(pt, key, { iv = nonce, counter = 1 }) == ct, i)
        local mac = pad16(aad) .. pad16(ct) .. le32(#aad) .. le32(0) .. le32(#ct) .. le32(0)
        assert(chacha20.poly1305(mac, otk) == tag, i)
        for _, chunk in ipairs(CHUNKS) do
            local c2, t2 = streamEncrypt(pt, key, opts, chunk)
            assert(c2 == ct and t2 == tag, i)
            -- the expected tag as option or as argument of finish()
            assert(streamDecrypt(ct, key, with(opts, { tag = tag }), chunk) == pt, i)
            assert(streamDecrypt(ct, key, opts, chunk, tag) == pt, i)
        end
        -- any change is detected
        local bad = string.char((tag:byte(1) + 1) % 256) .. tag:sub(2)
        assertError("authentication failed", chacha20.decrypt, ct, key, with(opts, { tag = bad }))
        assertError("authentication failed", chacha20.decrypt, ct, key, with(opts, { tag = tag, aad = aad .. "x" }))
        assertError("authentication failed", chacha20.decrypt, ct, key, with(opts, { tag = tag, aad = "" }))
        local ct2 = ct:sub(1, -2) .. string.char((ct:byte(-1) + 128) % 256)
        assertError("authentication failed", chacha20.decrypt, ct2, key, with(opts, { tag = tag }))
        assertError("authentication failed", chacha20.decrypt, ct:sub(1, -2), key, with(opts, { tag = tag }))
        assertError("authentication failed", chacha20.decrypt, ct .. "\0", key, with(opts, { tag = tag }))
        local nonce2 = nonce:sub(1, -2) .. string.char((nonce:byte(-1) + 1) % 256)
        assertError("authentication failed", chacha20.decrypt, ct, key, { iv = nonce2, aad = aad, tag = tag })
        local d = chacha20.decryptor(key, opts)
        d:update(ct)
        assertError("authentication failed", d.finish, d, nil, bad)
        assertError("decryptor is closed", d.finish, d)
        assertError("decryptor is closed", d.update, d, "x")
        PRINT(format("AEAD vector %d ok (nonce %d bytes, aad %d, data %d bytes)", i, #nonce, #aad, #pt))
    end
end
PRINT("==================================================================================")
do
    -- draft-irtf-cfrg-xchacha 2.2.1: HChaCha20; XChaCha20 with a 24 byte nonce is
    -- ChaCha20 with the subkey and the nonce of four zero bytes and the last 8 bytes
    local v = vectors.HCHACHA[1]
    local key, nonce16, subkey = fromhex(v.key), fromhex(v.nonce), fromhex(v.subkey)
    local tail = randomBytes(8, 1)
    local data = randomBytes(300, 2)
    assert(chacha20.crypt(data, key, { iv = nonce16 .. tail }) ==
           chacha20.crypt(data, subkey, { iv = "\0\0\0\0" .. tail }))
    assert(chacha20.crypt(data, key, { iv = nonce16 .. tail, counter = 7 }) ==
           chacha20.crypt(data, subkey, { iv = "\0\0\0\0" .. tail, counter = 7 }))
    PRINT("HChaCha20 ok")
    -- draft-irtf-cfrg-xchacha A.3.2: XChaCha20
    for i, x in ipairs(vectors.XCHACHA) do
        local xkey, xnonce = fromhex(x.key), fromhex(x.nonce)
        local pt, ks, ct = fromhex(x.plaintext), fromhex(x.keystream), fromhex(x.ciphertext)
        local opts = { iv = xnonce, counter = x.counter }
        assert(chacha20.crypt(("\0"):rep(#ks), xkey, opts) == ks, i)
        assert(chacha20.crypt(pt, xkey, opts) == ct, i)
        assert(chacha20.crypt(ct, xkey, opts) == pt, i)
        for _, chunk in ipairs(CHUNKS) do
            assert(streamCrypt(pt, xkey, opts, chunk) == ct, i)
        end
    end
    PRINT(format("XChaCha20: %d vectors ok", #vectors.XCHACHA))
end
PRINT("==================================================================================")
do
    -- the original ChaCha20 with an 8 byte nonce and a 64 bit block counter: its block
    -- is the block of RFC 8439 with the high half of the counter as first nonce word
    local key = randomBytes(32, 3)
    local n8 = randomBytes(8, 4)
    local data = randomBytes(1000, 5)
    assert(chacha20.crypt(data, key, { iv = n8 }) == chacha20.crypt(data, key, { iv = le32(0) .. n8 }))
    assert(chacha20.crypt(data, key, { iv = n8, counter = 5 }) ==
           chacha20.crypt(data, key, { iv = le32(0) .. n8, counter = 5 }))
    -- the carry into the high half of the counter
    local hi = 4294967296
    local two = chacha20.crypt(("\0"):rep(128), key, { iv = n8, counter = hi - 1 })
    assert(two:sub(1, 64) == chacha20.crypt(("\0"):rep(64), key, { iv = le32(0) .. n8, counter = hi - 1 }))
    assert(two:sub(65) == chacha20.crypt(("\0"):rep(64), key, { iv = le32(1) .. n8, counter = 0 }))
    assert(chacha20.crypt(("\0"):rep(64), key, { iv = n8, counter = 3 * hi + 17 }) ==
           chacha20.crypt(("\0"):rep(64), key, { iv = le32(3) .. n8, counter = 17 }))
    -- the all zero vector of the original ChaCha20 is the one of RFC 8439 A.1 #1
    assert(chacha20.crypt(("\0"):rep(64), ("\0"):rep(32), { iv = ("\0"):rep(8) })
           == fromhex(vectors.BLOCK[2].keystream))
    PRINT("64 bit nonce, 64 bit counter ok")
end
PRINT("==================================================================================")
do
    -- the limit of the 32 bit block counter: the keystream may not run over its end
    local key, iv = randomBytes(32, 6), randomBytes(12, 7)
    local last = 4294967295
    local ks = chacha20.crypt(("\0"):rep(64), key, { iv = iv, counter = last })
    assert(#ks == 64)
    assertError("data exceeds the limit of the counter", chacha20.crypt, ("\0"):rep(65), key,
                { iv = iv, counter = last })
    assertError("data exceeds the limit of the counter", chacha20.crypt, ("\0"):rep(129), key,
                { iv = iv, counter = last - 1 })
    assert(#chacha20.crypt(("\0"):rep(128), key, { iv = iv, counter = last - 1 }) == 128)
    assert(chacha20.crypt("", key, { iv = iv, counter = last }) == "")
    local st = chacha20.new(key, { iv = iv, counter = last })
    assert(st:crypt(("\0"):rep(60)) == ks:sub(1, 60))
    assertError("data exceeds the limit of the counter", st.crypt, st, ("\0"):rep(5))
    -- nothing was done: the stream is unchanged and can be used up to the end
    assert(st:crypt(("\0"):rep(4)) == ks:sub(61, 64))
    assertError("data exceeds the limit of the counter", st.crypt, st, "x")
    assert(st:crypt("") == "")
    -- XChaCha20 has the 32 bit counter of RFC 8439 as well
    local xiv = randomBytes(24, 8)
    assert(#chacha20.crypt(("\0"):rep(64), key, { iv = xiv, counter = last }) == 64)
    assertError("data exceeds the limit of the counter", chacha20.crypt, ("\0"):rep(65), key,
                { iv = xiv, counter = last })
    -- with 8 byte nonces the counter has 64 bits
    assert(#chacha20.crypt(("\0"):rep(1000), key, { iv = randomBytes(8, 9), counter = last }) == 1000)
    PRINT("counter limit ok")
end
PRINT("==================================================================================")
do
    -- one-shot and streams give the same results for larger data, all nonce lengths
    local data = randomBytes(100000, 10)
    for _, n in ipairs({ 8, 12, 24 }) do
        local key, iv = randomBytes(32, n), randomBytes(n, n + 1)
        local c = chacha20.crypt(data, key, { iv = iv, counter = 3 })
        assert(c ~= data and #c == #data)
        assert(chacha20.crypt(c, key, { iv = iv, counter = 3 }) == data)
        local rnd = newRandom(n)
        local st = chacha20.new(key, { iv = iv, counter = 3 })
        local parts, pos = {}, 1
        while pos <= #data do
            local len = rnd(3000)
            parts[#parts + 1] = st:crypt(data:sub(pos, pos + len - 1))
            pos = pos + len
        end
        assert(table.concat(parts) == c)
        if n ~= 8 then
            local ct, tag = chacha20.encrypt(data, key, { iv = iv, aad = "header" })
            assert(chacha20.decrypt(ct, key, { iv = iv, aad = "header", tag = tag }) == data)
            local e = chacha20.encryptor(key, { iv = iv, aad = "header" })
            local d = chacha20.decryptor(key, { iv = iv, aad = "header" })
            local eparts, dparts = {}, {}
            pos = 1
            while pos <= #data do
                local len = rnd(3000)
                eparts[#eparts + 1] = e:update(data:sub(pos, pos + len - 1))
                dparts[#dparts + 1] = d:update(ct:sub(pos, pos + len - 1))
                pos = pos + len
            end
            local last, tag2 = e:finish()
            eparts[#eparts + 1] = last
            assert(table.concat(eparts) == ct and tag2 == tag)
            dparts[#dparts + 1] = d:finish(nil, tag)
            assert(table.concat(dparts) == data)
        end
        PRINT(format("nonce of %2d bytes: one-shot = stream", n))
    end
end
PRINT("==================================================================================")
do
    -- AEAD details: empty data and aad, aad only, stream results
    local key, iv = randomBytes(32, 11), randomBytes(12, 12)
    local c, t = chacha20.encrypt("", key, { iv = iv })
    assert(c == "" and #t == 16)
    assert(chacha20.decrypt("", key, { iv = iv, tag = t }) == "")
    -- an empty aad is no aad
    assert(select(2, chacha20.encrypt("x", key, { iv = iv, aad = "" })) == select(2, chacha20.encrypt("x", key, { iv = iv })))
    -- aad only: an authentication tag
    local a = randomBytes(1000, 13)
    c, t = chacha20.encrypt("", key, { iv = iv, aad = a })
    assert(c == "" and chacha20.decrypt("", key, { iv = iv, aad = a, tag = t }) == "")
    assertError("authentication failed", chacha20.decrypt, "", key, { iv = iv, aad = a:sub(2), tag = t })
    -- the ciphertext is ChaCha20 from the counter 1
    assert(chacha20.encrypt("data", key, { iv = iv }) == chacha20.crypt("data", key, { iv = iv, counter = 1 }))
    -- stream results: update() gives nil while there is no output, finish() "" and the tag
    local e = chacha20.encryptor(key, { iv = iv, aad = "a" })
    assertError("the tag is only available after finish()", e.tag, e)
    assert(e:update("") == nil)
    local r1 = e:update("abc")
    local r2, tag = e:finish("def")
    assert(r1 .. r2 == chacha20.encrypt("abcdef", key, { iv = iv, aad = "a" }))
    assert(tag == select(2, chacha20.encrypt("abcdef", key, { iv = iv, aad = "a" })))
    assert(e:tag() == tag)
    assertError("encryptor is closed", e.update, e, "x")
    assertError("encryptor is closed", e.finish, e)
    assert(tostring(e):match("^cipher%.chacha20%.encryptor: "))
    assert(getmetatable(e) == "cipher.chacha20.encryptor")
    -- finish(chunk) is update(chunk) and finish()
    local d = chacha20.decryptor(key, { iv = iv, aad = "a" })
    assert(d:update("") == nil)
    assert(d:finish(r1 .. r2, tag) == "abcdef")
    -- the decryptor without a tag
    d = chacha20.decryptor(key, { iv = iv })
    d:update("abc")
    assertError("no tag given", d.finish, d)
    assertError("decryptor is closed", d.finish, d)
    d = chacha20.decryptor(key, { iv = iv })
    assertError("invalid tag length (3)", d.finish, d, nil, "abc")
    assertError("invalid tag length (17)", d.finish, d, nil, ("t"):rep(17))
    -- argument errors do not close the stream; the tag of finish() replaces the option
    local ct, tg = chacha20.encrypt("text", key, { iv = iv })
    d = chacha20.decryptor(key, { iv = iv, tag = ("x"):rep(16) })
    assert(d:finish(ct, tg) == "text")
    assert(tostring(d):match("^cipher%.chacha20%.decryptor: "))
    assert(getmetatable(d) == "cipher.chacha20.decryptor")
    local st = chacha20.new(key, { iv = iv })
    assert(tostring(st):match("^cipher%.chacha20%.stream: "))
    assert(getmetatable(st) == "cipher.chacha20.stream")
    assert(st:crypt("") == "")
end
PRINT("==================================================================================")
do
    -- argument and option errors
    local key, iv = ("k"):rep(32), ("i"):rep(12)
    for _, n in ipairs({ 0, 1, 16, 24, 31, 33, 64 }) do
        local k = ("k"):rep(n)
        assertError(format("invalid key length (%d)", n), chacha20.crypt, "x", k, { iv = iv })
        assertError(format("invalid key length (%d)", n), chacha20.new, k, { iv = iv })
        assertError(format("invalid key length (%d)", n), chacha20.encrypt, "x", k, { iv = iv })
        assertError(format("invalid key length (%d)", n), chacha20.decryptor, k, { iv = iv })
        assertError(format("invalid key length (%d)", n), chacha20.poly1305, "x", k)
    end
    assertError("string or carray expected, got no value", chacha20.crypt, "x")
    assertError("string or carray expected, got number", chacha20.new, 12345, { iv = iv })
    assertError("string or carray expected, got nil", chacha20.crypt, nil, key, { iv = iv })
    assertError("string or carray expected, got table", chacha20.encrypt, {}, key, { iv = iv })
    assertError("bad argument #1", chacha20.crypt, true, key, { iv = iv })
    assert(chacha20.crypt(1234, key, { iv = iv }) == chacha20.crypt("1234", key, { iv = iv }))

    assertError("option 'iv' is required", chacha20.crypt, "x", key)
    assertError("option 'iv' is required", chacha20.new, key)
    assertError("option 'iv' is required", chacha20.encrypt, "x", key, {})
    assertError("option 'iv' is required", chacha20.decryptor, key)
    for _, n in ipairs({ 0, 1, 7, 9, 11, 13, 16, 23, 25, 32 }) do
        assertError(format("invalid iv length (%d)", n), chacha20.crypt, "x", key, { iv = ("i"):rep(n) })
        assertError(format("invalid iv length (%d)", n), chacha20.encrypt, "x", key, { iv = ("i"):rep(n) })
    end
    assertError("invalid iv length (8)", chacha20.encrypt, "x", key, { iv = ("i"):rep(8) })
    assertError("invalid iv length (8)", chacha20.encryptor, key, { iv = ("i"):rep(8) })
    assertError("invalid iv value", chacha20.crypt, "x", key, { iv = 123456789012 })
    assertError("invalid iv value", chacha20.crypt, "x", key, { iv = {} })
    assertError("invalid counter value", chacha20.crypt, "x", key, { iv = iv, counter = -1 })
    assertError("invalid counter value", chacha20.crypt, "x", key, { iv = iv, counter = 1.5 })
    assertError("invalid counter value", chacha20.crypt, "x", key, { iv = iv, counter = "1" })
    assertError("invalid counter value", chacha20.crypt, "x", key, { iv = iv, counter = 4294967296 })
    assertError("invalid counter value", chacha20.new, key, { iv = ("i"):rep(24), counter = 4294967296 })
    assert(#chacha20.crypt("x", key, { iv = ("i"):rep(8), counter = 4294967296 }) == 1)
    assert(chacha20.crypt("x", key, { iv = iv, counter = 0 }) == chacha20.crypt("x", key, { iv = iv }))
    assert(chacha20.crypt("x", key, { iv = iv, counter = 2.0 }) == chacha20.crypt("x", key, { iv = iv, counter = 2 }))
    assertError("option 'aad' is not supported by crypt()", chacha20.crypt, "x", key, { iv = iv, aad = "a" })
    assertError("option 'tag' is not supported by new()", chacha20.new, key, { iv = iv, tag = ("t"):rep(16) })
    assertError("option 'counter' is not supported by encrypt()", chacha20.encrypt, "x", key,
                { iv = iv, counter = 1 })
    assertError("option 'counter' is not supported by decryptor()", chacha20.decryptor, key,
                { iv = iv, counter = 1 })
    assertError("option 'tag' is not supported by encrypt()", chacha20.encrypt, "x", key,
                { iv = iv, tag = ("t"):rep(16) })
    assertError("option 'tag' is not supported by encryptor()", chacha20.encryptor, key,
                { iv = iv, tag = ("t"):rep(16) })
    assertError("option 'tag' is required", chacha20.decrypt, "x", key, { iv = iv })
    for _, n in ipairs({ 0, 1, 4, 8, 12, 15, 17, 32 }) do
        assertError(format("invalid tag length (%d)", n), chacha20.decrypt, "x", key,
                    { iv = iv, tag = ("t"):rep(n) })
        assertError(format("invalid tag length (%d)", n), chacha20.decryptor, key,
                    { iv = iv, tag = ("t"):rep(n) })
    end
    assertError("unknown option 'mode'", chacha20.encrypt, "x", key, { iv = iv, mode = "gcm" })
    assertError("unknown option 'taglen'", chacha20.encrypt, "x", key, { iv = iv, taglen = 16 })
    assertError("unknown option 'nonce'", chacha20.crypt, "x", key, { nonce = iv })
    assertError("unknown option 'foo'", chacha20.poly1305, "x", key, { foo = 1 })
    assertError("option 'iv' is not supported by poly1305()", chacha20.poly1305, "x", key, { iv = iv })
    assertError("option names must be strings", chacha20.crypt, "x", key, { iv = iv, [1] = 2 })
    assertError("option 'out' is not supported: pass the carray as the last argument", chacha20.crypt,
                "x", key, { iv = iv, out = {} })
    assertError("table or carray expected, got string", chacha20.crypt, "x", key, "iv")
    assertError("table or carray expected, got string", chacha20.poly1305, "x", key, "iv")
    assertError("table expected, got string", chacha20.new, key, "iv")
    assertError("table expected, got string", chacha20.encryptor, key, "iv")
    assertError("bad argument #3", chacha20.crypt, "x", key, { foo = 1 })
    assertError("bad argument #2", chacha20.new, key, { foo = 1 })
    assertError("bad argument #3", chacha20.encrypt, "x", key)
    assert(chacha20.poly1305("x", key, {}) == chacha20.poly1305("x", key))
    assert(chacha20.poly1305("x", key, nil) == chacha20.poly1305("x", key))
    assert(chacha20.poly1305("", key) == chacha20.poly1305("", key) and #chacha20.poly1305("", key) == 16)
    -- methods with objects of another kind
    local st = chacha20.new(key, { iv = iv })
    local e = chacha20.encryptor(key, { iv = iv })
    assertError("bad argument #1", st.crypt, e, "x")
    assertError("bad argument #1", e.update, st, "x")
    assertError("bad argument #1", chacha20.decryptor(key, { iv = iv }).update, e, "x")
    assertError("string or carray expected, got no value", st.crypt, st)
    assertError("string or carray expected, got no value", e.update, e)
    -- argument errors do not close the stream
    assert(#e:finish("abc") == 3)
end
PRINT("==================================================================================")
do
    -- larger data: 10 MB
    local data = randomBytes(65536, 21):rep(160)
    local key, iv = randomBytes(32, 22), randomBytes(12, 23)
    local t0 = os.clock()
    local c = chacha20.crypt(data, key, { iv = iv })
    local t1 = os.clock()
    assert(chacha20.crypt(c, key, { iv = iv }) == data)
    local t2 = os.clock()
    local ct, tag = chacha20.encrypt(data, key, { iv = iv })
    local t3 = os.clock()
    assert(chacha20.decrypt(ct, key, { iv = iv, tag = tag }) == data)
    local t4 = os.clock()
    PRINT(format("10 MB: crypt %.2f s, %.2f s; encrypt %.2f s, decrypt %.2f s", t1 - t0, t2 - t1, t3 - t2, t4 - t3))
end
PRINT("==================================================================================")
print("OK.")
