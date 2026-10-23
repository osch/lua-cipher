-- cipher.chacha20 with carray objects: carray data, keys, nonces, AAD and tags (read
-- without copying) and carray output (the out argument: the output is appended in place)
-- of all functions and methods, carray chunks, errors.

local chacha20 = require("cipher.chacha20")

local format = string.format

local function PRINT(s)
    print(s.." ("..debug.getinfo(2).currentline..")")
end
local function assertError(pattern, f, ...)
    local ok, err = pcall(f, ...)
    assert(not ok, "error expected")
    assert(tostring(err):find(pattern, 1, true), format("unexpected error message: %s", tostring(err)))
end

local ok, carray = pcall(require, "carray")
if not ok then
    print("carray module not available: test skipped")
    return
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

local function newC(s, t)
    return carray.new(t or "char"):append(s)
end

local TYPES = { "char", "uchar", "schar", "int8", "uint8" }

PRINT("==================================================================================")
do
    -- carray input gives the same results as string input: data, key, iv, aad, tag
    local key = randomBytes(32, 1)
    for _, ivlen in ipairs({ 8, 12, 24 }) do
        local iv = randomBytes(ivlen, ivlen)
        for _, n in ipairs({ 0, 1, 64, 65, 1000 }) do
            local s = randomBytes(n, n + 3)
            local c = chacha20.crypt(s, key, { iv = iv, counter = 2 })
            local ct, tag
            if ivlen ~= 8 then
                ct, tag = chacha20.encrypt(s, key, { iv = iv, aad = "aad" })
            end
            for _, t in ipairs(TYPES) do
                assert(chacha20.crypt(newC(s, t), newC(key, t), { iv = newC(iv, t), counter = 2 }) == c)
                assert(chacha20.new(newC(key, t), { iv = newC(iv, t), counter = 2 }):crypt(newC(s, t)) == c)
                if ivlen ~= 8 then
                    local c2, tag2 = chacha20.encrypt(newC(s, t), newC(key, t), { iv = newC(iv, t), aad = newC("aad", t) })
                    assert(c2 == ct and tag2 == tag)
                    assert(chacha20.decrypt(newC(ct, t), newC(key, t),
                                            { iv = newC(iv, t), aad = newC("aad", t), tag = newC(tag, t) }) == s)
                    local e = chacha20.encryptor(newC(key, t), { iv = newC(iv, t), aad = newC("aad", t) })
                    local r = (e:update(newC(s, t)) or "") .. e:finish(newC("", t))
                    assert(r == ct)
                    local d = chacha20.decryptor(newC(key, t), { iv = newC(iv, t), aad = newC("aad", t),
                                                                tag = newC(tag, t) })
                    assert((d:update(newC(ct, t)) or "") .. d:finish() == s)
                end
                assert(chacha20.poly1305(newC(s, t), newC(key, t)) == chacha20.poly1305(s, key))
            end
        end
    end
    assertError("carray elements must be 1 byte in size", chacha20.crypt, carray.new("int", 4), key,
                { iv = ("i"):rep(12) })
    assertError("carray elements must be 1 byte in size", chacha20.crypt, "x", carray.new("int", 8),
                { iv = ("i"):rep(12) })
    assertError("iv: carray elements must be 1 byte in size", chacha20.crypt, "x", key,
                { iv = carray.new("int", 3) })
    assertError("aad: carray elements must be 1 byte in size", chacha20.encrypt, "x", key,
                { iv = ("i"):rep(12), aad = carray.new("short", 4) })
    assertError("tag: carray elements must be 1 byte in size", chacha20.decrypt, "x", key,
                { iv = ("i"):rep(12), tag = carray.new("int", 4) })
    assertError("invalid key length (16)", chacha20.new, newC(("k"):rep(16)), { iv = ("i"):rep(12) })
end
PRINT("==================================================================================")
do
    -- carray output: the output is appended to the carray, which is returned
    local key, iv = randomBytes(32, 5), randomBytes(12, 6)
    local s = randomBytes(5000, 7)
    local c = chacha20.crypt(s, key, { iv = iv })
    local o = newC("prefix:")
    assert(chacha20.crypt(s, key, { iv = iv }, o) == o)
    assert(o:tostring() == "prefix:" .. c)
    assert(chacha20.crypt(c, key, { iv = iv }, o) == o)
    assert(o:tostring() == "prefix:" .. c .. s)
    -- AEAD: the tag as second result
    local ct, tag = chacha20.encrypt(s, key, { iv = iv })
    o = newC("x")
    local r, tag2 = chacha20.encrypt(s, key, { iv = iv }, o)
    assert(r == o and tag2 == tag and o:tostring() == "x" .. ct)
    assert(chacha20.decrypt(ct, key, { iv = iv, tag = tag }, o) == o)
    assert(o:tostring() == "x" .. ct .. s)
    -- carray in, carray out
    local o2 = carray.new("uint8")
    assert(chacha20.decrypt(newC(ct), key, { iv = iv, tag = tag }, o2) == o2 and o2:tostring() == s)
    -- Poly1305: the tag appended
    o = newC("mac:")
    assert(chacha20.poly1305(s, key, o) == o)
    assert(chacha20.poly1305(s, key, nil, o) == o)
    assert(o:tostring() == "mac:" .. chacha20.poly1305(s, key):rep(2))
    -- empty output still returns the carray, unchanged
    o = newC("x")
    assert(chacha20.crypt("", key, { iv = iv }, o) == o and o:tostring() == "x")
    -- the out argument in place of the options: the iv is required
    o = carray.new("char")
    assertError("option 'iv' is required", chacha20.crypt, "x", key, o)
    assert(o:len() == 0)
    -- many calls into one carray, reset in between keeps the capacity
    o = carray.new("char")
    local expect = {}
    for i = 1, 100 do
        local si = randomBytes(i * 7, i)
        chacha20.crypt(si, key, { iv = iv, counter = i }, o)
        expect[#expect + 1] = chacha20.crypt(si, key, { iv = iv, counter = i })
    end
    assert(o:tostring() == table.concat(expect))
    for i = 1, 20 do
        o:reset()
        local si = randomBytes(i * 100, i)
        local cti, tagi = chacha20.encrypt(si, key, { iv = iv })
        assert(chacha20.decrypt(cti, key, { iv = iv, tag = tagi }, o):tostring() == si)
    end
end
PRINT("==================================================================================")
do
    -- carray output errors; on errors the carray keeps its previous content
    local key, iv = randomBytes(32, 8), randomBytes(12, 9)
    local ct, tag = chacha20.encrypt(("secret"):rep(100), key, { iv = iv })
    assertError("out: carray expected, got table", chacha20.crypt, "x", key, { iv = iv }, {})
    assertError("out: carray expected, got number", chacha20.encrypt, "x", key, { iv = iv }, 1)
    assertError("out: carray elements must be 1 byte in size", chacha20.crypt, "x", key, { iv = iv },
                carray.new("int"))
    assertError("bad argument #4", chacha20.decrypt, ct, key, { iv = iv, tag = tag }, {})
    assertError("bad argument #3", chacha20.poly1305, "x", key, carray.new("int"))
    local cin = newC(ct)
    assertError("out: carray must not be the input data", chacha20.crypt, cin, key, { iv = iv }, cin)
    assertError("out: carray must not be the input data", chacha20.poly1305, cin, key, cin)
    assert(cin:tostring() == ct)
    -- nothing is decrypted if the tag does not match
    local o = newC("previous content")
    assertError("authentication failed", chacha20.decrypt, ct, key,
                { iv = iv, tag = tag:sub(1, 15) .. "\0" }, o)
    assert(o:tostring() == "previous content")
    -- the limit of the counter
    assertError("data exceeds the limit of the counter", chacha20.crypt, ("x"):rep(65), key,
                { iv = iv, counter = 4294967295 }, o)
    assert(o:tostring() == "previous content")
    assert(chacha20.decrypt(ct, key, { iv = iv, tag = newC(tag) }, o):tostring()
           == "previous content" .. ("secret"):rep(100))
end
PRINT("==================================================================================")
do
    -- carray output of the stream methods: appended, the carray is returned (also when
    -- there is no output), the same bytes as with string results
    local key, iv = randomBytes(32, 10), randomBytes(24, 11)
    local s = randomBytes(20000, 12)
    -- the stream cipher
    local c = chacha20.crypt(s, key, { iv = iv })
    local st = chacha20.new(key, { iv = iv })
    local o = newC("head")
    for i = 1, #s, 777 do
        assert(st:crypt(s:sub(i, i + 776), o) == o)
    end
    assert(o:tostring() == "head" .. c)
    assert(st:crypt("", o) == o and o:tostring() == "head" .. c)
    -- AEAD streams
    local ct, tag = chacha20.encrypt(s, key, { iv = iv, aad = "aad" })
    local e = chacha20.encryptor(key, { iv = iv, aad = "aad" })
    o = newC("head")
    for i = 1, #s, 777 do
        assert(e:update(s:sub(i, i + 776), o) == o)
    end
    local r, tag2 = e:finish(nil, o)
    assert(r == o and tag2 == tag)
    assert(o:tostring() == "head" .. ct)
    -- byte by byte, carray chunks
    local d = chacha20.decryptor(key, { iv = iv, aad = "aad" })
    o = newC("head")
    for i = 1, 200 do
        assert(d:update(newC(ct:sub(i, i)), o) == o)
    end
    assert(d:update(ct:sub(201), o) == o)
    assert(d:finish(nil, tag, o) == o)
    assert(o:tostring() == "head" .. s)
    -- finish(chunk, tag, out), finish(chunk, out), finish(chunk, nil, out)
    d = chacha20.decryptor(key, { iv = iv, aad = "aad" })
    o = carray.new("char")
    assert(d:finish(ct, tag, o) == o and o:tostring() == s)
    d = chacha20.decryptor(key, { iv = iv, aad = "aad", tag = tag })
    o = carray.new("char")
    assert(d:finish(ct, o) == o and o:tostring() == s)
    d = chacha20.decryptor(key, { iv = iv, aad = "aad", tag = tag })
    o = carray.new("char")
    assert(d:finish(ct, nil, o) == o and o:tostring() == s)
    -- update without output returns the carray unchanged; nil as out: string results
    e = chacha20.encryptor(key, { iv = iv })
    o = newC("x")
    assert(e:update("", o) == o and o:tostring() == "x")
    assert(e:update("", nil) == nil)
    assert(type(e:finish(nil, nil)) == "string")

    -- errors of the stream methods: the carray keeps what the successful calls appended
    d = chacha20.decryptor(key, { iv = iv, aad = "aad" })
    o = carray.new("char")
    d:update(ct:sub(1, 1000), o)
    assert(o:len() == 1000)
    assertError("authentication failed", d.finish, d, ct:sub(1001, -2), tag, o)
    assert(o:len() == 1000)
    assertError("decryptor is closed", d.update, d, "x", o)
    -- out errors are argument errors of their position
    e = chacha20.encryptor(key, { iv = iv })
    assertError("bad argument #3", e.update, e, "x", {})
    assertError("bad argument #3", e.finish, e, "x", 1)
    d = chacha20.decryptor(key, { iv = iv })
    assertError("bad argument #4", d.finish, d, "x", tag, {})
    st = chacha20.new(key, { iv = iv })
    assertError("bad argument #3", st.crypt, st, "x", 1)
    local cin = newC("same")
    assertError("out: carray must not be the input data", e.update, e, cin, cin)
    assertError("out: carray must not be the input data", st.crypt, st, cin, cin)
    -- and do not close the stream
    assert(#e:finish("x") == 1)
    assert(st:crypt(s) == c)
end
PRINT("==================================================================================")
do
    -- read-only carrays and carrays referencing foreign memory (test helper module)
    local ok2, tc = pcall(require, "cipher_testcarray")
    if not ok2 then
        print("test helper cipher_testcarray not available: test part skipped")
    else
        local key, iv = randomBytes(32, 13), randomBytes(12, 14)
        local s = randomBytes(3000, 15)
        local c = chacha20.crypt(s, key, { iv = iv })
        local ct, tag = chacha20.encrypt(s, key, { iv = iv })
        -- read-only carrays can be read
        assert(chacha20.crypt(tc.readonly(c), tc.readonly(key), { iv = tc.readonly(iv) }) == s)
        assert(chacha20.decrypt(tc.readonly(ct), key, { iv = iv, tag = tc.readonly(tag) }) == s)
        assertError("out: carray is not writable", chacha20.crypt, c, key, { iv = iv }, tc.readonly("abc"))
        -- carrays referencing foreign memory cannot be resized
        assert(chacha20.crypt(tc.ref(c), key, { iv = iv }) == s)
        local r = tc.ref("abc")
        assertError("cannot resize carray", chacha20.crypt, s, key, { iv = iv }, r)
        assertError("cannot resize carray", chacha20.encrypt, s, key, { iv = iv }, r)
        assertError("cannot resize carray", chacha20.poly1305, s, key, r)
        assert(r:tostring() == "abc")
        -- empty output needs no resizing
        assert(chacha20.crypt("", key, { iv = iv }, r) == r and r:tostring() == "abc")
        -- the stream methods: the stream stays usable, its keystream is not consumed
        local st = chacha20.new(key, { iv = iv })
        assertError("out: carray is not writable", st.crypt, st, s, tc.readonly(""))
        assertError("cannot resize carray", st.crypt, st, s, r)
        assert(st:crypt(s) == c)
        local e = chacha20.encryptor(key, { iv = iv })
        assertError("cannot resize carray", e.update, e, ("x"):rep(20), r)
        assert(r:tostring() == "abc")
        assert(e:update(s) == ct)
    end
end
PRINT("==================================================================================")
print("OK.")
