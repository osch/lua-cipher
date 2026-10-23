-- cipher.aes with carray objects: carray data, keys, IVs, AAD and tags (read without
-- copying) and carray output (the out argument: the output is appended in place) of all
-- functions and methods, carray chunks, errors.

local aes = require("cipher.aes")

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

local MODES = { "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr", "gcm" }

local function optsFor(mode, iv)
    if mode == "ecb" then
        return { mode = mode }
    end
    return { mode = mode, iv = iv, aad = (mode == "gcm") and "aad" or nil }
end

PRINT("==================================================================================")
do
    -- carray input gives the same results as string input: data, key, iv, aad, tag
    local key, iv = randomBytes(24, 1), randomBytes(16, 2)
    for _, mode in ipairs(MODES) do
        for _, n in ipairs({ 0, 1, 16, 33, 1000 }) do
            local s = randomBytes(n, n + 3)
            local opts = optsFor(mode, iv)
            local c, tag = aes.encrypt(s, key, opts)
            for _, t in ipairs({ "char", "uchar", "schar", "int8", "uint8" }) do
                local copts = optsFor(mode, newC(iv, t))
                if mode == "gcm" then copts.aad = newC("aad", t) end
                local c2, tag2 = aes.encrypt(newC(s, t), newC(key, t), copts)
                assert(c2 == c and tag2 == tag)
                copts.tag = tag and newC(tag, t)
                assert(aes.decrypt(newC(c, t), newC(key, t), copts) == s)
                local e = aes.encryptor(newC(key, t), copts.tag and optsFor(mode, newC(iv, t)) or copts)
                local r = (e:update(newC(s, t)) or "") .. e:finish(newC("", t))
                assert(r == c)
            end
        end
    end
    local k = aes.newkey(newC(key))
    assert(k:encryptblock(newC(("b"):rep(32))) == aes.newkey(key):encryptblock(("b"):rep(32)))
    assertError("carray elements must be 1 byte in size", aes.encrypt, carray.new("int", 4), key,
                { mode = "ecb" })
    assertError("carray elements must be 1 byte in size", aes.encrypt, "x", carray.new("int", 4),
                { mode = "ecb" })
    assertError("iv: carray elements must be 1 byte in size", aes.encrypt, "x", key,
                { iv = carray.new("int", 4) })
    assertError("aad: carray elements must be 1 byte in size", aes.encrypt, "x", key,
                { mode = "gcm", iv = iv, aad = carray.new("short", 4) })
    assertError("invalid key length (8)", aes.newkey, newC(("k"):rep(8)))
end
PRINT("==================================================================================")
do
    -- carray output: the output is appended to the carray, which is returned
    local key, iv = randomBytes(16, 5), randomBytes(16, 6)
    local s = randomBytes(5000, 7)
    for _, mode in ipairs(MODES) do
        local opts = optsFor(mode, iv)
        local c, tag = aes.encrypt(s, key, opts)
        local o = newC("prefix:")
        local r, tag2 = aes.encrypt(s, key, opts, o)
        assert(r == o and tag2 == tag)
        assert(o:tostring() == "prefix:" .. c)
        opts.tag = tag
        assert(aes.decrypt(c, key, opts, o) == o)
        assert(o:tostring() == "prefix:" .. c .. s)
        -- carray in, carray out
        local o2 = carray.new("uint8")
        assert(aes.decrypt(newC(c), key, opts, o2) == o2 and o2:tostring() == s)
        -- without options: aes.encrypt(data, key, out) for ecb with its defaults is not
        -- possible (the default mode cbc needs an iv), so nil options
        o2:reset()
        assert(aes.decrypt(newC(c), key, opts, o2):tostring() == s)
    end
    -- empty output still returns the carray, unchanged
    local o = newC("x")
    assert(aes.encrypt("", key, { mode = "ctr", iv = iv }, o) == o and o:tostring() == "x")
    -- the out argument in place of the options
    local k = aes.newkey(key)
    o = carray.new("char")
    assertError("option 'iv' is required for mode 'cbc'", aes.encrypt, "x", key, o)
    assert(o:len() == 0)
    -- key objects: block functions with out
    o = newC("blocks:")
    assert(k:encryptblock(("a"):rep(32), o) == o)
    assert(k:decryptblock(o:tostring():sub(8), o) == o)
    assert(o:tostring() == "blocks:" .. k:encryptblock(("a"):rep(32)) .. ("a"):rep(32))
    -- many calls into one carray, reset in between keeps the capacity
    o = carray.new("char")
    local expect = {}
    for i = 1, 100 do
        local si = randomBytes(i * 7, i)
        aes.encrypt(si, key, { iv = iv }, o)
        expect[#expect + 1] = aes.encrypt(si, key, { iv = iv })
    end
    assert(o:tostring() == table.concat(expect))
    for i = 1, 20 do
        o:reset()
        local si = randomBytes(i * 100, i)
        assert(aes.decrypt(aes.encrypt(si, key, { iv = iv }), key, { iv = iv }, o):tostring() == si)
    end
end
PRINT("==================================================================================")
do
    -- carray output errors; on errors the carray keeps its previous content
    local key, iv = randomBytes(16, 8), randomBytes(16, 9)
    local c = aes.encrypt(("x"):rep(100), key, { iv = iv })
    assertError("out: carray expected, got table", aes.decrypt, c, key, { iv = iv }, {})
    assertError("out: carray expected, got number", aes.encrypt, "x", key, { iv = iv }, 1)
    assertError("out: carray elements must be 1 byte in size", aes.decrypt, c, key, { iv = iv },
                carray.new("int"))
    assertError("bad argument #4", aes.decrypt, c, key, { iv = iv }, {})
    assertError("bad argument #3", aes.decrypt, c, key, carray.new("int"))
    local cin = newC(c)
    assertError("out: carray must not be the input data", aes.decrypt, cin, key, { iv = iv }, cin)
    assert(cin:tostring() == c)

    local o = newC("previous content")
    -- invalid padding, wrong length
    local bad = aes.encrypt(("x"):rep(32), key, { iv = iv, padding = "none" })
    assertError("invalid padding", aes.decrypt, bad, key, { iv = iv }, o)
    assert(o:tostring() == "previous content")
    assertError("data length (31) is not a multiple of the block size (16)", aes.decrypt,
                bad:sub(2), key, { iv = iv }, o)
    assert(o:tostring() == "previous content")
    -- GCM: nothing is decrypted if the tag does not match
    local g, tag = aes.encrypt(("secret"):rep(100), key, { mode = "gcm", iv = iv })
    assertError("authentication failed", aes.decrypt, g, key,
                { mode = "gcm", iv = iv, tag = tag:sub(1, 15) .. "\0" }, o)
    assert(o:tostring() == "previous content")
    assert(aes.decrypt(g, key, { mode = "gcm", iv = iv, tag = newC(tag) }, o):tostring()
           == "previous content" .. ("secret"):rep(100))
end
PRINT("==================================================================================")
do
    -- carray output of the stream methods: appended, the carray is returned (also when
    -- there is no output), the same bytes as with string results
    local key, iv = randomBytes(32, 10), randomBytes(16, 11)
    local s = randomBytes(20000, 12)
    for _, mode in ipairs(MODES) do
        local opts = optsFor(mode, iv)
        local c, tag = aes.encrypt(s, key, opts)
        local e = aes.encryptor(key, opts)
        local o = newC("head")
        for i = 1, #s, 777 do
            assert(e:update(s:sub(i, i + 776), o) == o)
        end
        local r, tag2 = e:finish(nil, o)
        assert(r == o and tag2 == tag)
        assert(o:tostring() == "head" .. c)
        -- byte by byte, carray chunks
        local d = aes.decryptor(key, opts)
        o = newC("head")
        for i = 1, 200 do
            assert(d:update(newC(c:sub(i, i)), o) == o)
        end
        assert(d:update(c:sub(201), o) == o)
        assert(d:finish(nil, tag, o) == o)       -- the tag of gcm, nil for the other modes
        assert(o:tostring() == "head" .. s)
        -- finish(chunk, out)
        d = aes.decryptor(key, opts)
        o = carray.new("char")
        if mode == "gcm" then
            assert(d:finish(c, tag, o) == o)
        else
            assert(d:finish(c, o) == o)
        end
        assert(o:tostring() == s)
    end
    -- update without output returns the carray unchanged
    local e = aes.encryptor(key, { iv = iv })
    local o = newC("x")
    assert(e:update("abc", o) == o and o:tostring() == "x")
    assert(e:finish(nil, o) == o and #o:tostring() == 17)
    -- nil as out: string results
    e = aes.encryptor(key, { iv = iv })
    assert(e:update("abc", nil) == nil)
    assert(type(e:finish(nil, nil)) == "string")

    -- errors of the stream methods: the carray keeps what the successful calls appended
    local c = aes.encrypt(("x"):rep(64), key, { iv = iv, padding = "none" })
    local d = aes.decryptor(key, { iv = iv })
    o = newC("head")
    d:update(c:sub(1, 40), o)
    local before = o:tostring()
    assert(#before == 4 + 32)
    assertError("invalid padding", d.finish, d, c:sub(41), o)
    assert(o:tostring() == before)
    assertError("decryptor is closed", d.update, d, "x", o)
    local g, tag = aes.encrypt(s, key, { mode = "gcm", iv = iv })
    d = aes.decryptor(key, { mode = "gcm", iv = iv })
    o = carray.new("char")
    d:update(g:sub(1, 1000), o)
    assert(o:len() == 1000)
    assertError("authentication failed", d.finish, d, g:sub(1001, -2), tag, o)
    assert(o:len() == 1000)
    -- out errors are argument errors of their position
    e = aes.encryptor(key, { iv = iv })
    assertError("bad argument #3", e.update, e, "x", {})
    assertError("bad argument #3", e.finish, e, "x", 1)
    d = aes.decryptor(key, { mode = "gcm", iv = iv })
    assertError("bad argument #4", d.finish, d, "x", tag, {})
    local cin = newC("same")
    assertError("out: carray must not be the input data", e.update, e, cin, cin)
    -- and do not close the stream
    assert(#e:finish("x") == 16)
end
PRINT("==================================================================================")
do
    -- read-only carrays and carrays referencing foreign memory (test helper module)
    local ok2, tc = pcall(require, "cipher_testcarray")
    if not ok2 then
        print("test helper cipher_testcarray not available: test part skipped")
    else
        local key, iv = randomBytes(16, 13), randomBytes(16, 14)
        local s = randomBytes(3000, 15)
        local c = aes.encrypt(s, key, { iv = iv })
        -- read-only carrays can be read
        assert(aes.decrypt(tc.readonly(c), tc.readonly(key), { iv = tc.readonly(iv) }) == s)
        assert(aes.encrypt(tc.readonly(s), key, { iv = iv }) == c)
        assertError("out: carray is not writable", aes.decrypt, c, key, { iv = iv }, tc.readonly("abc"))
        -- carrays referencing foreign memory cannot be resized
        assert(aes.decrypt(tc.ref(c), key, { iv = iv }) == s)
        assertError("cannot resize carray", aes.decrypt, c, key, { iv = iv }, tc.ref("abc"))
        local r = tc.ref("abc")
        assertError("cannot resize carray", aes.encrypt, s, key, { iv = iv }, r)
        assert(r:tostring() == "abc")
        -- empty output needs no resizing
        assert(aes.encrypt("", key, { mode = "ctr", iv = iv }, r) == r and r:tostring() == "abc")
        -- the stream methods: the stream stays usable
        local e = aes.encryptor(key, { iv = iv })
        assertError("out: carray is not writable", e.update, e, ("x"):rep(20), tc.readonly(""))
        assertError("cannot resize carray", e.update, e, ("x"):rep(20), r)
        assert(r:tostring() == "abc")
        assert(e:finish(s) == c)
        local k = aes.newkey(key)
        assertError("cannot resize carray", k.encryptblock, k, ("x"):rep(16), r)
        assertError("out: carray is not writable", k.decryptblock, k, ("x"):rep(16), tc.readonly(""))
    end
end
PRINT("==================================================================================")
print("OK.")
