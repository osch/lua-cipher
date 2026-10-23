-- cipher.des with carray objects: carray data, keys and IVs (read without copying) and
-- carray output (the out argument: the output is appended in place) of all functions and
-- methods, carray chunks, errors.

local des = require("cipher.des")

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

local MODES = { "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr" }

local function optsFor(mode, iv)
    if mode == "ecb" then
        return { mode = mode }
    end
    return { mode = mode, iv = iv }
end

PRINT("==================================================================================")
do
    -- carray input gives the same results as string input: data, key, iv
    local key, iv = randomBytes(24, 1), randomBytes(8, 2)
    for _, mode in ipairs(MODES) do
        for _, n in ipairs({ 0, 1, 8, 17, 500 }) do
            local s = randomBytes(n, n + 3)
            local c = des.encrypt(s, key, optsFor(mode, iv))
            for _, t in ipairs({ "char", "uchar", "schar", "int8", "uint8" }) do
                local copts = optsFor(mode, newC(iv, t))
                assert(des.encrypt(newC(s, t), newC(key, t), copts) == c)
                assert(des.decrypt(newC(c, t), newC(key, t), copts) == s)
                local e = des.encryptor(newC(key, t), copts)
                local r = (e:update(newC(s, t)) or "") .. e:finish(newC("", t))
                assert(r == c)
            end
        end
    end
    local k = des.newkey(newC(key))
    assert(k:encryptblock(newC(("b"):rep(32))) == des.newkey(key):encryptblock(("b"):rep(32)))
    assertError("carray elements must be 1 byte in size", des.encrypt, carray.new("int", 4), key,
                { mode = "ecb" })
    assertError("carray elements must be 1 byte in size", des.encrypt, "x", carray.new("int", 2),
                { mode = "ecb" })
    assertError("iv: carray elements must be 1 byte in size", des.encrypt, "x", key,
                { iv = carray.new("int", 2) })
    assertError("invalid key length (12)", des.newkey, newC(("k"):rep(12)))
end
PRINT("==================================================================================")
do
    -- carray output: the output is appended to the carray, which is returned
    local key, iv = randomBytes(16, 5), randomBytes(8, 6)
    local s = randomBytes(5000, 7)
    for _, mode in ipairs(MODES) do
        local opts = optsFor(mode, iv)
        local c = des.encrypt(s, key, opts)
        local o = newC("prefix:")
        local r, more = des.encrypt(s, key, opts, o)
        assert(r == o and more == nil)
        assert(o:tostring() == "prefix:" .. c)
        assert(des.decrypt(c, key, opts, o) == o)
        assert(o:tostring() == "prefix:" .. c .. s)
        -- carray in, carray out
        local o2 = carray.new("uint8")
        assert(des.decrypt(newC(c), key, opts, o2) == o2 and o2:tostring() == s)
        o2:reset()
        assert(des.decrypt(newC(c), key, opts, o2):tostring() == s)
    end
    -- empty output still returns the carray, unchanged
    local o = newC("x")
    assert(des.encrypt("", key, { mode = "ctr", iv = iv }, o) == o and o:tostring() == "x")
    -- the out argument in place of the options (the default mode cbc needs an iv)
    o = carray.new("char")
    assertError("option 'iv' is required for mode 'cbc'", des.encrypt, "x", key, o)
    assert(o:len() == 0)
    -- key objects: block functions with out
    local k = des.newkey(key)
    o = newC("blocks:")
    assert(k:encryptblock(("a"):rep(16), o) == o)
    assert(k:decryptblock(o:tostring():sub(8), o) == o)
    assert(o:tostring() == "blocks:" .. k:encryptblock(("a"):rep(16)) .. ("a"):rep(16))
    -- many calls into one carray, reset in between keeps the capacity
    o = carray.new("char")
    local expect = {}
    for i = 1, 100 do
        local si = randomBytes(i * 7, i)
        des.encrypt(si, key, { iv = iv }, o)
        expect[#expect + 1] = des.encrypt(si, key, { iv = iv })
    end
    assert(o:tostring() == table.concat(expect))
    for i = 1, 20 do
        o:reset()
        local si = randomBytes(i * 100, i)
        assert(des.decrypt(des.encrypt(si, key, { iv = iv }), key, { iv = iv }, o):tostring() == si)
    end
end
PRINT("==================================================================================")
do
    -- carray output errors; on errors the carray keeps its previous content
    local key, iv = randomBytes(8, 8), randomBytes(8, 9)
    local c = des.encrypt(("x"):rep(100), key, { iv = iv })
    assertError("out: carray expected, got table", des.decrypt, c, key, { iv = iv }, {})
    assertError("out: carray expected, got number", des.encrypt, "x", key, { iv = iv }, 1)
    assertError("out: carray elements must be 1 byte in size", des.decrypt, c, key, { iv = iv },
                carray.new("int"))
    assertError("bad argument #4", des.decrypt, c, key, { iv = iv }, {})
    assertError("bad argument #3", des.decrypt, c, key, carray.new("int"))
    local cin = newC(c)
    assertError("out: carray must not be the input data", des.decrypt, cin, key, { iv = iv }, cin)
    assert(cin:tostring() == c)

    local o = newC("previous content")
    -- invalid padding, wrong length
    local bad = des.encrypt(("x"):rep(16), key, { iv = iv, padding = "none" })
    assertError("invalid padding", des.decrypt, bad, key, { iv = iv }, o)
    assert(o:tostring() == "previous content")
    assertError("data length (15) is not a multiple of the block size (8)", des.decrypt,
                bad:sub(2), key, { iv = iv }, o)
    assert(o:tostring() == "previous content")
    assert(des.decrypt(c, key, { iv = iv }, o):tostring() == "previous content" .. ("x"):rep(100))
end
PRINT("==================================================================================")
do
    -- carray output of the stream methods: appended, the carray is returned (also when
    -- there is no output), the same bytes as with string results
    local key, iv = randomBytes(24, 10), randomBytes(8, 11)
    local s = randomBytes(20000, 12)
    for _, mode in ipairs(MODES) do
        local opts = optsFor(mode, iv)
        local c = des.encrypt(s, key, opts)
        local e = des.encryptor(key, opts)
        local o = newC("head")
        for i = 1, #s, 777 do
            assert(e:update(s:sub(i, i + 776), o) == o)
        end
        local r, more = e:finish(nil, o)
        assert(r == o and more == nil)
        assert(o:tostring() == "head" .. c)
        -- byte by byte, carray chunks
        local d = des.decryptor(key, opts)
        o = newC("head")
        for i = 1, 200 do
            assert(d:update(newC(c:sub(i, i)), o) == o)
        end
        assert(d:update(c:sub(201), o) == o)
        assert(d:finish(nil, nil, o) == o)
        assert(o:tostring() == "head" .. s)
        -- finish(chunk, out)
        d = des.decryptor(key, opts)
        o = carray.new("char")
        assert(d:finish(c, o) == o)
        assert(o:tostring() == s)
    end
    -- update without output returns the carray unchanged
    local e = des.encryptor(key, { iv = iv })
    local o = newC("x")
    assert(e:update("abc", o) == o and o:tostring() == "x")
    assert(e:finish(nil, o) == o and #o:tostring() == 9)
    -- nil as out: string results
    e = des.encryptor(key, { iv = iv })
    assert(e:update("abc", nil) == nil)
    assert(type(e:finish(nil, nil)) == "string")

    -- errors of the stream methods: the carray keeps what the successful calls appended
    local c = des.encrypt(("x"):rep(32), key, { iv = iv, padding = "none" })
    local d = des.decryptor(key, { iv = iv })
    o = newC("head")
    d:update(c:sub(1, 20), o)
    local before = o:tostring()
    assert(#before == 4 + 16)
    assertError("invalid padding", d.finish, d, c:sub(21), o)
    assert(o:tostring() == before)
    assertError("decryptor is closed", d.update, d, "x", o)
    -- out errors are argument errors of their position
    e = des.encryptor(key, { iv = iv })
    assertError("bad argument #3", e.update, e, "x", {})
    assertError("bad argument #3", e.finish, e, "x", 1)
    d = des.decryptor(key, { iv = iv })
    assertError("bad argument #4", d.finish, d, "x", nil, {})
    local cin = newC("same")
    assertError("out: carray must not be the input data", e.update, e, cin, cin)
    -- and do not close the stream
    assert(#e:finish("x") == 8)
end
PRINT("==================================================================================")
do
    -- read-only carrays and carrays referencing foreign memory (test helper module)
    local ok2, tc = pcall(require, "cipher_testcarray")
    if not ok2 then
        print("test helper cipher_testcarray not available: test part skipped")
    else
        local key, iv = randomBytes(16, 13), randomBytes(8, 14)
        local s = randomBytes(3000, 15)
        local c = des.encrypt(s, key, { iv = iv })
        -- read-only carrays can be read
        assert(des.decrypt(tc.readonly(c), tc.readonly(key), { iv = tc.readonly(iv) }) == s)
        assert(des.encrypt(tc.readonly(s), key, { iv = iv }) == c)
        assertError("out: carray is not writable", des.decrypt, c, key, { iv = iv }, tc.readonly("abc"))
        -- carrays referencing foreign memory cannot be resized
        assert(des.decrypt(tc.ref(c), key, { iv = iv }) == s)
        assertError("cannot resize carray", des.decrypt, c, key, { iv = iv }, tc.ref("abc"))
        local r = tc.ref("abc")
        assertError("cannot resize carray", des.encrypt, s, key, { iv = iv }, r)
        assert(r:tostring() == "abc")
        -- empty output needs no resizing
        assert(des.encrypt("", key, { mode = "ctr", iv = iv }, r) == r and r:tostring() == "abc")
        -- the stream methods: the stream stays usable
        local e = des.encryptor(key, { iv = iv })
        assertError("out: carray is not writable", e.update, e, ("x"):rep(20), tc.readonly(""))
        assertError("cannot resize carray", e.update, e, ("x"):rep(20), r)
        assert(r:tostring() == "abc")
        assert(e:finish(s) == c)
        local k = des.newkey(key)
        assertError("cannot resize carray", k.encryptblock, k, ("x"):rep(8), r)
        assertError("out: carray is not writable", k.decryptblock, k, ("x"):rep(8), tc.readonly(""))
    end
end
PRINT("==================================================================================")
print("OK.")
