-- cipher.rc4 with carray objects: carray data and keys (read without copying) and
-- carray output (the out argument: the output is appended in place), errors.

local rc4 = require("cipher.rc4")

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

PRINT("==================================================================================")
do
    -- carray input gives the same results as string input
    local key = randomBytes(16, 1)
    for _, n in ipairs({ 0, 1, 100, 10000 }) do
        local s = randomBytes(n, n + 2)
        local c = rc4.crypt(s, key, { drop = 768 })
        for _, t in ipairs({ "char", "uchar", "schar", "int8", "uint8" }) do
            assert(rc4.crypt(newC(s, t), newC(key, t), { drop = 768 }) == c)
            local st = rc4.new(newC(key, t), { drop = 768 })
            assert(st:crypt(newC(s, t)) == c)
        end
    end
    assertError("carray elements must be 1 byte in size", rc4.crypt, carray.new("int", 4), key)
    assertError("carray elements must be 1 byte in size", rc4.crypt, "x", carray.new("int", 4))
    assertError("invalid key length (0)", rc4.new, carray.new("char"))
end
PRINT("==================================================================================")
do
    -- carray output: appended, the carray is returned
    local key = "carray key"
    local s = randomBytes(5000, 3)
    local c = rc4.crypt(s, key)
    local o = newC("prefix:")
    assert(rc4.crypt(s, key, o) == o)
    assert(o:tostring() == "prefix:" .. c)
    assert(rc4.crypt(c, key, nil, o) == o)
    assert(o:tostring() == "prefix:" .. c .. s)
    o:reset()
    assert(rc4.crypt(s, key, { drop = 0 }, o):tostring() == c)
    -- stream: byte by byte into one carray
    local st = rc4.new(key)
    o = newC("head")
    for i = 1, #s do
        assert(st:crypt(s:sub(i, i), o) == o)
    end
    assert(o:tostring() == "head" .. c)
    assert(st:crypt("", o) == o and o:tostring() == "head" .. c)
    st = rc4.new(key)
    assert(st:crypt(newC(s), nil) == c)
    -- errors
    assertError("out: carray expected, got table", rc4.crypt, "x", "k", nil, {})
    assertError("out: carray elements must be 1 byte in size", rc4.crypt, "x", "k", carray.new("int"))
    local cin = newC("same")
    assertError("out: carray must not be the input data", rc4.crypt, cin, "k", cin)
    assertError("out: carray must not be the input data", st.crypt, st, cin, cin)
    assertError("bad argument #3", st.crypt, st, "x", 1)
    local ok2, tc = pcall(require, "cipher_testcarray")
    if not ok2 then
        print("test helper cipher_testcarray not available: test part skipped")
    else
        assert(rc4.crypt(tc.readonly(s), tc.readonly(key)) == c)
        assertError("out: carray is not writable", rc4.crypt, s, key, tc.readonly(""))
        local r = tc.ref("abc")
        assertError("cannot resize carray", rc4.crypt, s, key, r)
        assert(r:tostring() == "abc")
        -- the keystream of a stream is not consumed by a failed call
        st = rc4.new(key)
        assertError("cannot resize carray", st.crypt, st, s, r)
        assert(st:crypt(s) == c)
    end
end
PRINT("==================================================================================")
print("OK.")
