-- cipher.chacha20 in several independent Lua states of the same process, also used from
-- parallel OS threads: cipher.chacha20 keeps all its state (stream objects, carray C API
-- cache) per Lua state and has no global mutable data.
-- Needs the test helper module cipher_multistate (tests/multistate.c).

local chacha20 = require("cipher.chacha20")

local format = string.format

local function PRINT(s)
    print(s.." ("..debug.getinfo(2).currentline..")")
end

local ok, ms = pcall(require, "cipher_multistate")
if not ok then
    print("test helper cipher_multistate not available: test skipped")
    return
end

PRINT("==================================================================================")
local A = ms.new()
local B = ms.new()
do
    local init = [[
        chacha20 = require("cipher.chacha20")
        hasCarray, carray = pcall(require, "carray")
        function data(n, tag)
            local t = {}
            for i = 1, n do t[i] = tag .. (i % 1000) .. " " end
            return table.concat(t)
        end
        return chacha20._VERSION
    ]]
    assert(A:run(init) == chacha20._VERSION)
    assert(B:run(init) == chacha20._VERSION)
end
PRINT("==================================================================================")
do
    -- interleaved use: streams in A and B stay independent
    A:run([[ s = data(20000, "a"); key = ("A"):rep(32); iv = ("1"):rep(12)
             st = chacha20.new(key, { iv = iv, counter = 1 }); e = chacha20.encryptor(key, { iv = iv, aad = "A" })
             outS, outE = {}, {} ]])
    B:run([[ s = data(20000, "b"); key = ("B"):rep(32); iv = ("2"):rep(24)
             st = chacha20.new(key, { iv = iv, counter = 1 }); e = chacha20.encryptor(key, { iv = iv, aad = "B" })
             outS, outE = {}, {} ]])
    local step = [[
        local i = ...
        outS[#outS + 1] = st:crypt(s:sub(i, i + 999))
        outE[#outE + 1] = e:update(s:sub(i, i + 999))
    ]]
    for i = 1, 200000, 1000 do
        A:run(format("return (function(...) %s end)(%d)", step, i))
        B:run(format("return (function(...) %s end)(%d)", step, i))
    end
    local check = [[
        local last, tag = e:finish()
        outE[#outE + 1] = last
        local c, t = chacha20.encrypt(s, key, { iv = iv, aad = ... })
        return table.concat(outS) == chacha20.crypt(s, key, { iv = iv, counter = 1 })
               and table.concat(outE) == c and tag == t
    ]]
    assert(A:run("return (function(...) "..check.." end)('A')") == true)
    assert(B:run("return (function(...) "..check.." end)('B')") == true)
end
PRINT("==================================================================================")
do
    -- parallel threads: both states encrypt and decrypt at the same time
    local work = [[
        local tag = %q
        local s = data(50000, tag)
        local n = 0
        for round = 1, 20 do
            local key = (tag .. round):rep(32):sub(1, 32)
            local iv = ("iv" .. round):rep(24):sub(1, 8 + 4 * (round %% 5))
            if #iv == 16 or #iv == 20 then iv = iv:sub(1, 12) end
            local c = chacha20.crypt(s, key, { iv = iv, counter = round })
            assert(chacha20.crypt(c, key, { iv = iv, counter = round }) == s)
            local st = chacha20.new(key, { iv = iv, counter = round })
            local parts = {}
            for i = 1, #c, 777 do parts[#parts + 1] = st:crypt(c:sub(i, i + 776)) end
            assert(table.concat(parts) == s)
            if #iv ~= 8 then
                local g, t = chacha20.encrypt(s, key, { iv = iv, aad = tag })
                assert(chacha20.decrypt(g, key, { iv = iv, aad = tag, tag = t }) == s)
                assert(not pcall(chacha20.decrypt, g, key, { iv = iv, tag = t }))
                if hasCarray then
                    local o = carray.new("char")
                    chacha20.decrypt(carray.new("char"):append(g), key, { iv = iv, aad = tag, tag = t }, o)
                    assert(o:tostring() == s)
                end
            end
            assert(#chacha20.poly1305(s, key) == 16)
            n = n + #c
        end
        return tag .. ":" .. n
    ]]
    local t0 = os.clock()
    local ra, rb = ms.parallel(A, format(work, "A"), B, format(work, "B"))
    PRINT(format("parallel: %s / %s (%.2f s cpu)", ra, rb, os.clock() - t0))
    assert(ra:match("^A:%d+$") and rb:match("^B:%d+$"))
end
PRINT("==================================================================================")
do
    -- closing A (with open streams) does not affect B
    A:run([[ open1 = chacha20.encryptor(("k"):rep(32), { iv = ("i"):rep(12) }); open1:update("pending")
             open2 = chacha20.new(("k"):rep(32), { iv = ("i"):rep(8) }) ]])
    A:close()
    assert(not pcall(A.run, A, "return 1"))
    collectgarbage()
    assert(B:run([[ local k, iv = ("k"):rep(32), ("i"):rep(12)
                    return chacha20.crypt(chacha20.crypt("still working", k, { iv = iv }), k, { iv = iv }) ]])
           == "still working")
    B:close()
    -- and the main state still works
    local k, iv = ("m"):rep(32), ("i"):rep(12)
    local c, t = chacha20.encrypt("main", k, { iv = iv })
    assert(chacha20.decrypt(c, k, { iv = iv, tag = t }) == "main")
end
PRINT("==================================================================================")
print("OK.")
