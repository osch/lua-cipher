-- cipher.aes in several independent Lua states of the same process, also used from
-- parallel OS threads: cipher.aes keeps all its state (stream and key objects, carray C
-- API cache) per Lua state and has no global mutable data.
-- Needs the test helper module cipher_multistate (tests/multistate.c).

local aes = require("cipher.aes")

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
        aes = require("cipher.aes")
        hasCarray, carray = pcall(require, "carray")
        function data(n, tag)
            local t = {}
            for i = 1, n do t[i] = tag .. (i % 1000) .. " " end
            return table.concat(t)
        end
        return aes._VERSION
    ]]
    assert(A:run(init) == aes._VERSION)
    assert(B:run(init) == aes._VERSION)
end
PRINT("==================================================================================")
do
    -- interleaved use: streams in A and B stay independent
    A:run([[ s = data(20000, "a"); key = ("A"):rep(16); iv = ("1"):rep(16)
             c = aes.encrypt(s, key, { iv = iv })
             d = aes.decryptor(key, { iv = iv }); e = aes.encryptor(aes.newkey(key), { mode = "gcm", iv = iv })
             outD, outE = {}, {} ]])
    B:run([[ s = data(20000, "b"); key = ("B"):rep(32); iv = ("2"):rep(16)
             c = aes.encrypt(s, key, { iv = iv })
             d = aes.decryptor(key, { iv = iv }); e = aes.encryptor(aes.newkey(key), { mode = "gcm", iv = iv })
             outD, outE = {}, {} ]])
    local step = [[
        local i = ...
        outD[#outD + 1] = d:update(c:sub(i, i + 999))
        outE[#outE + 1] = e:update(s:sub(i, i + 999))
    ]]
    for i = 1, 200000, 1000 do
        A:run(format("return (function(...) %s end)(%d)", step, i))
        B:run(format("return (function(...) %s end)(%d)", step, i))
    end
    local check = [[
        outD[#outD + 1] = d:finish()
        local last, tag = e:finish()
        outE[#outE + 1] = last
        local g, t = aes.encrypt(s, key, { mode = "gcm", iv = iv })
        return table.concat(outD) == s and table.concat(outE) == g and tag == t
    ]]
    assert(A:run(check) == true)
    assert(B:run(check) == true)

    if pcall(require, "carray") then
        local code = [[
            local o = carray.new("char")
            local k = ("k"):rep(16)
            aes.decrypt(aes.encrypt(carray.new("char"):append(...), k, { mode = "ctr", iv = k }), k,
                        { mode = "ctr", iv = k }, o)
            return o:tostring()
        ]]
        assert(A:run("return (function(...) "..code.." end)('carray in A')") == "carray in A")
        assert(B:run("return (function(...) "..code.." end)('carray in B')") == "carray in B")
    end
end
PRINT("==================================================================================")
do
    -- parallel threads: both states encrypt and decrypt at the same time
    local work = [[
        local tag = %q
        local s = data(50000, tag)
        local n = 0
        for round = 1, 10 do
            local key = (tag .. round):rep(32):sub(1, 16 + 8 * (round %% 3))
            local iv = ("iv" .. round):rep(16):sub(1, 16)
            for _, mode in ipairs({ "cbc", "ctr", "cfb", "ofb", "ecb" }) do
                local opts = { mode = mode, iv = mode ~= "ecb" and iv or nil }
                local c = aes.encrypt(s, key, opts)
                assert(aes.decrypt(c, key, opts) == s)
                local d = aes.decryptor(aes.newkey(key), opts)
                local parts = {}
                for i = 1, #c, 777 do parts[#parts + 1] = d:update(c:sub(i, i + 776)) end
                parts[#parts + 1] = d:finish()
                assert(table.concat(parts) == s)
                n = n + #c
            end
            local g, t = aes.encrypt(s, key, { mode = "gcm", iv = iv, aad = tag })
            assert(aes.decrypt(g, key, { mode = "gcm", iv = iv, aad = tag, tag = t }) == s)
            assert(not pcall(aes.decrypt, g, key, { mode = "gcm", iv = iv, tag = t }))
            if hasCarray then
                local o = carray.new("char")
                aes.decrypt(carray.new("char"):append(g), key, { mode = "gcm", iv = iv, aad = tag, tag = t }, o)
                assert(o:tostring() == s)
            end
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
    -- closing A (with open streams and key objects) does not affect B
    A:run([[ open1 = aes.encryptor(("k"):rep(16), { iv = ("i"):rep(16) }); open1:update("pending")
             open2 = aes.newkey(("k"):rep(32)) ]])
    A:close()
    assert(not pcall(A.run, A, "return 1"))
    collectgarbage()
    assert(B:run([[ local k = ("k"):rep(16)
                    return aes.decrypt(aes.encrypt("still working", k, { iv = k }), k, { iv = k }) ]])
           == "still working")
    B:close()
    -- and the main state still works
    local k = ("m"):rep(16)
    assert(aes.decrypt(aes.encrypt("main", k, { iv = k }), k, { iv = k }) == "main")
end
PRINT("==================================================================================")
print("OK.")
