-- cipher.des in several independent Lua states of the same process, also used from
-- parallel OS threads: cipher.des keeps all its state (stream and key objects, carray C
-- API cache) per Lua state and has no global mutable data.
-- Needs the test helper module cipher_multistate (tests/multistate.c).

local des = require("cipher.des")

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
        des = require("cipher.des")
        hasCarray, carray = pcall(require, "carray")
        function data(n, tag)
            local t = {}
            for i = 1, n do t[i] = tag .. (i % 1000) .. " " end
            return table.concat(t)
        end
        return des._VERSION
    ]]
    assert(A:run(init) == des._VERSION)
    assert(B:run(init) == des._VERSION)
end
PRINT("==================================================================================")
do
    -- interleaved use: streams in A and B stay independent
    A:run([[ s = data(5000, "a"); key = ("A"):rep(8); iv = ("1"):rep(8)
             c = des.encrypt(s, key, { iv = iv })
             d = des.decryptor(key, { iv = iv }); e = des.encryptor(des.newkey(key), { mode = "ctr", iv = iv })
             outD, outE = {}, {} ]])
    B:run([[ s = data(5000, "b"); key = ("B"):rep(24); iv = ("2"):rep(8)
             c = des.encrypt(s, key, { iv = iv })
             d = des.decryptor(key, { iv = iv }); e = des.encryptor(des.newkey(key), { mode = "ctr", iv = iv })
             outD, outE = {}, {} ]])
    local step = [[
        local i = ...
        outD[#outD + 1] = d:update(c:sub(i, i + 999))
        outE[#outE + 1] = e:update(s:sub(i, i + 999))
    ]]
    for i = 1, 50000, 1000 do
        A:run(format("return (function(...) %s end)(%d)", step, i))
        B:run(format("return (function(...) %s end)(%d)", step, i))
    end
    local check = [[
        outD[#outD + 1] = d:finish()
        outE[#outE + 1] = e:finish()
        return table.concat(outD) == s and table.concat(outE) == des.encrypt(s, key, { mode = "ctr", iv = iv })
    ]]
    assert(A:run(check) == true)
    assert(B:run(check) == true)
end
PRINT("==================================================================================")
do
    -- parallel threads: both states encrypt and decrypt at the same time
    local work = [[
        local tag = %q
        local s = data(5000, tag)
        local n = 0
        for round = 1, 6 do
            local key = (tag .. round):rep(24):sub(1, 8 * (round %% 3 + 1))
            local iv = ("iv" .. round):rep(8):sub(1, 8)
            for _, mode in ipairs({ "cbc", "ctr", "cfb", "ofb", "ecb" }) do
                local opts = { mode = mode, iv = mode ~= "ecb" and iv or nil }
                local c = des.encrypt(s, key, opts)
                assert(des.decrypt(c, key, opts) == s)
                local d = des.decryptor(des.newkey(key), opts)
                local parts = {}
                for i = 1, #c, 777 do parts[#parts + 1] = d:update(c:sub(i, i + 776)) end
                parts[#parts + 1] = d:finish()
                assert(table.concat(parts) == s)
                if hasCarray then
                    local o = carray.new("char")
                    des.decrypt(carray.new("char"):append(c), key, opts, o)
                    assert(o:tostring() == s)
                end
                n = n + #c
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
    A:run([[ open1 = des.encryptor(("k"):rep(16), { iv = ("i"):rep(8) }); open1:update("pending")
             open2 = des.newkey(("k"):rep(24)) ]])
    A:close()
    assert(not pcall(A.run, A, "return 1"))
    collectgarbage()
    assert(B:run([[ local k, iv = ("k"):rep(16), ("i"):rep(8)
                    return des.decrypt(des.encrypt("still working", k, { iv = iv }), k, { iv = iv }) ]])
           == "still working")
    B:close()
    -- and the main state still works
    local k, iv = ("m"):rep(8), ("i"):rep(8)
    assert(des.decrypt(des.encrypt("main", k, { iv = iv }), k, { iv = iv }) == "main")
end
PRINT("==================================================================================")
print("OK.")
