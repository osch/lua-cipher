-- cipher.rc4 in several independent Lua states of the same process, also used from
-- parallel OS threads: cipher.rc4 keeps all its state per Lua state and has no global
-- mutable data.
-- Needs the test helper module cipher_multistate (tests/multistate.c).

local rc4 = require("cipher.rc4")

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
        rc4 = require("cipher.rc4")
        hasCarray, carray = pcall(require, "carray")
        function data(n, tag)
            local t = {}
            for i = 1, n do t[i] = tag .. (i % 1000) .. " " end
            return table.concat(t)
        end
        return rc4._VERSION
    ]]
    assert(A:run(init) == rc4._VERSION)
    assert(B:run(init) == rc4._VERSION)
end
PRINT("==================================================================================")
do
    -- interleaved streams
    A:run([[ s = data(20000, "a"); st = rc4.new("key A", { drop = 768 }); out = {} ]])
    B:run([[ s = data(20000, "b"); st = rc4.new("key B"); out = {} ]])
    local step = [[ local i = ...; out[#out + 1] = st:crypt(s:sub(i, i + 999)) ]]
    for i = 1, 200000, 1000 do
        A:run(format("return (function(...) %s end)(%d)", step, i))
        B:run(format("return (function(...) %s end)(%d)", step, i))
    end
    assert(A:run([[ return table.concat(out) == rc4.crypt(s, "key A", { drop = 768 }) ]]) == true)
    assert(B:run([[ return table.concat(out) == rc4.crypt(s, "key B") ]]) == true)
end
PRINT("==================================================================================")
do
    -- parallel threads
    local work = [[
        local tag = %q
        local s = data(50000, tag)
        local n = 0
        for round = 1, 20 do
            local key = (tag .. round):rep(20)
            local c = rc4.crypt(s, key, { drop = round })
            assert(rc4.crypt(c, key, { drop = round }) == s)
            local st = rc4.new(key, { drop = round })
            local parts = {}
            for i = 1, #c, 777 do parts[#parts + 1] = st:crypt(c:sub(i, i + 776)) end
            assert(table.concat(parts) == s)
            if hasCarray then
                local o = carray.new("char")
                rc4.crypt(carray.new("char"):append(c), key, { drop = round }, o)
                assert(o:tostring() == s)
            end
            n = n + #c
        end
        return tag .. ":" .. n
    ]]
    local ra, rb = ms.parallel(A, format(work, "A"), B, format(work, "B"))
    PRINT(format("parallel: %s / %s", ra, rb))
    assert(ra:match("^A:%d+$") and rb:match("^B:%d+$"))
end
PRINT("==================================================================================")
do
    A:run([[ open = rc4.new("pending") ]])
    A:close()
    collectgarbage()
    assert(B:run([[ return rc4.crypt(rc4.crypt("still working", "k"), "k") ]]) == "still working")
    B:close()
    assert(rc4.crypt(rc4.crypt("main", "k"), "k") == "main")
end
PRINT("==================================================================================")
print("OK.")
