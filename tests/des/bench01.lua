-- Throughput of cipher.des (MB/s) for DES and Triple DES in all modes, and the time of the
-- key schedule. Not a test: run by hand, "lua bench01.lua [MB]" (default 4 MB of data per
-- measurement).

local des = require("cipher.des")

local format = string.format
local MB     = tonumber(arg and arg[1]) or 4

local function randomBytes(n, seed)
    local x, t = seed, {}
    for i = 1, n do
        x = (x * 16807) % 2147483647
        t[i] = string.char(x % 256)
    end
    return table.concat(t)
end

local function measure(f, bytes)
    local t0 = os.clock()
    local rounds = 0
    repeat
        f()
        rounds = rounds + 1
    until os.clock() - t0 > 0.5
    return bytes * rounds / (os.clock() - t0) / 1e6
end

local data = randomBytes(65536, 1):rep(MB * 16)
print(format("cipher.des %s, %s, %d MB of data", des._VERSION, _VERSION, #data / 1048576))
print(format("%-6s %-6s %10s %10s", "mode", "key", "encrypt", "decrypt"))
for _, mode in ipairs({ "ecb", "cbc", "cfb", "ofb", "ctr" }) do
    for _, klen in ipairs({ 8, 24 }) do
        local key = randomBytes(klen, 2)
        local opts = { mode = mode, iv = (mode ~= "ecb") and randomBytes(8, 3) or nil,
                       padding = (mode == "ecb" or mode == "cbc") and "none" or nil }
        local ct = des.encrypt(data, key, opts)
        local enc = measure(function() des.encrypt(data, key, opts) end, #data)
        local dec = measure(function() des.decrypt(ct, key, opts) end, #ct)
        print(format("%-6s %-6s %7.1f MB/s %7.1f MB/s", mode, klen == 8 and "DES" or "3DES", enc, dec))
    end
end
do
    local n, keys = 20000, {}
    for i = 1, 64 do keys[i] = randomBytes(24, i) end
    local t0 = os.clock()
    for i = 1, n do
        des.newkey(keys[i % 64 + 1])
    end
    print(format("des.newkey() of a 24 byte key: %.1f us", (os.clock() - t0) / n * 1e6))
end
