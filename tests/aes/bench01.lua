-- Throughput of cipher.aes in all modes (MB/s), for comparison also of a pure Lua AES-128
-- (table based, Lua 5.3 and later) in CBC mode. Not a test: run by hand,
-- "lua bench01.lua [MB]" (default 16 MB of data per measurement).

local aes = require("cipher.aes")

local format = string.format
local MB     = tonumber(arg and arg[1]) or 16

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
print(format("cipher.aes %s, %s, %d MB of data", aes._VERSION, _VERSION, #data / 1048576))
print(format("%-6s %-6s %10s %10s", "mode", "key", "encrypt", "decrypt"))
for _, mode in ipairs({ "ecb", "cbc", "cfb", "ofb", "ctr", "gcm" }) do
    for _, klen in ipairs({ 16, 32 }) do
        local key = randomBytes(klen, 2)
        local opts = { mode = mode, iv = (mode ~= "ecb") and randomBytes(mode == "gcm" and 12 or 16, 3) or nil,
                       padding = (mode == "ecb" or mode == "cbc") and "none" or nil }
        local ct, tag = aes.encrypt(data, key, opts)
        opts.tag = tag
        local enc = measure(function() aes.encrypt(data, key, { mode = opts.mode, iv = opts.iv,
                                                                padding = opts.padding }) end, #data)
        local dec = measure(function() aes.decrypt(ct, key, opts) end, #ct)
        print(format("%-6s %-6s %7.1f MB/s %7.1f MB/s", mode, "AES-" .. klen * 8, enc, dec))
    end
end
do
    -- short messages with changing keys: key schedule and one CBC operation per message
    local n, keys, msgs = 20000, {}, {}
    for i = 1, 64 do keys[i] = randomBytes(16, i) end
    for i = 1, 64 do msgs[i] = randomBytes(48, i + 100) end
    local iv = randomBytes(16, 7)
    local t0 = os.clock()
    for i = 1, n do
        aes.decrypt(msgs[i % 64 + 1], keys[i % 64 + 1], { iv = iv, padding = "none" })
    end
    local t = os.clock() - t0
    print(format("cbc, 48 bytes with a new key each time: %.1f us per message", t / n * 1e6))
    local ks = {}
    for i = 1, 64 do ks[i] = aes.newkey(keys[i]) end
    t0 = os.clock()
    for i = 1, n do
        aes.decrypt(msgs[i % 64 + 1], ks[i % 64 + 1], { iv = iv, padding = "none" })
    end
    t = os.clock() - t0
    print(format("cbc, 48 bytes with key objects:          %.1f us per message", t / n * 1e6))
    t0 = os.clock()
    for i = 1, n do
        aes.newkey(keys[i % 64 + 1])
    end
    t = os.clock() - t0
    print(format("aes.newkey():                            %.1f us", t / n * 1e6))
end

-- a pure Lua AES-128 (encryption with T-tables, CBC), for comparison
local pure = load([==[
    local aes = ...
    local sbox, T0, T1, T2, T3 = {}, {}, {}, {}, {}
    local function xtime(a) a = a << 1; if a > 255 then a = a ~ 0x11b end; return a end
    local function mul(a, b)
        local r = 0
        while b > 0 do
            if b & 1 == 1 then r = r ~ a end
            a = xtime(a); b = b >> 1
        end
        return r
    end
    local inv = { [0] = 0 }
    for a = 1, 255 do for b = 1, 255 do if mul(a, b) == 1 then inv[a] = b break end end end
    for a = 0, 255 do
        local x = inv[a]
        local s = x
        for _ = 1, 4 do x = ((x << 1) | (x >> 7)) & 255; s = s ~ x end
        s = s ~ 0x63
        sbox[a] = s
        local w = (mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3)
        T0[a] = w
        T1[a] = ((w >> 8) | (w << 24)) & 0xffffffff
        T2[a] = ((w >> 16) | (w << 16)) & 0xffffffff
        T3[a] = ((w >> 24) | (w << 8)) & 0xffffffff
    end
    local function expand(key)
        local w = { string.unpack(">I4I4I4I4", key) }
        w[5] = nil
        local rcon = 1
        for i = 5, 44 do
            local t = w[i - 1]
            if (i - 1) % 4 == 0 then
                t = ((t << 8) | (t >> 24)) & 0xffffffff
                t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16) | (sbox[(t >> 8) & 255] << 8)
                    | sbox[t & 255]
                t = t ~ (rcon << 24)
                rcon = xtime(rcon)
            end
            w[i] = w[i - 4] ~ t
        end
        return w
    end
    local function encryptCbc(data, key, iv)
        local w = expand(key)
        local p0, p1, p2, p3 = string.unpack(">I4I4I4I4", iv)
        local out = {}
        for pos = 1, #data, 16 do
            local d0, d1, d2, d3 = string.unpack(">I4I4I4I4", data, pos)
            local s0, s1, s2, s3 = d0 ~ p0 ~ w[1], d1 ~ p1 ~ w[2], d2 ~ p2 ~ w[3], d3 ~ p3 ~ w[4]
            for r = 1, 9 do
                local k = 4 * r
                s0, s1, s2, s3 =
                    T0[s0 >> 24] ~ T1[(s1 >> 16) & 255] ~ T2[(s2 >> 8) & 255] ~ T3[s3 & 255] ~ w[k + 1],
                    T0[s1 >> 24] ~ T1[(s2 >> 16) & 255] ~ T2[(s3 >> 8) & 255] ~ T3[s0 & 255] ~ w[k + 2],
                    T0[s2 >> 24] ~ T1[(s3 >> 16) & 255] ~ T2[(s0 >> 8) & 255] ~ T3[s1 & 255] ~ w[k + 3],
                    T0[s3 >> 24] ~ T1[(s0 >> 16) & 255] ~ T2[(s1 >> 8) & 255] ~ T3[s2 & 255] ~ w[k + 4]
            end
            local function last(a, b, c, d, k)
                return ((sbox[a >> 24] << 24) | (sbox[(b >> 16) & 255] << 16) | (sbox[(c >> 8) & 255] << 8)
                        | sbox[d & 255]) ~ k
            end
            p0, p1, p2, p3 = last(s0, s1, s2, s3, w[41]), last(s1, s2, s3, s0, w[42]),
                             last(s2, s3, s0, s1, w[43]), last(s3, s0, s1, s2, w[44])
            out[#out + 1] = string.pack(">I4I4I4I4", p0, p1, p2, p3)
        end
        return table.concat(out)
    end
    return encryptCbc
]==])
if pure and _VERSION ~= "Lua 5.1" and _VERSION ~= "Lua 5.2" then
    local ok, encryptCbc = pcall(pure, aes)
    if ok then
        local key, iv = randomBytes(16, 5), randomBytes(16, 6)
        local small = data:sub(1, 1048576)
        assert(encryptCbc(small, key, iv) == aes.encrypt(small, key, { iv = iv, padding = "none" }))
        local lua = measure(function() encryptCbc(small, key, iv) end, #small)
        local c = measure(function() aes.encrypt(data, key, { iv = iv, padding = "none" }) end, #data)
        print(format("cbc encryption AES-128: pure Lua %.1f MB/s, cipher.aes %.1f MB/s (%.0f times)", lua, c, c / lua))
    end
end
