-- Throughput of cipher.chacha20 (MB/s): ChaCha20, XChaCha20, ChaCha20-Poly1305 and
-- Poly1305, and the time for short messages. Not a test: run by hand,
-- "lua bench01.lua [MB]" (default 16 MB of data per measurement).

local chacha20 = require("cipher.chacha20")

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
local key  = randomBytes(32, 2)
print(format("cipher.chacha20 %s, %s, %d MB of data", chacha20._VERSION, _VERSION, #data / 1048576))
for _, n in ipairs({ 12, 24 }) do
    local iv = randomBytes(n, 3)
    local name = (n == 12) and "ChaCha20" or "XChaCha20"
    print(format("%-24s %7.1f MB/s", name, measure(function() chacha20.crypt(data, key, { iv = iv }) end, #data)))
    local ct, tag = chacha20.encrypt(data, key, { iv = iv })
    print(format("%-24s %7.1f MB/s encrypt, %7.1f MB/s decrypt", name .. "-Poly1305",
                 measure(function() chacha20.encrypt(data, key, { iv = iv }) end, #data),
                 measure(function() chacha20.decrypt(ct, key, { iv = iv, tag = tag }) end, #data)))
end
print(format("%-24s %7.1f MB/s", "Poly1305", measure(function() chacha20.poly1305(data, key) end, #data)))
do
    -- short messages: a new key and nonce for each message
    local n, keys, msgs = 20000, {}, {}
    for i = 1, 64 do keys[i] = randomBytes(32, i) end
    for i = 1, 64 do msgs[i] = randomBytes(48, i + 100) end
    local iv = randomBytes(12, 7)
    local t0 = os.clock()
    for i = 1, n do
        chacha20.encrypt(msgs[i % 64 + 1], keys[i % 64 + 1], { iv = iv })
    end
    print(format("ChaCha20-Poly1305, 48 bytes with a new key each time: %.1f us per message",
                 (os.clock() - t0) / n * 1e6))
end
