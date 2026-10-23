-- Compares cipher.chacha20 with other ChaCha20 and Poly1305 implementations on this
-- machine, in both directions (their encryption with ours, our ciphertext decrypted and
-- our tags checked by them):
--
--   * the command line tool openssl ("openssl enc -chacha20": 12 byte nonces, and 8 byte
--     nonces with the 64 bit counter; "openssl mac Poly1305"),
--   * the Python packages cryptography (ChaCha20, ChaCha20Poly1305, Poly1305) and
--     pycryptodome (ChaCha20 and XChaCha20, ChaCha20_Poly1305 also with 24 byte nonces),
--     helper test04.py,
--   * the Perl modules of CryptX (Crypt::Stream::ChaCha, Crypt::Stream::XChaCha,
--     Crypt::AuthEnc::ChaCha20Poly1305, Crypt::Mac::Poly1305), helper test04.pl.
--
-- Each part is skipped if the tool or module is not installed. CIPHER_TEST_REQUIRE gives a
-- comma separated list of parts that must not be skipped (openssl, cryptography,
-- pycryptodome, cryptx). CIPHER_TEST_OPENSSL, CIPHER_TEST_PYTHON and CIPHER_TEST_PERL name
-- the programs (default openssl, python3 or python, perl; a path without spaces).

local chacha20 = require("cipher.chacha20")

local format = string.format

local OPENSSL = os.getenv("CIPHER_TEST_OPENSSL") or "openssl"
local PYTHON  = os.getenv("CIPHER_TEST_PYTHON")
local PERL    = os.getenv("CIPHER_TEST_PERL") or "perl"

local required = {}
for name in (os.getenv("CIPHER_TEST_REQUIRE") or ""):gmatch("[^,%s]+") do
    required[name] = true
end

local function PRINT(s)
    print(s.." ("..debug.getinfo(2).currentline..")")
end

-- os.execute returns a number in Lua 5.1/LuaJIT and true/nil in Lua 5.2+
local function run(cmd)
    local r = os.execute(cmd)
    return r == true or r == 0
end

local function capture(cmd)
    local f = io.popen(cmd)
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local function readFile(name)
    local f = assert(io.open(name, "rb"))
    local s = f:read("*a")
    f:close()
    return s
end

local function writeFile(name, data)
    local f = assert(io.open(name, "wb"))
    f:write(data)
    f:close()
end

local function tohex(s)
    if s == nil or s == "" then return "-" end
    return (s:gsub(".", function(c) return format("%02x", c:byte()) end))
end

local function newRandom(seed)
    local x = seed
    return function(n)
        x = (x * 16807) % 2147483647
        return x % n
    end
end

local function randomBytes(n, seed)
    local rnd = newRandom(seed)
    local t = {}
    for i = 1, n do t[i] = string.char(rnd(256)) end
    return table.concat(t)
end

-- n as little endian number of len bytes (n < 2^53)
local function le(n, len)
    local t = {}
    for i = 1, len do
        t[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(t)
end

local function skipped(name, why)
    if required[name] then
        error(format("%s is required (CIPHER_TEST_REQUIRE) but %s", name, why))
    end
    print(format("%s %s: test part skipped", name, why))
end

-- os.tmpname() gives a name in the root directory on Windows, use the current one there
local isWindows = package.config:sub(1, 1) == "\\"
local devnull = isWindows and "NUL" or "/dev/null"
local here = debug.getinfo(1, "S").source:match("^@(.*[/\\])") or ""
local tmpDir
if isWindows then
    tmpDir = "cipher_chacha20_test04.tmp"
else
    tmpDir = os.tmpname()
    os.remove(tmpDir)
end
assert(run(format('mkdir "%s"', tmpDir)), "cannot create temporary directory")
local files = {}
local function tmpFile(name)
    files[#files + 1] = name
    return tmpDir .. "/" .. name
end
local function cleanup()
    for _, name in ipairs(files) do os.remove(tmpDir .. "/" .. name) end
    if isWindows then
        run(format('rmdir "%s"', tmpDir))
    else
        os.remove(tmpDir)
    end
end

-- the cases: our results, the jobs for the helpers
--   op "crypt": ChaCha20 (iv of 8, 12 or 24 bytes, counter)
--   op "enc", "dec": ChaCha20-Poly1305 (iv of 12 or 24 bytes, aad, tag); "dec" also with
--                    a wrong tag, then the helper must give "ERR"
--   op "poly": Poly1305 (key, data)
local SIZES = { 0, 1, 15, 16, 17, 63, 64, 65, 100, 1000, 4103 }
local TWO32 = 4294967296
local cases = {}
do
    local seed = 1
    for _, ivlen in ipairs({ 8, 12, 24 }) do
        local counters = { 0, 1, 42, TWO32 - 70 }
        if ivlen == 8 then
            counters[#counters + 1] = TWO32 - 3          -- the 64 bit counter: carry
            counters[#counters + 1] = 1099511627781     -- 2^40 + 5
        end
        for _, counter in ipairs(counters) do
            for _, n in ipairs(SIZES) do
                seed = seed + 1
                local c = { op = "crypt", key = randomBytes(32, seed * 3), iv = randomBytes(ivlen, seed * 5),
                            counter = counter, aad = "", data = randomBytes(n, seed * 7) }
                c.out = chacha20.crypt(c.data, c.key, { iv = c.iv, counter = counter })
                c.tag = ""
                cases[#cases + 1] = c
            end
        end
    end
    for _, ivlen in ipairs({ 12, 24 }) do
        for _, n in ipairs(SIZES) do
            for _, alen in ipairs({ 0, 1, 16, 33 }) do
                seed = seed + 1
                local c = { op = "enc", key = randomBytes(32, seed * 3), iv = randomBytes(ivlen, seed * 5),
                            counter = 0, aad = randomBytes(alen, seed * 11), data = randomBytes(n, seed * 7) }
                c.out, c.tag = chacha20.encrypt(c.data, c.key, { iv = c.iv, aad = c.aad })
                cases[#cases + 1] = c
                -- the decryption of our ciphertext
                cases[#cases + 1] = { op = "dec", key = c.key, iv = c.iv, counter = 0, aad = c.aad,
                                      data = c.out, tag = c.tag, out = c.data }
                if n % 2 == 1 then
                    -- and with a wrong tag: rejected
                    local bad = string.char((c.tag:byte(1) + 1) % 256) .. c.tag:sub(2)
                    cases[#cases + 1] = { op = "dec", key = c.key, iv = c.iv, counter = 0, aad = c.aad,
                                          data = c.out, tag = bad, err = true }
                end
            end
        end
    end
    for _, n in ipairs({ 0, 1, 15, 16, 17, 31, 32, 33, 100, 1000, 4103 }) do
        seed = seed + 1
        local c = { op = "poly", key = randomBytes(32, seed * 3), iv = "", counter = 0, aad = "",
                    data = randomBytes(n, seed * 7), tag = "" }
        c.out = chacha20.poly1305(c.data, c.key)
        cases[#cases + 1] = c
    end
end

local function jobLines()
    local lines = {}
    for _, c in ipairs(cases) do
        lines[#lines + 1] = format("%s %s %s %.0f %s %s %s", c.op, tohex(c.key), tohex(c.iv), c.counter,
                                   tohex(c.aad), tohex(c.op == "dec" and c.tag or ""), tohex(c.data))
    end
    return table.concat(lines, "\n") .. "\n"
end

-- the result line that is expected for a case
local function expected(c)
    if c.err then
        return "ERR"
    elseif c.op == "enc" then
        return tohex(c.out) .. " " .. tohex(c.tag)
    else
        return tohex(c.out) .. " -"
    end
end

-- runs a helper script and compares its results
local function compareHelper(name, cmd)
    local out = capture(cmd)
    if not out or out == "" then
        skipped(name, "cannot be run")
        return
    end
    if out:match("^UNAVAILABLE") then
        skipped(name, "is not installed")
        return
    end
    local results = {}
    for line in out:gmatch("[^\r\n]+") do
        results[#results + 1] = line
    end
    assert(#results == #cases, format("%s: %d results for %d jobs", name, #results, #cases))
    local counts, skip, kinds = {}, 0, {}
    for i, c in ipairs(cases) do
        local r = results[i]
        local what = format("%s: %s, iv %d bytes, counter %.0f, %d bytes", name, c.op, #c.iv, c.counter, #c.data)
        if r == "SKIP" then
            skip = skip + 1
        else
            assert(r == expected(c), what .. ": result differs: " .. r:sub(1, 80))
            local kind = (c.op == "crypt") and format("crypt/%d", #c.iv) or (c.op == "poly") and "poly1305"
                         or format("aead/%d", #c.iv)
            if not counts[kind] then kinds[#kinds + 1] = kind end
            counts[kind] = (counts[kind] or 0) + 1
        end
    end
    assert(#kinds > 0, name .. ": no job was run")
    local list = {}
    for _, kind in ipairs(kinds) do list[#list + 1] = format("%s %d", kind, counts[kind]) end
    PRINT(format("%-12s: identical: %s; %d skipped", name, table.concat(list, ", "), skip))
end

-- the tests, run with pcall: the temporary files are removed also after a failure
local function main()

PRINT("==================================================================================")
-- openssl enc -chacha20: the iv is the 32 bit counter and the 12 byte nonce, or the
-- 64 bit counter and the 8 byte nonce (OpenSSL carries into the second counter word)
do
    local version = capture(OPENSSL .. " version 2>" .. devnull)
    if not version or not version:match("SSL") then
        skipped("openssl", "is not available")
    elseif not run(format("%s enc -chacha20 -K %s -iv %s -in %s -out %s 2>%s", OPENSSL, ("00"):rep(32),
                          ("00"):rep(16), devnull, devnull, devnull)) then
        skipped("openssl", "has no ChaCha20")
    else
        PRINT("openssl: " .. version:gsub("%s+$", ""))
        local n, m, inName, outName = 0, 0, tmpFile("ossl.in"), tmpFile("ossl.out")
        for _, c in ipairs(cases) do
            if c.op == "crypt" and #c.iv ~= 24 and (#c.data == 0 or #c.data == 65 or #c.data == 4103) then
                local iv = (#c.iv == 12) and (le(c.counter, 4) .. c.iv) or (le(c.counter, 8) .. c.iv)
                writeFile(inName, c.data)
                assert(run(format('%s enc -chacha20 -K %s -iv %s -in "%s" -out "%s"', OPENSSL, tohex(c.key),
                                  tohex(iv), inName, outName)), "openssl enc failed")
                assert(readFile(outName) == c.out, format("openssl chacha20, iv %d bytes, counter %.0f, %d bytes: differs",
                                                          #c.iv, c.counter, #c.data))
                n = n + 1
            elseif c.op == "poly" then
                writeFile(inName, c.data)
                local r = capture(format('%s mac -macopt hexkey:%s -in "%s" Poly1305 2>%s', OPENSSL, tohex(c.key),
                                         inName, devnull))
                if r and r:match("^%x+") then
                    assert(r:match("^%x+"):lower() == tohex(c.out), format("openssl Poly1305, %d bytes: differs", #c.data))
                    m = m + 1
                end
            end
        end
        PRINT(format("openssl     : %d ChaCha20 outputs (12 and 8 byte nonces), %d Poly1305 tags identical", n, m))
    end
end
PRINT("==================================================================================")
-- Python
local jobs = tmpFile("jobs")
writeFile(jobs, jobLines())
do
    local python = PYTHON
    if not python then
        for _, p in ipairs({ "python3", "python" }) do
            local v = capture(p .. " --version 2>&1")
            if v and v:match("^Python 3") then python = p break end
        end
    end
    if not python then
        skipped("cryptography", "is not available (no Python 3)")
        skipped("pycryptodome", "is not available (no Python 3)")
    else
        for _, backend in ipairs({ "cryptography", "pycryptodome" }) do
            compareHelper(backend, format('%s "%stest04.py" %s "%s" 2>%s', python, here, backend, jobs, devnull))
        end
    end
end
PRINT("==================================================================================")
-- Perl
do
    local v = capture(PERL .. ' -e "print 1" 2>' .. devnull)
    if v ~= "1" then
        skipped("cryptx", "is not available (no Perl)")
    else
        compareHelper("cryptx", format('%s "%stest04.pl" cryptx "%s" 2>%s', PERL, here, jobs, devnull))
    end
end
PRINT("==================================================================================")

end

local ok, err = pcall(main)
cleanup()
if not ok then
    error(err, 0)
end
print("OK.")
