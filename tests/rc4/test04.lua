-- Compares cipher.rc4 with other RC4 implementations on this machine:
--
--   * the command line tool openssl ("openssl enc -rc4", 16 byte keys, and "-rc4-40",
--     5 byte keys; RC4 is in the legacy provider of OpenSSL 3),
--   * the Python packages cryptography (ARC4) and pycryptodome (ARC4, with drop),
--     helper test04.py,
--   * the Perl modules Crypt::RC4 and Crypt::Stream::RC4 of CryptX (helper test04.pl).
--
-- Each part is skipped if the tool or module is not installed. CIPHER_TEST_REQUIRE gives a
-- comma separated list of parts that must not be skipped (openssl, cryptography,
-- pycryptodome, rc4, cryptx). CIPHER_TEST_OPENSSL, CIPHER_TEST_PYTHON and CIPHER_TEST_PERL
-- name the programs (default openssl, python3 or python, perl; a path without spaces).

local rc4 = require("cipher.rc4")

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
    if s == "" then return "-" end
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

local function skipped(name, why)
    if required[name] then
        error(format("%s is required (CIPHER_TEST_REQUIRE) but %s", name, why))
    end
    print(format("%s %s: test part skipped", name, why))
end

local isWindows = package.config:sub(1, 1) == "\\"
local devnull = isWindows and "NUL" or "/dev/null"
local here = debug.getinfo(1, "S").source:match("^@(.*[/\\])") or ""
local tmpDir
if isWindows then
    tmpDir = "cipher_rc4_test04.tmp"
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

local cases = {}
do
    local seed = 1
    for _, klen in ipairs({ 1, 2, 5, 7, 8, 13, 16, 32, 100, 255, 256 }) do
        for _, drop in ipairs({ 0, 1, 256, 768, 3072 }) do
            for _, n in ipairs({ 0, 1, 100, 5000 }) do
                seed = seed + 1
                local c = { key = randomBytes(klen, seed * 3), drop = drop, data = randomBytes(n, seed) }
                c.out = rc4.crypt(c.data, c.key, { drop = drop })
                cases[#cases + 1] = c
            end
        end
    end
end

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
    local n, skip = 0, 0
    for i, c in ipairs(cases) do
        if results[i] == "SKIP" then
            skip = skip + 1
        else
            assert(results[i] == tohex(c.out), format("%s: key %d bytes, drop %d, %d bytes: output differs",
                                                       name, #c.key, c.drop, #c.data))
            n = n + 1
        end
    end
    PRINT(format("%-12s: %d outputs identical, %d skipped", name, n, skip))
end

local function main()

PRINT("==================================================================================")
do
    local version = capture(OPENSSL .. " version 2>" .. devnull)
    local provider = "-provider legacy -provider default"
    if not version or not version:match("SSL") then
        skipped("openssl", "is not available")
    elseif not run(format("%s enc -rc4 %s -K 00112233445566778899aabbccddeeff -in %s -out %s 2>%s",
                          OPENSSL, provider, devnull, devnull, devnull))
       and not run(format("%s enc -rc4 -K 00112233445566778899aabbccddeeff -in %s -out %s 2>%s",
                          OPENSSL, devnull, devnull, devnull)) then
        skipped("openssl", "has no RC4")
    else
        if not run(format("%s enc -rc4 %s -K 00 -in %s -out %s 2>%s", OPENSSL, provider, devnull,
                          devnull, devnull)) then
            provider = ""   -- OpenSSL 1.x: no providers
        end
        local n, inName, outName = 0, tmpFile("ossl.in"), tmpFile("ossl.out")
        for _, c in ipairs(cases) do
            local cipherName = (#c.key == 16) and "rc4" or (#c.key == 5) and "rc4-40" or nil
            if cipherName and c.drop == 0 then
                writeFile(inName, c.data)
                assert(run(format('%s enc -%s %s -K %s -in "%s" -out "%s"', OPENSSL, cipherName, provider,
                                  tohex(c.key), inName, outName)), "openssl enc failed")
                assert(readFile(outName) == c.out, format("openssl %s %d bytes: output differs", cipherName,
                                                          #c.data))
                n = n + 1
            end
        end
        PRINT(format("openssl     : %d outputs identical (rc4, rc4-40)", n))
    end
end
PRINT("==================================================================================")
local jobs = tmpFile("jobs")
do
    local lines = {}
    for _, c in ipairs(cases) do
        lines[#lines + 1] = format("%s %d %s", tohex(c.key), c.drop, tohex(c.data))
    end
    writeFile(jobs, table.concat(lines, "\n") .. "\n")
end
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
do
    local v = capture(PERL .. ' -e "print 1" 2>' .. devnull)
    if v ~= "1" then
        skipped("rc4", "is not available (no Perl)")
        skipped("cryptx", "is not available (no Perl)")
    else
        for _, backend in ipairs({ "rc4", "cryptx" }) do
            compareHelper(backend, format('%s "%stest04.pl" %s "%s" 2>%s', PERL, here, backend, jobs, devnull))
        end
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
