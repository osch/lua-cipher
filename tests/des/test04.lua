-- Compares cipher.des with other DES and Triple DES implementations on this machine, in
-- both directions (their encryption with ours, our ciphertext decrypted by them):
--
--   * the command line tool openssl ("openssl enc -des-*", "-des-ede-*", "-des-ede3-*":
--     modes ecb, cbc, cfb, cfb8, ofb; single DES with the legacy provider of OpenSSL 3),
--   * the Python packages cryptography (TripleDES: all modes except ctr) and pycryptodome
--     (DES, DES3: all modes), helper test04.py,
--   * the Perl modules of CryptX (Crypt::Mode::* with DES and DES_EDE), Crypt::DES and
--     Crypt::DES_EDE3 (single blocks), Crypt::CBC (with Crypt::DES and Crypt::DES_EDE3),
--     helper test04.pl.
--
-- Each part is skipped if the tool or module is not installed. CIPHER_TEST_REQUIRE gives a
-- comma separated list of parts that must not be skipped (openssl, cryptography,
-- pycryptodome, cryptx, des, cbc). CIPHER_TEST_OPENSSL, CIPHER_TEST_PYTHON and
-- CIPHER_TEST_PERL name the programs (default openssl, python3 or python, perl; a path
-- without spaces).

local des = require("cipher.des")

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
    tmpDir = "cipher_des_test04.tmp"
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
local SIZES = { 0, 1, 7, 8, 9, 15, 16, 17, 100, 1000, 4103 }
local MODES = { "ecb", "cbc", "cfb", "cfb8", "ofb", "ctr" }
local cases = {}
do
    local seed = 1
    for _, mode in ipairs(MODES) do
        for _, klen in ipairs({ 8, 16, 24 }) do
            local paddings = (mode == "ecb" or mode == "cbc") and { "pkcs7", "none" } or { "none" }
            for _, padding in ipairs(paddings) do
                for _, n in ipairs(SIZES) do
                    if padding ~= "none" or (mode ~= "ecb" and mode ~= "cbc") or n % 8 == 0 then
                        seed = seed + 1
                        local c = { mode = mode, padding = padding,
                                    key = randomBytes(klen, seed * 3),
                                    iv = (mode ~= "ecb") and randomBytes(8, seed * 5) or "",
                                    data = randomBytes(n, seed * 7) }
                        local opts = { mode = mode, iv = (c.iv ~= "") and c.iv or nil, padding = padding }
                        c.ct = des.encrypt(c.data, c.key, opts)
                        cases[#cases + 1] = c
                    end
                end
            end
        end
    end
end

local function jobLines()
    local lines = {}
    for _, c in ipairs(cases) do
        local common = format("%s %s %s %s", c.mode, tohex(c.key), tohex(c.iv), c.padding)
        lines[#lines + 1] = format("enc %s %s", common, tohex(c.data))
        lines[#lines + 1] = format("dec %s %s", common, tohex(c.ct))
    end
    return table.concat(lines, "\n") .. "\n"
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
    assert(#results == 2 * #cases, format("%s: %d results for %d jobs", name, #results, 2 * #cases))
    local counts, modes, keys = { enc = 0, dec = 0, skip = 0 }, {}, {}
    for i, c in ipairs(cases) do
        local r1, r2 = results[2 * i - 1], results[2 * i]
        local what = format("%s: %s key %d, padding %s, %d bytes", name, c.mode, #c.key, c.padding, #c.data)
        if r1 == "SKIP" then
            counts.skip = counts.skip + 1
        else
            assert(r1 == tohex(c.ct), what .. ": encryption differs: " .. r1:sub(1, 80))
            counts.enc = counts.enc + 1
            modes[c.mode] = true
            keys[#c.key] = true
        end
        if r2 == "SKIP" then
            counts.skip = counts.skip + 1
        else
            assert(r2 == tohex(c.data), what .. ": decryption differs: " .. r2:sub(1, 80))
            counts.dec = counts.dec + 1
            modes[c.mode] = true
            keys[#c.key] = true
        end
    end
    local list = {}
    for _, m in ipairs(MODES) do
        if modes[m] then list[#list + 1] = m end
    end
    local klist = {}
    for _, k in ipairs({ 8, 16, 24 }) do
        if keys[k] then klist[#klist + 1] = tostring(k) end
    end
    assert(counts.enc + counts.dec > 0, name .. ": no job was run")
    PRINT(format("%-12s: %d encryptions and %d decryptions identical (%s; keys %s), %d skipped", name,
                 counts.enc, counts.dec, table.concat(list, " "), table.concat(klist, " "), counts.skip))
end

-- the tests, run with pcall: the temporary files are removed also after a failure
local function main()

PRINT("==================================================================================")
-- openssl enc
do
    local version = capture(OPENSSL .. " version 2>" .. devnull)
    local provider = "-provider legacy -provider default"
    if not version or not version:match("SSL") then
        skipped("openssl", "is not available")
    else
        PRINT("openssl: " .. version:gsub("%s+$", ""))
        if not run(format("%s enc -des-ecb %s -K 0000000000000000 -in %s -out %s 2>%s", OPENSSL, provider,
                          devnull, devnull, devnull)) then
            provider = ""   -- OpenSSL 1.x: no providers
        end
        local n, inName, outName = 0, tmpFile("ossl.in"), tmpFile("ossl.out")
        local names = { [8] = "des-", [16] = "des-ede-", [24] = "des-ede3-" }
        local used, missing = {}, {}
        for _, c in ipairs(cases) do
            -- openssl enc has no des-ctr and no des-ede-cfb8
            local cipherName = names[#c.key] .. c.mode
            if c.mode ~= "ctr" and not (#c.key == 16 and c.mode == "cfb8") and not missing[cipherName]
               and (#c.data == 0 or #c.data == 9 or #c.data == 1000 or #c.data == 16) then
                local args = format("-K %s%s%s", tohex(c.key), (c.iv ~= "") and (" -iv " .. tohex(c.iv)) or "",
                                    (c.padding == "none") and " -nopad" or "")
                writeFile(inName, c.data)
                if not run(format('%s enc -%s %s %s -in "%s" -out "%s" 2>%s', OPENSSL, cipherName, provider, args,
                                  inName, outName, devnull)) then
                    -- e.g. single DES without the legacy provider of OpenSSL 3
                    missing[cipherName] = true
                    missing[#missing + 1] = cipherName
                else
                    assert(readFile(outName) == c.ct, format("openssl %s %d bytes: encryption differs", cipherName, #c.data))
                    writeFile(inName, c.ct)
                    assert(run(format('%s enc -d -%s %s %s -in "%s" -out "%s"', OPENSSL, cipherName, provider, args,
                                      inName, outName)), "openssl enc -d failed: " .. cipherName)
                    assert(readFile(outName) == c.data, format("openssl %s %d bytes: decryption differs", cipherName, #c.data))
                    n = n + 1
                    used[names[#c.key]] = true
                end
            end
        end
        local list = {}
        for _, k in ipairs({ 8, 16, 24 }) do
            if used[names[k]] then list[#list + 1] = names[k] .. "*" end
        end
        assert(n > 0, "openssl: no case was run")
        PRINT(format("openssl     : %d cases identical in both directions (%s; ecb cbc cfb cfb8 ofb)%s", n,
                     table.concat(list, " "), (#missing > 0) and ("; not available: " .. table.concat(missing, " ")) or ""))
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
        for _, backend in ipairs({ "cryptx", "des", "cbc" }) do
            skipped(backend, "is not available (no Perl)")
        end
    else
        for _, backend in ipairs({ "cryptx", "des", "cbc" }) do
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
