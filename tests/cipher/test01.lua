-- The meta module cipher: lazy loading of the submodules, identity with the modules
-- loaded directly, behaviour for unknown keys.

local format = string.format

local function PRINT(s)
    print(s.." ("..debug.getinfo(2).currentline..")")
end

PRINT("==================================================================================")
do
    -- nothing is loaded before the first access
    package.loaded["cipher.aes"] = nil
    package.loaded["cipher.rc4"] = nil
    package.loaded["cipher.chacha20"] = nil
    package.loaded["cipher.des"] = nil
    local cipher = require("cipher")
    PRINT(format("cipher %s, submodules: %s", cipher._VERSION, table.concat(cipher.names, ", ")))
    assert(type(cipher._VERSION) == "string" and cipher._VERSION:match("^%d+%.%d+%.%d+$"))
    assert(getmetatable(cipher) == "cipher")
    assert(rawget(cipher, "aes") == nil)
    assert(package.loaded["cipher.aes"] == nil)
    assert(rawget(cipher, "rc4") == nil)
    assert(package.loaded["cipher.rc4"] == nil)
    assert(rawget(cipher, "chacha20") == nil)
    assert(rawget(cipher, "des") == nil)

    -- the first access loads the module with require() and caches it
    local aes = cipher.aes
    assert(type(aes) == "table")
    assert(rawget(cipher, "aes") == aes)
    assert(package.loaded["cipher.aes"] == aes)
    assert(require("cipher.aes") == aes)
    assert(cipher.aes == aes)
    assert(require("cipher").aes == require("cipher.aes"))
    assert(package.loaded["cipher.rc4"] == nil)
    local key = ("k"):rep(16)
    assert(aes.decrypt(aes.encrypt("meta", key, { iv = key }), key, { iv = key }) == "meta")
end
PRINT("==================================================================================")
do
    -- the same for cipher.rc4
    local cipher = require("cipher")
    local rc4 = cipher.rc4
    assert(type(rc4) == "table")
    assert(rawget(cipher, "rc4") == rc4)
    assert(package.loaded["cipher.rc4"] == rc4)
    assert(require("cipher").rc4 == require("cipher.rc4"))
    assert(rc4.crypt(rc4.crypt("meta", "key"), "key") == "meta")
    assert(package.loaded["cipher.chacha20"] == nil)
    assert(package.loaded["cipher.des"] == nil)
end
PRINT("==================================================================================")
do
    -- the same for cipher.chacha20 and cipher.des
    local cipher = require("cipher")
    local chacha20 = cipher.chacha20
    assert(type(chacha20) == "table")
    assert(rawget(cipher, "chacha20") == chacha20)
    assert(package.loaded["cipher.chacha20"] == chacha20)
    assert(require("cipher").chacha20 == require("cipher.chacha20"))
    local key, nonce = ("k"):rep(32), ("n"):rep(12)
    local ct, tag = chacha20.encrypt("meta", key, { iv = nonce })
    assert(chacha20.decrypt(ct, key, { iv = nonce, tag = tag }) == "meta")
    assert(package.loaded["cipher.des"] == nil)
    local des = cipher.des
    assert(type(des) == "table")
    assert(rawget(cipher, "des") == des)
    assert(package.loaded["cipher.des"] == des)
    assert(require("cipher").des == require("cipher.des"))
    local dkey, iv = ("k"):rep(24), ("i"):rep(8)
    assert(des.decrypt(des.encrypt("meta", dkey, { iv = iv }), dkey, { iv = iv }) == "meta")
    local names = table.concat(cipher.names, ",")
    assert(names == "aes,rc4,chacha20,des", names)
end
PRINT("==================================================================================")
do
    -- every listed name is a module of the same name
    local cipher = require("cipher")
    for _, name in ipairs(cipher.names) do
        assert(cipher[name] == require("cipher." .. name), name)
    end
end
PRINT("==================================================================================")
do
    -- other keys give nil, as for an ordinary table, and are not looked up
    local cipher = require("cipher")
    assert(cipher.foo == nil)
    assert(cipher.AES == nil)
    assert(cipher.des3 == nil)
    assert(cipher.poly1305 == nil)
    assert(cipher[1] == nil)
    assert(cipher[true] == nil)
    assert(package.loaded["cipher.foo"] == nil)
end
PRINT("==================================================================================")
do
    -- errors of require() are raised on access: a listed module that cannot be found
    local cipher = require("cipher")
    local saved = package.loaded["cipher.aes"]
    rawset(cipher, "aes", nil)
    package.loaded["cipher.aes"] = nil
    local savedPreload = package.preload["cipher.aes"]
    package.preload["cipher.aes"] = function() error("test: load failure") end
    local ok, err = pcall(function() return cipher.aes end)
    assert(not ok and tostring(err):find("test: load failure", 1, true))
    assert(rawget(cipher, "aes") == nil)
    package.preload["cipher.aes"] = savedPreload
    package.loaded["cipher.aes"] = saved
    assert(cipher.aes == saved)
end
PRINT("==================================================================================")
print("OK.")
