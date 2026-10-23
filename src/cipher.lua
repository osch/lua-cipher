--[[
    cipher - the meta module of lua-cipher.

    Gives access to the cipher modules of lua-cipher under one name:
    cipher.aes is the module "cipher.aes", cipher.rc4 the module
    "cipher.rc4". A submodule is loaded with require() on its first access,
    so only the modules actually used are loaded; afterwards it is cached in
    this table. require("cipher").aes and require("cipher.aes") are the same
    object.

    Only the names of the modules of lua-cipher are looked up (cipher.names).
    Errors of require() (e.g. a module that is not installed) are raised on
    access. Any other key gives nil, as for an ordinary table.

    See doc/README.md.
--]]

local require      = require
local rawset       = rawset
local type         = type
local ipairs       = ipairs
local setmetatable = setmetatable

local cipher = {}

cipher._VERSION = "0.0.1"

-- the modules of lua-cipher that this meta module loads, in this order also
-- documented in doc/README.md; the meta rock depends on all of them
cipher.names = { "aes", "rc4", "chacha20", "des" }

local known = {}
for _, name in ipairs(cipher.names) do
    known[name] = true
end

setmetatable(cipher, {
    __metatable = "cipher",
    __index = function(self, key)
        if type(key) == "string" and known[key] then
            local module = require("cipher." .. key)
            rawset(self, key, module)
            return module
        end
        return nil
    end,
})

return cipher
