#!/usr/bin/lua
--
-- Sets the version of all release rockspecs in this directory and the _VERSION
-- of the meta module (../src/cipher.lua), e.g. "lua setversion.lua 0.0.2".
-- All rocks of lua-cipher are released together with the same version.

os.setlocale("C")

local format = string.format
local lfs    = require("lfs")

local version = ...
assert(version and version:match("^%d+%.%d+%.%d+$"), format("invalid version %q", tostring(version)))

local function rewrite(fileName, newName, pattern)
    local out = {}
    local matched = false
    local inFile = assert(io.open(fileName, "r"))
    for line in inFile:lines() do
        local l1, l2 = line:match(pattern)
        if l1 then
            assert(not matched)
            matched = true
            out[#out+1] = l1..version..l2
        else
            out[#out+1] = line
        end
    end
    out[#out+1] = ""
    inFile:close()
    assert(matched, format("no version found in %s", fileName))
    local newFile, err = io.open(newName, "w")
    assert(newFile, err)
    newFile:write(table.concat(out, "\n"))
    newFile:close()
    if fileName ~= newName then
        os.remove(fileName)
    end
end

for fileName in lfs.dir(".") do
    local p1, v, p2 = fileName:match("^(cipher[%.%w]*%-)(%d+%.%d+%.%d+)(%-%d+%.rockspec)$")
    if p1 then
        local newName = p1..version..p2
        print(format("%-36s -> %s", fileName, newName))
        rewrite(fileName, newName, "^(%s*version%s*%=%s*\")%d+%.%d+%.%d+(%-%d+\"%s*)$")
    end
end

print(format("%-36s -> _VERSION = %q", "../src/cipher.lua", version))
rewrite("../src/cipher.lua", "../src/cipher.lua",
        "^(%s*cipher%._VERSION%s*%=%s*\")%d+%.%d+%.%d+(\"%s*)$")
