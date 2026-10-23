-- Test helper for tests/*/test03.lua, not part of the lua-cipher rocks.
-- Install from the repository root: luarocks make tests/cipher_multistate-scm-0.rockspec
package = "cipher_multistate"
version = "scm-0"
source = {
  url = "https://github.com/osch/lua-cipher/archive/master.zip",
  dir = "lua-cipher-master",
}
description = {
  summary = "Test helper for lua-cipher: independent Lua states and parallel threads",
  homepage = "https://github.com/osch/lua-cipher",
  license = "MIT",
}
dependencies = {
  "lua >= 5.1",
}
build = {
  type = "builtin",
  modules = {
    cipher_multistate = {
      sources = { "tests/multistate.c" },
    },
  },
  platforms = {
    unix = {
      modules = {
        cipher_multistate = {
          libraries = { "pthread" },
        },
      },
    },
  },
}
