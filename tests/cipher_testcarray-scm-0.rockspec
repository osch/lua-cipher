-- Test helper for tests/*/test02.lua, not part of the lua-cipher rocks.
-- Install from the repository root: luarocks make tests/cipher_testcarray-scm-0.rockspec
package = "cipher_testcarray"
version = "scm-0"
source = {
  url = "https://github.com/osch/lua-cipher/archive/master.zip",
  dir = "lua-cipher-master",
}
description = {
  summary = "Test helper for lua-cipher: read-only and non-resizable carray objects",
  homepage = "https://github.com/osch/lua-cipher",
  license = "MIT",
}
dependencies = {
  "lua >= 5.1",
  "carray",
}
build = {
  type = "builtin",
  modules = {
    cipher_testcarray = {
      sources = { "tests/testcarray.c" },
    },
  },
}
