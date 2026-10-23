.PHONY: default all aes rc4 chacha20 des multistate testcarray
default: all
all: aes rc4 chacha20 des

BUILD_DATE  := $(shell date "+%Y-%m-%dT%H:%M:%S")

LNX_GCC_RUN := gcc -shared -fPIC -O2 -g -Werror=return-type
WIN_GCC_RUN := gcc -shared -fPIC -O2
MAC_GCC_RUN := MACOSX_DEPLOYMENT_TARGET=10.8 gcc -O2 -bundle -undefined dynamic_lookup -all_load

LNX_COPTS   :=
WIN_COPTS   := -I/mingw64/include/lua5.1
MAC_COPTS   := -I/usr/local/opt/lua/include/lua5.3

LNX_LOPTS   :=
WIN_LOPTS   :=
MAC_LOPTS   :=

LNX_SO_EXT  := so
WIN_SO_EXT  := dll
MAC_SO_EXT  := so

GCC_RUN     :=
SO_EXT      :=
COPTS       :=
LOPTS       :=

# platforms: LNX, WIN, MAC
# (may be set in sandbox.mk)

PLATFORM    := LNX
LUA_VERSION := 5.5

-include sandbox.mk

GCC_RUN       := $(or $(GCC_RUN),       $($(PLATFORM)_GCC_RUN))
SO_EXT        := $(or $(SO_EXT),        $($(PLATFORM)_SO_EXT))
COPTS         := $(or $(COPTS),         $($(PLATFORM)_COPTS))
LOPTS         := $(or $(LOPTS),         $($(PLATFORM)_LOPTS))

OUT_DIR       := build/lua$(LUA_VERSION)

# module cipher.aes -> build/lua$(LUA_VERSION)/cipher/aes.$(SO_EXT)
aes:
	@mkdir -p $(OUT_DIR)/cipher/
	$(GCC_RUN) $(COPTS) \
	    -D CIPHER_AES_VERSION=Makefile"-$(BUILD_DATE)" \
	    aes/main.c aes/aesmod.c aes/aes_ct64.c aes/ghash.c \
	    aes/aes_compat.c  \
	    $(LOPTS) \
	    -o $(OUT_DIR)/cipher/aes.$(SO_EXT)

# module cipher.rc4 -> build/lua$(LUA_VERSION)/cipher/rc4.$(SO_EXT)
rc4:
	@mkdir -p $(OUT_DIR)/cipher/
	$(GCC_RUN) $(COPTS) \
	    -D CIPHER_RC4_VERSION=Makefile"-$(BUILD_DATE)" \
	    rc4/main.c rc4/rc4mod.c \
	    rc4/rc4_compat.c  \
	    $(LOPTS) \
	    -o $(OUT_DIR)/cipher/rc4.$(SO_EXT)

# module cipher.chacha20 -> build/lua$(LUA_VERSION)/cipher/chacha20.$(SO_EXT)
chacha20:
	@mkdir -p $(OUT_DIR)/cipher/
	$(GCC_RUN) $(COPTS) \
	    -D CIPHER_CHACHA20_VERSION=Makefile"-$(BUILD_DATE)" \
	    chacha20/main.c chacha20/chacha20mod.c chacha20/chacha.c chacha20/poly1305.c \
	    chacha20/chacha20_compat.c  \
	    $(LOPTS) \
	    -o $(OUT_DIR)/cipher/chacha20.$(SO_EXT)

# module cipher.des -> build/lua$(LUA_VERSION)/cipher/des.$(SO_EXT)
des:
	@mkdir -p $(OUT_DIR)/cipher/
	$(GCC_RUN) $(COPTS) \
	    -D CIPHER_DES_VERSION=Makefile"-$(BUILD_DATE)" \
	    des/main.c des/desmod.c des/des_ct.c \
	    des/des_compat.c  \
	    $(LOPTS) \
	    -o $(OUT_DIR)/cipher/des.$(SO_EXT)

# Test helper module for tests/*/test02.lua (read-only and non-resizable carrays)
testcarray:
	@mkdir -p $(OUT_DIR)/
	$(GCC_RUN) $(COPTS) \
	    ../tests/testcarray.c \
	    -o $(OUT_DIR)/cipher_testcarray.$(SO_EXT)

# Test helper module for tests/*/test03.lua (several Lua states, parallel threads)
multistate:
	@mkdir -p $(OUT_DIR)/
	$(GCC_RUN) $(COPTS) \
	    ../tests/multistate.c \
	    $(if $(filter WIN,$(PLATFORM)),,-lpthread) \
	    -o $(OUT_DIR)/cipher_multistate.$(SO_EXT)
