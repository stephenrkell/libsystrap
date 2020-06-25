THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE)))

KERNEL ?= $(shell uname -s)

.PHONY: default build
default: build config.mk $(CONTRIB)/env.sh

include config.mk

ifeq ($(KERNEL),Linux)
build: build-xed build-musl build-librunt \
#build-liballocs build-dwarfidl build-libfootprints build-opdis build-binutils build-zlib build-eglibc build-udis86
else
ifeq ($(KERNEL),FreeBSD)
build: build-udis86
endif
endif

# don't remove intermediates
.SECONDARY:

# Things we may need to build
# libudis86
# opdis
# binutils: libiberty, libopcodes, bfd  (for opdis)
# zlib  (for bfd)
# eglibc or musl
# xed
# mbuild (for xed)
# librunt
OPDIS_REPO := https://github.com/mkfs/opdis.git
UDIS86_REPO := https://github.com/vmt/udis86.git
ZLIB_DIR := zlib-1.2.8
ZLIB_TAR := zlib-1.2.8.tar.gz
# ZLIB_TAR_URL := http://zlib.net/zlib-1.2.8.tar.gz
# zlib.net removes non-current releases, so use Debian ftp
ZLIB_TAR_URL := http://cdn-fastly.deb.debian.org/debian/pool/main/z/zlib/zlib_1.2.8.dfsg.orig.tar.gz
BINUTILS_DIR := binutils-2.26
BINUTILS_TAR := binutils-2.26.tar.bz2
BINUTILS_TAR_URL := ftp://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.bz2
MBUILD_DIR := mbuild
WGET := wget

# ----------------------------we need some libc or other, to be self-contained

$(EGLIBC_TAR):
	$(WGET) http://downloads.yoctoproject.org/releases/eglibc/$(EGLIBC_TAR)
$(EGLIBC_DIR)/libc/configure: $(EGLIBC_TAR)
	tar -k -xvjf "$<"
	touch "$@"
# eglibc is VERY picky about its compiler flags
$(EGLIBC_DIR)/libc/build/Makefile: $(EGLIBC_DIR)/libc/configure | install-binutils
	mkdir -p $(EGLIBC_DIR)/libc/build
	cd $(EGLIBC_DIR)/libc/build && CFLAGS="-g -O1 -fPIC -DPIC" CPPFLAGS="" ../configure --prefix=/usr --with-binutils=$(CONTRIB)/bin # --with-sysroot=$(CONTRIB)
.PHONY: build-eglibc
build-eglibc: $(EGLIBC_DIR)/libc/build/Makefile
	CFLAGS="-g -O1 -fPIC -DPIC" CPPFLAGS="" $(MAKE) -C $(EGLIBC_DIR)/libc/build

.PHONY: build-musl
build-musl: musl/libc/libc.a
musl/config.mak:
	cd musl && ./configure

musl/libc/libc.a: musl/config.mak
	$(MAKE) -C musl

ifeq ($(KERNEL),Linux)
CONFIG_MK += \nLIBC_A := $(realpath $(dir $(THIS_MAKEFILE)))/musl/lib/libc.a\n
else
ifeq ($(KERNEL),FreeBSD) # FIXME: check this
CONFIG_MK += \nLIBC_A := /usr/lib/libc_pic.a\n
endif
endif
varlist += LIBC_A

# ----------------------------we need some instruction decoder or other

$(ZLIB_TAR):
	$(WGET) -O "$@" $(ZLIB_TAR_URL)
$(ZLIB_DIR)/configure: $(ZLIB_TAR)
	tar -k -xvzf "$<"
	touch "$@"
$(ZLIB_DIR)/Makefile: $(ZLIB_DIR)/configure
	cd $(ZLIB_DIR) && CFLAGS="-fPIC -DPIC" ./configure
.PHONY: build-zlib
build-zlib: $(ZLIB_DIR)/Makefile
	$(MAKE) -C $(ZLIB_DIR)

opdis/bootstrap:
	git clone $(OPDIS_REPO)
opdis/configure: opdis/bootstrap
	cd opdis && ./bootstrap
opdis-build/Makefile: opdis/configure | build-binutils
	mkdir -p opdis-build
	cd opdis-build && CPPFLAGS="-I$(CONTRIB)/binutils-2.26/include -I$(CONTRIB)/binutils-build/bfd" CFLAGS="-fPIC -g -I$(CONTRIB)/binutils-2.26/include -I$(CONTRIB)/binutils-build/bfd" LDFLAGS="-L$(CONTRIB)/binutils-build/libiberty -L$(CONTRIB)/binutils-build/bfd -L$(CONTRIB)/binutils-build/intl -L$(CONTRIB)/binutils-build/opcodes" ../opdis/configure
.PHONY: build-opdis
build-opdis: opdis-build/Makefile
	$(MAKE) -C opdis-build

.PHONY: build-udis86
build-udis86: udis86/Makefile
	$(MAKE) -C udis86
udis86/autogen.sh:
	git clone $(UDIS86_REPO)
udis86/configure: udis86/autogen.sh
	cd udis86 && ./autogen.sh
udis86/Makefile: udis86/configure
	cd udis86 && CFLAGS=-fPIC ./configure --enable-shared=no --enable-static=yes

$(BINUTILS_TAR):
	$(WGET) $(BINUTILS_TAR_URL)
$(BINUTILS_DIR)/configure: $(BINUTILS_TAR)
	tar -k -xjf "$(BINUTILS_TAR)"
	touch "$@"

#binutils-build/Makefile: $(BINUTILS_DIR)/configure
#	mkdir -p binutils-build
#	cd binutils-build && CFLAGS="-g -O2 -fPIC -DPIC" ../$(BINUTILS_DIR)/configure --prefix=$(CONTRIB) --enable-ld --disable-gold --disable-multilib --disable-bootstrap --without-x --without-system-zlib

# NOT -DPIC because that breaks libintl
# and don't bother to build the docs
# yes, MAKEINFO=true actually accomplishes that ¬_¬
binutils-build/Makefile: $(BINUTILS_DIR)/configure
	mkdir -p binutils-build
	cd binutils-build && CFLAGS="-g -O2 -fPIC" ../$(BINUTILS_DIR)/$*/configure --prefix=$(CONTRIB) --without-included-gettext --disable-bootstrap --enable-ld --disable-gold --without-x --with-sysroot=$(CONTRIB)

# gah binutils
.PHONY: build-binutils
build-binutils: binutils-build/Makefile
	$(MAKE) -C binutils-build MAKEINFO=/bin/true

.PHONY: install-binutils
install-binutils: build-binutils
	$(MAKE) -C binutils-build install MAKEINFO=/bin/true

# ----------------------------xed

.PHONY: build-xed
build-xed: $(MBUILD_DIR)
	cd xed && ./mfile.py install --install-dir=build --no-encoder --extra-flags='-fPIC'

CONFIG_MK +=\nXED_DIR ?= $(CONTRIB)/xed/build\n
CONFIG_MK +=\nXED_A ?= $(CONTRIB)/xed/build/lib/libxed.a\n
varlist += XED_DIR XED_A

# ----------------------------librunt

.PHONY: build-librunt
build-librunt: librunt/lib/librunt_preload.a
librunt/lib/librunt_preload.a: librunt/Makefile
	cd librunt && $(MAKE)
# librunt is not yet autotools'd
#librunt/Makefile: librunt/configure
#	cd librunt && ./configure
#librunt/configure: librunt/configure.ac
#	cd librunt && ./autogen.sh

CONFIG_MK +=\nLIBRUNT_DIR ?= $(realpath $(CONTRIB)/librunt)\n
CONFIG_MK +=\nLIBRUNT_CFLAGS ?= -I$(CONTRIB)/librunt/include\n
CONFIG_MK +=\nLIBRUNT_LDFLAGS ?= -L$(CONTRIB)/librunt/lib -Wl,-rpath,$(CONTRIB)/librunt/lib
# non-autoconf'd stuff (liballocs, libsystrap) may expect LIBRUNT_DIR
varlist += LIBRUNT_CFLAGS LIBRUNT_LDFLAGS LIBRUNT_DIR

# ----------------------------config.mk

# If the user nukes a sub-config.mk that our config.mk depends on,
# we'd like to be able to rebuild it. So we include a generic rule
# for rebuilding config.mks.
config.mk: $(subconfigs)
	(printf '%%/config.mk:\n\t$$(MAKE) -C $$* config.mk\n\n'; \
	printf "$(foreach cfg,$(subconfigs),\ninclude $(CONTRIB)/$(cfg))"; \
	printf '$(CONFIG_MK)'; echo) > "$@" || (rm -f "$@"; false)
# env.sh exports some vars
env.sh $(CONTRIB)/env.sh: $(foreach cfg,$(subconfigs),$(dir $(CONTRIB)/$(cfg))env.sh)
	(printf "$(foreach cfg,$(subconfigs),\n. $$(dirname $(CONTRIB)/$(cfg))/env.sh)"; \
	printf '$(foreach var,$(varlist),\nexport $(var)="$($(var))")'; echo )>"$@" || (rm -f "$@"; false)
# Similarly when we make an env.sh, have Make ensure existence of
# its depended-on env.sh too, so that we don't get 'source'-time
# failures of sub-env.sh.
$(foreach cfg,$(subconfigs),$(dir $(CONTRIB)/$(cfg))env.sh): %/env.sh:
	$(MAKE) -C $* env.sh
clean::
	rm -f config.mk env.sh
