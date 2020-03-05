THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE)))

KERNEL ?= $(shell uname -s)

.PHONY: default build
default: build config.mk

ifeq ($(KERNEL),Linux)
build: build-xed build-musl \
#build-liballocs build-dwarfidl build-libfootprints build-opdis build-binutils build-zlib build-eglibc build-udis86
else
ifeq ($(KERNEL),FreeBSD)
build: build-udis86
endif
endif

# don't remove intermediates
.SECONDARY:

# Things we need to build
# opdis
# libiberty, libopcodes, bfd
# zlib
# eglibc
# librunt (headers only), dwarfidl (tools only) => libsrk31c++, libc++fileno, libdwarfpp   but not PIC builds of these
# xed
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
XED_DIR := xed
MBUILD_DIR := mbuild
WGET := wget

# ----------------------------------------------

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

.PHONY: FORCE
FORCE: ;


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


.PHONY: build-xed
build-xed: $(XED_DIR) $(MBUILD_DIR)
	cd $(XED_DIR) && ./mfile.py install --install-dir=build --no-encoder --extra-flags='-fPIC'

config.mk:
	printf 'CONTRIB := $(realpath $(dir $@)) \n\
LIBC_CFLAGS := -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/obj/include -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/arch/x86_64 -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/include \n\
LIBC_A := $(realpath $(dir $(THIS_MAKEFILE)))/musl/lib/libc.a \n\
LIBC_DIR ?= $(wildcard $(CONTRIB)/eglibc-*/libc/build) \n\
LIBC_A ?= $$(LIBC_DIR)/libc_pic.a $$(LIBC_DIR)/libc_nonshared.a \n\
RTLD_OBJ_DIR ?= $$(LIBC_DIR)/elf\n\
RTLD_SO ?= $$(RTLD_OBJ_DIR)/ld.so\n\
RTLD_LIBC_A ?= $$(RTLD_OBJ_DIR)/rtld-libc.a\n\
LIBUDIS86_A ?= $$(CONTRIB)/udis86/libudis86/.libs/libudis86.a \n\
LIBOPDIS_A ?= $$(CONTRIB)/opdis-build/dist/.libs/libopdis.a \n\
LIBOPCODES_DIR ?= $$(CONTRIB)/binutils-2.26 \n\
BFD_DIR ?= $$(CONTRIB)/binutils-build/bfd \n\
LIBOPCODES_A ?= $$(CONTRIB)/binutils-build/opcodes/libopcodes.a \n\
LIBBFD_A ?= $$(CONTRIB)/binutils-build/bfd/libbfd.a \n\
LIBIBERTY_A ?= $$(CONTRIB)/binutils-build/libiberty/libiberty.a \n\
LIBRUNT_DIR ?= $$(CONTRIB)/librunt \n\
ANTLR3C_DIR ?= $$(CONTRIB)/libantlr3c-3.4 \n\
DWARFIDL_DIR ?= $$(CONTRIB)/dwarfidl \n\
OPDIS_DIR ?= $$(CONTRIB)/opdis \n\
UDIS86_DIR ?= $$(CONTRIB)/udis86 \n\
ZLIB_A ?= $$(CONTRIB)/zlib-1.2.8/libz.a \n\
XED_DIR ?= $$(CONTRIB)/$(XED_DIR)/build \n\
XED_A ?= $$(CONTRIB)/$(XED_DIR)/build/lib/libxed.a' | sed '/^\\$$/ d' | sed 's/ *$$//' > "$@"
