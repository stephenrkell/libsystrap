THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE)))

default: extract build config.mk

# Things we need to build
# opdis
# libiberty, libopcodes, bfd
# zlib
# eglibc
# liballocs (headers only), dwarfidl (tools only) => libsrk31c++, libc++fileno, libdwarfpp   but not PIC builds of these

EGLIBC_TAR := eglibc-2.19-svnr25243.tar.bz2
OPDIS_REPO := https://github.com/mkfs/opdis.git
ZLIB_TAR := zlib-1.2.8.tar.gz
BINUTILS_TAR := binutils-2.25.tar.gz
LIBALLOCS_REPO := https://github.com/stephenrkell/liballocs.git
DWARFIDL_REPO := https://github.com/stephenrkell/dwarfidl.git

.PHONY: build
build: build-opdis build-binutils build-zlib build-eglibc build-liballocs build-dwarfidl

.PHONY: build-opdis
build-opdis: extract-opdis build-binutils

.PHONY: build-binutils
build-binutils: extract-binutils build-zlib

.PHONY: build-zlib
build-zlib: extract-zlib

.PHONY: build-eglibc
build-eglibc: extract-eglibc

.PHONY: build-liballocs
build-liballocs: extract-liballocs build-dwarfidl

.PHONY: build-dwarfidl
build-dwarfidl: extract-dwarfidl

# ----------------------------------------------

.PHONY: extract
extract: extract-eglibc extract-opdis extract-zlib extract-binutils extract-dwarfidl extract-liballocs

.PHONY: extract-eglibc
extract-eglibc: $(EGLIBC_TAR)
	test -d $$( ls -td eglibc-* | head -n1 ) || tar -k -xjf "$<"
$(EGLIBC_TAR):
	wget http://downloads.yoctoproject.org/releases/eglibc/$(EGLIBC_TAR)
build-eglibc:
	eglibc_dir="$$( ls -td eglibc-* | head -n1 )"/libc || exit 1; \
	(test -e "$$eglibc_dir"/build/config.log && \
	        ! grep 'exit 1' "$$eglibc_dir"/build/config.log) || \
	    (cd "$$eglibc_dir" && mkdir -p build && cd build && \
	CFLAGS="-g -O2" ../configure --prefix=/usr); \
	cd "$$eglibc_dir"/build && $(MAKE) -j3

.PHONY: extract-opdis
extract-opdis:
	test -e opdis/configure || (git clone $(OPDIS_REPO) && cd opdis && ./bootstrap)
build-opdis: build-binutils
	(test -e opdis-build/config.log && ! grep 'exit 1' opdis-build/config.log) || (mkdir -p opdis-build && cd opdis-build && CPPFLAGS="-I$(CONTRIB)/binutils-2.25/include -I$(CONTRIB)/binutils-build/bfd" CFLAGS="-fPIC -g -I$(CONTRIB)/binutils-2.25/include -I$(CONTRIB)/binutils-build/bfd" LDFLAGS="-L$(CONTRIB)/binutils-build/libiberty -L$(CONTRIB)/binutils-build/bfd -L$(CONTRIB)/binutils-build/intl -L$(CONTRIB)/binutils-build/opcodes" ../opdis/configure && $(MAKE) -j3)

.PHONY: extract-zlib
extract-zlib: $(ZLIB_TAR)
	test -e zlib-1.2.8/configure || tar -k -xzf "$<"
$(ZLIB_TAR): 
	wget http://zlib.net/$(ZLIB_TAR)
build-zlib:
	cd $$( ls -td zlib-* | grep -v "$(ZLIB_TAR)" | head -n1 ) && (test -e configure.log && ! grep 'exit 1' configure.log) || CFLAGS="-fPIC" ./configure
	cd $$( ls -td zlib-* | grep -v "$(ZLIB_TAR)" | head -n1 ) && $(MAKE) -j3

.PHONY: extract-binutils
extract-binutils: $(BINUTILS_TAR)
	test -e binutils-2.25/configure || tar -k -xzf "$(BINUTILS_TAR)"
$(BINUTILS_TAR): 
	wget http://ftp.gnu.org/gnu/binutils/$(BINUTILS_TAR)
build-binutils: build-binutils-libiberty build-binutils-bfd build-binutils-opcodes build-binutils-intl
build-binutils-%: extract-binutils
	(test -e binutils-build/$*/config.log && ! grep 'exit 1' binutils-build/$*/config.log) || (mkdir -p binutils-build/$*  && cd binutils-build/$* && CFLAGS="-fPIC -g -O2" $$( ls -td ../../binutils-2.* | grep -v $(BINUTILS_TAR) | head -n1)/$*/configure)
	cd binutils-build/$*  && $(MAKE) -j3 

.PHONY: extract-dwarfidl
extract-dwarfidl:
	test -d dwarfidl/.git || git clone $(DWARFIDL_REPO)
build-dwarfidl:
	cd dwarfidl/contrib && ./checkout.sh
	cd dwarfidl && $(MAKE)

.PHONY: extract
extract: extract-eglibc extract-opdis extract-zlib extract-binutils extract-dwarfidl extract-liballocs

.PHONY: extract-liballocs
extract-liballocs:
	test -d liballocs/.git || git clone $(LIBALLOCS_REPO)
build-liballocs: build-dwarfidl
	cd liballocs && cp ../dwarfidl/src/makefile ./

config.mk:
	echo 'CONTRIB := $(realpath $(dir $@)) \n\
LIBC_DIR := $(wildcard $(CONTRIB)/eglibc-*/libc/build) \n\
LIBC_A := $$(LIBC_DIR)/libc_pic.a $$(LIBC_DIR)/libc_nonshared.a \n\
RTLD_OBJ_DIR := $$(LIBC_DIR)/elf\n\
RTLD_SO := $$(RTLD_OBJ_DIR)/ld.so\n\
RTLD_LIBC_A := $$(RTLD_OBJ_DIR)/rtld-libc.a\n\
LIBOPDIS_A := $$(CONTRIB)/opdis-build/dist/.libs/libopdis.a \n\
LIBOPCODES_DIR := $$(CONTRIB)/binutils-2.25 \n\
BFD_DIR := $$(CONTRIB)/binutils-build/bfd \n\
LIBOPCODES_A := $$(CONTRIB)/binutils-build/opcodes/libopcodes.a \n\
LIBBFD_A := $$(CONTRIB)/binutils-build/bfd/libbfd.a \n\
LIBIBERTY_A := $$(CONTRIB)/binutils-build/libiberty/libiberty.a \n\
LIBALLOCS_DIR := $$(CONTRIB)/liballocs \n\
DWARFIDL_DIR := $$(CONTRIB)/dwarfidl \n\
OPDIS_DIR := $$(CONTRIB)/opdis \n\
ZLIB_A ?= $$(CONTRIB)/zlib-1.2.8/libz.a' | sed '/^\\$$/ d' | sed 's/ *$$//' > "$@"
