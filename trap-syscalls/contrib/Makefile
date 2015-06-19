default: download build config.mk

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

.PHONY: build-opdis
build-opdis: download-opdis build-binutils

.PHONY: build-binutils
build-binutils: download-binutils build-zlib

.PHONY: build-zlib
build-zlib: download-zlib

.PHONY: build-eglibc
build-eglibc: download-eglibc

.PHONY: build-liballocs
build-liballocs: download-liballocs build-dwarfidl

.PHONY: build-dwarfidl
build-dwarfidl: download-dwarfidl

# ----------------------------------------------

.PHONY: download-eglibc
download-eglibc: $(EGLIBC_TAR)
	tar -k -xjf "$<"
$(EGLIBC_TAR):
	wget http://downloads.yoctoproject.org/releases/eglibc/$(EGLIBC_TAR)
build-eglibc:
	cd $$( ls -td eglibc-* | head -n1 )/libc && mkdir -p build && cd build && \
	CFLAGS="-g -O2" ../configure --prefix=/usr && \
	$(MAKE) -j3
	
.PHONY: download-opdis
download-opdis:
	git clone $(OPDIS_REPO)
build-opdis:
	mkdir -p opdis-build && CFLAGS="-fPIC -g" ../opdis/configure && $(MAKE) -j3

.PHONY: download-zlib
download-zlib: $(ZLIB_TAR)
	tar -k -xzf "$<"
$(ZLIB_TAR): 
	wget http://zlib.net/$(ZLIB_TAR)
build-zlib:
	cd $$( ls -td zlib-* | head -n1 ) && CFLAGS="-fPIC" ./configure && $(MAKE) -j3

.PHONY: download-binutils
download-binutils: $(BINUTILS_TAR)
	tar -k -xzf "$(BINUTILS_TAR)"
$(BINUTILS_TAR): 
	wget http://ftp.gnu.org/gnu/binutils/$(BINUTILS_TAR)
build-binutils:
	mkdir -p binutils-build/libiberty  && cd binutils-build/libiberty  && CFLAGS="-fPIC -g -O2" $$( ls -td ../../binutils-[0-9]* | head -n1)/libiberty/configure && $(MAKE) -j3
	mkdir -p binutils-build/bfd        && cd binutils-build/bfd        && CFLAGS="-fPIC -g -O2" $$( ls -td ../../binutils-[0-9]* | head -n1)/bfd/configure && $(MAKE) -j3
	mkdir -p binutils-build/opcodes    && cd binutils-build/opcodes    && CFLAGS="-fPIC -g -O2" $$( ls -td ../../binutils-[0-9]* | head -n1)/opcodes/configure && $(MAKE) -j3

.PHONY: download-dwarfidl
download-dwarfidl:
	git clone $(DWARFIDL_REPO)
build-dwarfidl:
	cd dwarfidl/contrib && ./checkout.sh
	cd dwarfidl && $(MAKE)

.PHONY: download-liballocs
download-liballocs:
	git clone $(LIBALLOCS_REPO)
build-liballocs:
	cd liballocs && cp ../dwarfidl/src/makefile ./

config.mk:
	echo -e 'THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST)) \n\
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE))) \n\
LIBALLOCS := $(CONTRIB)/liballocs \n\
LIBC_A += $(CONTRIB)/$$( ls -td eglibc-* | head -n1 )/libc/build/libc_pic.a $(CONTRIB)/eglibc-2.19/libc/build/libc_nonshared.a \n\
LIBOPDIS_A := $(CONTRIB)/opdis-build/dist/.libs/libopdis.a \n\
LIBOPCODES_A := $(CONTRIB)/binutils-build/opcodes/libopcodes.a \n\
LIBBFD_A := $(CONTRIB)/binutils-build/bfd/libbfd.a \n\
LIBIBERTY_A := $(CONTRIB)/binutils-build/libiberty/libiberty.a \n\
ZLIB_A ?= $(CONTRIB)/zlib-1.2.8/libz.a' > "$@"
