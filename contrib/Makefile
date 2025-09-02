THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CONTRIB := $(realpath $(dir $(THIS_MAKEFILE)))

KERNEL ?= $(shell uname -s)
$(info Building for kernel: $(KERNEL))

.PHONY: default clean
default: build.stamp config.mk $(CONTRIB)/env.sh

# our own config.mk may need to expand 'arch', so define it nice and early
arch := $(shell uname -m)
include config.mk

ifeq ($(KERNEL),Linux)
build.stamp: build-xed build-musl build-librunt
else
ifeq ($(KERNEL),FreeBSD)
build.stamp: build-udis86
$(error FIXME: make xed build on FreeBSD)
endif
endif
	touch $@

clean::
	rm -f build.stamp

# don't remove intermediates
.SECONDARY:

MBUILD_DIR := mbuild

# ----------------------------we need some libc or other, to be self-contained

# TODO: multiarch musl build. What do we need to do?
# Possibly simplest:
# (1) always build in a build dir, not default/top-level
# (2) name the build dir after the arch
# (3) on x86-64, special-case an extra -m32 build.
# We will need to change LIBC_A because there can be more than one of them...
#    LIBC_A_PATTERN? i.e. we sub in the arch, although it can be a no-op on other arches
.PHONY: build-musl
build-musl: musl/build-$(arch)/lib/libc.a host-includes-$(arch)
musl/build-$(arch)/config.mak:
	mkdir -p $(dir $@) && cd $(dir $@) && CFLAGS=-g ../configure
musl/%/lib/libc.a: musl/%/config.mak
	$(MAKE) -C musl/$*

# on x86-64, also build the -m32 version
# XXX: This is still failing, because we are trying too hard
# to coerce musl to do the -m32 build... e.g. we are still pulling in
# 64-bit libgcc, for some reason, and the RANLIB hack does not work (i386-ranlib not found).
# Does musl support an -m32 build? as opposed to a fully general cross-compilation?
ifeq ($(arch),x86_64)
build-musl: musl/build-i386/lib/libc.a host-includes-i386
# our CC is probed by the shell snippet, so ensure it's exported... ditto AR, RANLIB
AR ?= ar
AS ?= as
export CC AR
# at some point I needed this compiler flag for musl...
# -DSYS_socketcall=__NR_socketcall
# ... but no longer
musl/build-i386/config.mak:
	mkdir -p $(dir $@) && cd $(dir $@) && \
	RANLIB="$${AR} -s" \
	AR="$${AR}" \
	LIBCC="$$( $${CC} -m32 -print-libgcc-file-name )" \
	CC="$${CC} -m32" \
	AS="$${AS} -m32" \
	LDFLAGS="-Wl,-melf_i386" \
	CFLAGS="$${CFLAGS} -g" ../configure --target=i386
musl/build-i386/lib/libc.a: musl/build-i386/config.mak
	$(MAKE) -C musl/build-i386
clean::
	$(MAKE) -C musl/build-i386 clean
	rm -f musl/build-i386/{Makefile,config.mak}
endif

# HACK: we rewrite 386 to 686... this should not be necessary, might be Debian-specific?
# HACK: on my Debian system I have /usr/i686-linux-gnu/include but /usr/include/x86_64-linux-gnu
# and no /usr/x86_64-linux-gnu/include... this is very unsatisfying.
host-includes-%:
	triple="$$( if [ "$*" = "i386" ] && [ "$$(uname -m)" = "x86_64" ]; then gcc -m32 -print-multiarch; else gcc -print-multiarch; fi )"; \
	mkdir -p $@ && for d in /usr/include/linux \
 /usr/include/asm-generic \
 /usr/$$( echo "$${triple}" | sed 's/386/686/' )/include/asm; do \
     echo "Expecting to use system include dir $${d}, so symlinking to it"; \
     { test -e "$$d" && ln -s -t $@ "$$d"; } || \
      { d="$$(echo "$$d" | sed "s^/usr/$${triple}/include^/usr/include/$${triple}^" )"; test -e "$$d" \
       && echo "Fell back to $$d" && ln -s -t $@ "$$d"; }  ; \
done

clean::
	$(MAKE) -C musl/build-$(arch) clean
	rm -f musl/build-$(arch)/{Makefile,config.mak}
	rm -rf host-includes-*

# musl always uses a 64-bit off_t.
# This matters both for our client code in the main repo
# *and* for the things we build here that need to link with musl, namely
# librunt and xed.
MUSL_ABI_CFLAGS := -D_FILE_OFFSET_BITS=64

ifeq ($(KERNEL),Linux)
CONFIG_MK += \nLIBC_A_PATTERN := $(realpath $(dir $(THIS_MAKEFILE)))/musl/build-$${arch}/lib/libc.a\n
CONFIG_MK += \nLIBC_CFLAGS_PATTERN := -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/arch/$${arch} -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/arch/generic -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/build-$${arch}/obj/include -I$(realpath $(dir $(THIS_MAKEFILE)))/musl/include -I$(realpath $(dir $(THIS_MAKEFILE)))/host-includes-$${arch} \n
# musl always uses a 64-bit off_t
CONFIG_MK += \nLIBC_CFLAGS_PATTERN += $(MUSL_ABI_CFLAGS)\n
else
ifeq ($(KERNEL),FreeBSD) # FIXME: check this
CONFIG_MK += \nLIBC_A_PATTERN := /usr/lib/libc_pic.a\n
CONFIG_MK += \nLIBC_CFLAGS_PATTERN :=
endif
endif
varlist += LIBC_A_PATTERN LIBC_CFLAGS_PATTERN

# Remember that we include CONFIG_MK ourselves, so we also get this var to use.
# BUT the quoting isn't quite right! LIBC_CFLAGS_PATTERN is supposed to be
# a pattern, so the ${arch} part should not be expanded. But currently it
# is. Not sure what to do about this... use a different pattern-expander tool/syntax?
# $(info LIBC_CFLAGS_PATTERN is $(LIBC_CFLAGS_PATTERN))

# ----------------------------xed

.PHONY: build-xed
build-xed: xed/build-$(arch)/lib/libxed.a
xed/build-$(arch)/lib/libxed.a: $(MBUILD_DIR)
	cd xed && ./mfile.py install --build-dir=obj-$(arch) --install-dir=build-$(arch) --no-encoder \
	  --extra-flags='-fPIC -ffreestanding $(MUSL_ABI_CFLAGS)'
ifeq ($(arch),x86_64)
build-xed: xed/build-i386/lib/libxed.a
xed/build-i386/lib/libxed.a: $(MBUILD_DIR)
	cd xed && ./mfile.py install --build-dir=obj-i386 --install-dir=build-i386 --no-encoder \
	  --extra-flags='-m32 -fPIC -ffreestanding $(MUSL_ABI_CFLAGS)' --extra-linkflags=-Wl,-melf_i386
endif

clean::
	cd xed && rm -rf obj-* build-* && ./mfile.py clean || true

CONFIG_MK +=\nXED_DIR ?= $(CONTRIB)/xed\n
varlist += XED_DIR

# ----------------------------librunt

# We build both opt and debug verisons of librunt, because
# liballocs's self-test (make TEST=1) configuration wants to
# use the debug version, and we run that as part of our test
# suite (the 'lib-test' case).
ifeq ($(DEBUG),)
frag := opt
else
frag := debug
endif
.PHONY: build-librunt
build-librunt: librunt/build/debug-$(arch)/librunt_preload.a librunt/build/opt-$(arch)/librunt_preload.a
librunt/build/%/librunt_preload.a: librunt/Makefile
	mkdir -p $(dir $@) && cd $(dir $@) && $(LIBRUNT_MAKE_PREFIX) $(MAKE) -f ../../src/Makefile
# librunt is not yet autotools'd
#librunt/Makefile: librunt/configure
#	cd librunt && ./configure
#librunt/configure: librunt/configure.ac
#	cd librunt && ./autogen.sh

# also build 32-bit version on x86_64
ifeq ($(arch),x86_64)
build-librunt: librunt/build/opt-i386/librunt_preload.a librunt/build/debug-i386/librunt_preload.a
librunt/build/%-i386/librunt_preload.a: LIBRUNT_MAKE_PREFIX := CFLAGS="$(CFLAGS) $(MUSL_ABI_CFLAGS)" CC="$(CC) -m32" ASFLAGS="-m32" LDFLAGS="-Wl,-melf_i386"
endif

CONFIG_MK +=\nLIBRUNT_CFLAGS := $(LIBRUNT_CFLAGS) -I$(CONTRIB)/librunt/include\n
CONFIG_MK +=\nLIBRUNT_LDFLAGS := $(LIBRUNT_LDFLAGS) -L$(CONTRIB)/librunt/build/$(if $(DEBUG),debug,opt)-$(arch) \
 -Wl,-rpath,$(CONTRIB)/librunt/build/$(if $(DEBUG),debug,opt)-$(arch)
# How to plumb through the 32-bit version's flags? Just add both -L dirs and
# let the linker figure it out.
ifeq ($(arch),x86_64)
CONFIG_MK +=\nLIBRUNT_LDFLAGS += -L$(CONTRIB)/librunt/build/$(if $(DEBUG),debug,opt)-i386 \
 -Wl,-rpath,$(CONTRIB)/librunt/build/$(if $(DEBUG),debug,opt)-i386
endif

clean::
	cd librunt && rm -rf build

CONFIG_MK +=\nLIBRUNT_DIR ?= $(realpath $(CONTRIB)/librunt)\n
# non-autoconf'd stuff (liballocs, libsystrap) may expect LIBRUNT_DIR
varlist += LIBRUNT_CFLAGS LIBRUNT_LDFLAGS LIBRUNT_DIR

# ----------------------------libx86emulate
CONFIG_MK +=\nLIBX86EMULATE_DIR ?= $(realpath $(CONTRIB)/libx86emulate)\n
varlist += LIBX86EMULATE_DIR

# ----------------------------donald
CONFIG_MK +=\nDONALD ?= $(realpath $(CONTRIB))/donald\n
varlist += DONALD

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
