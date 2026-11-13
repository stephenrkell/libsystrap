THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

# run-from-srcroot case:
# if the current dir is the source dir, change to the output directory
# and re-invoke this makefile from there.
# If we don't know which output directory we want, we want the production one.
ifeq ($(realpath .),$(realpath $(srcroot))/example)
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS := default
endif
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	for arch in `m=$$(uname -m); case "$$m" in (x86_64) echo x86_64 i386 ;; (*) echo "$$m" ;; esac`; do \
           mkdir -p $(srcroot)/build/$${arch} && \
           $(MAKE) -C $(srcroot)/build/$${arch} -f $(srcroot)/example/Makefile $(MAKECMDGOALS) || exit 1; \
    done
else
# the rest: we take our arch from the current dir
arch := $(notdir $(realpath .))
$(info arch is $(arch))
vpath %.c $(srcroot)/example
vpath %.s $(srcroot)/example
vpath %.lds $(srcroot)/example

# set arch options based on the name of the build dir

.PHONY: default
default: trace-syscalls.so trace-syscalls-ld.so noop-syscalls-ld.so

SYS := $(shell uname -s | tr A-Z a-z )

# if we are doing a 32-on-64 build, add -m32
ifeq ($(arch) $(shell uname -m),i386 x86_64)
CFLAGS += -m32
ASFLAGS += -m32
LDFLAGS += -m32 -Wl,-melf_i386
endif

ifneq ($(shell gcc $(CFLAGS) -print-multiarch | sed 's/-.*//' ),$(arch))
$(error GCC does not agree that the architecture is `$(arch)')
endif

# debugging
CFLAGS += -save-temps

ifeq ($(arch),i386)
LD_SO ?= /lib/ld-linux.so.2
else
ifeq ($(arch),x86_64)
LD_SO ?= /lib64/ld-linux-x86-64.so.2
endif
endif

ifeq ($(LD_SO),)
$(error Could not determine ld.so pathname (from architecture $(arch)).)
endif

UNWIND_MACHINE ?= $(arch)
ifeq ($(UNWIND_MACHINE),i386)
UNWIND_MACHINE := x86
endif

# How should we get our config?
# If we don't have one in srcroot, use contrib/
ifneq ($(realpath $(srcroot)/config.mk),)
include $(srcroot)/config.mk
else
include $(srcroot)/contrib/config.mk
$(srcroot)/contrib/config.mk:
	$(MAKE) -C $(srcroot)/contrib config.mk
endif

# Check for dependencies built already -- unless cleaning
ifneq ($(MAKECMDGOALS),clean)

ifeq ($(LIBRUNT_DIR),)
$(error Please install the librunt source tree and set LIBRUNT_DIR to point to it)
endif
ifeq ($(XED_DIR),)
$(error Please set XED_DIR)
endif
ifeq ($(DONALD),)
$(error Please set DONALD or make $(srcroot)/config.mk do so)
endif

ifneq ($(LIBC_A_PATTERN),)
$(info LIBC_A was pre-set to $(LIBC_A) (arch: $(arch), pattern: $(LIBC_A_PATTERN)))
LIBC_A ?= $(shell echo '$(LIBC_A_PATTERN)' | env arch='$(arch)' envsubst )
$(info LIBC_A is $(LIBC_A))
endif

ifeq ($(SYS),freebsd)
LIBC_A ?= /usr/lib/libc_pic.a
endif
ifeq ($(LIBC_A),)
$(error Please set LIBC_A to point to a position-independent libc archive, or LIBC_A_PATTERN to a pattern that can locate one after substituting $${arch})
endif
ifeq ($(realpath $(srcroot)/build/$(arch)/libsystrap.a),)
$(error Please build libsystrap first)
endif

endif # end dependencies check

# LIBC_CFLAGS_PATTERN is now expected to be self-sufficient
# e.g. using musl we should be able to build without pulling in ambient glibc stuff
# we use envsubst to expand the pattern
LIBC_CFLAGS := $(shell echo '$(LIBC_CFLAGS_PATTERN)' | env arch="$(arch)" envsubst )
$(info LIBC_CFLAGS is $(LIBC_CFLAGS))
CFLAGS += -nostdinc $(LIBC_CFLAGS)

CFLAGS += -DOUR_LDSO_DIR="\"$(shell pwd)/\""
CFLAGS += -DSYSTRAP_DEFINE_FILE
CFLAGS += -I$(XED_DIR)/include

CFLAGS += -g
CFLAGS += -Wall -Wno-unused-label -Wno-comment
ifeq ($(DEBUG),)
CFLAGS += -O2
# not ready to turn off assertions, but for consistency...
# CFLAGS += -DNDEBUG
else
CFLAGS += -Og
endif
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer
CFLAGS += -I$(srcroot)/src
CFLAGS += -I$(srcroot)/include
CFLAGS += -I $(LIBRUNT_DIR)/include
CFLAGS += -I$(XED_DIR)/build-$(arch)/include/xed
CFLAGS += -I$(XED_DIR)/include/public
CFLAGS += -std=c99

# This is necessary to make wrapping less unreliable
CFLAGS += -ffunction-sections

# musl has 'int' for line number, unlike glibc... librunt can hack around for us
# FIXME: should be a configure-time thing perhaps? in which repo?
# Problem is that configure might not see same libc headers as we plumb through here.
CFLAGS += -DASSERT_FAIL_LINE_SIGNED

PRELOAD_TARGETS := trace-syscalls.so
LOADER_TARGETS := trace-syscalls-ld.so noop-syscalls-ld.so

# force the object(s) containing preload symbols
preload_symbols := dlopen dlclose dlerror dlsym dladdr dladdr1 dlvsym dlmopen dl_iterate_phdr
LDFLAGS += -Wl,--version-script,version-script -Wl,-u,dlsym
version-script:
	printf '{\n  global:\n$(foreach v,$(preload_symbols),$(v);\n)\n\nlocal:\n    *;\n};' > $@ \
              || { rm -f "$@"; false; }
$(PRELOAD_TARGETS) $(LOADER_TARGETS): version-script

syscall-names.o: syscall-macros.h
# for syscall-macros.h
CFLAGS += -I.

# for dlmalloc.c
vpath %.c $(srcroot)/contrib

# for donald things
vpath %.c $(DONALD)/src
vpath %.S $(DONALD)/src
vpath %.h $(DONALD)/src
CFLAGS += -I$(DONALD)/src

CHAIN_LOADER_OBJS := chain-ext.o bootstrap.o
$(info CHAIN_LOADER_OBJS is $(CHAIN_LOADER_OBJS))
# these files are built from donald sources
LDSO_OBJS := premain.o main.o entry.o load.o debug.o start.o chain.o
$(info LDSO_OBJS is $(LDSO_OBJS))
TRACER_OBJS := syscall-names.o lcall.o
ALL_OBJS := $(LDSO_OBJS) $(CHAIN_LOADER_OBJS) $(TRACER_OBJS) dlmalloc.o \
  trace-syscalls.o # noop-syscalls.o
DEPS := $(patsubst %.o,%.d,$(ALL_OBJS))

$(ALL_OBJS): CFLAGS += -MD -MF $(basename $@).d

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

# disable sbrk() in dlmalloc, to avoid conflicting with the "other" C library
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
	$(AR) r "$@" $^

# This is a quick but incomplete way to build a number->name mapping
linux-syscall-macros.h:
	( echo '#include "asm/unistd.h"' | /usr/bin/cpp $(LIBC_CFLAGS) -E -dM -o -  | \
           grep '#define *__NR_' | sort | uniq | \
           sed -r 's/^#define *__NR_([^[:blank:]]*)[[:blank:]]*([0-9]*)/#ifdef SYS_\1\nSYSCALL(\1)\n#endif/') > "$@" || (rm -f "$@"; false)
freebsd-syscall-macros.h:
	cat /usr/include/sys/syscall.h | grep 'SYS_[a-z][A-Za-z0-9_]*' | cut -f2 | \
    sed 's/SYS_\(.*\)/SYSCALL(\1)/' > "$@" || (rm -f "$@"; false)
#vpath %.h $(srcroot)/build/$(arch)
syscall-macros.h: $(SYS)-syscall-macros.h
	cp "$<" "$@"

ifeq ($(DEBUG),)
librunt_frag := opt
else
librunt_frag := debug
endif

# FIXME: make our dynamic symbols hidden! 
# We don't want user code calling into our exit(), hence having us make its syscalls.
# NOTE: the --whole-archive is only necessary for debugging, to ensure that
# functions we might want to call from the debugger are actually linked in
$(PRELOAD_TARGETS): LDLIBS := -Bstatic \
	$(srcroot)/build/$(arch)/libsystrap.a \
	-Wl,--whole-archive $(LIBRUNT_DIR)/build/$(librunt_frag)-$(arch)/librunt_preload.a -Wl,--no-whole-archive \
	-ldl

# FIXME: what's the right way to pull in libgcc.a? It seems that
# the compiler should do it for us, but for some reason it doesn't.
$(PRELOAD_TARGETS): LDLIBS += \
	dlmalloc.a \
	$(LD_SO) \
	$(LIBC_A) -lunwind-$(UNWIND_MACHINE) -lunwind -lpthread -lgcc

# we used to insist -Wl,--hash-style=sysv here, but relf.h now groks GNU-style
$(PRELOAD_TARGETS) $(LOADER_TARGETS): LDFLAGS += \
-fno-lto -nostdlib -Wl,--no-as-needed
$(PRELOAD_TARGETS): LDFLAGS += \
-Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr \
-Wl,--defsym,__private_strdup=strdup \
-Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free
# hmm -- is this necessary now? FIXME: CHECK
$(PRELOAD_TARGETS): LDFLAGS += \
-Wl,--defsym,stat=raw_stat
# don't use lazy binding -- it's bad if we've removed exec permission
$(PRELOAD_TARGETS) $(LOADER_TARGETS): LDFLAGS += \
	-Wl,-z,now
# generate a map file, for debugging
$(PRELOAD_TARGETS) $(LOADER_TARGETS): LDFLAGS += -Wl,-Map,$@.map
# don't re-export symbols from any archives we link in
$(PRELOAD_TARGETS): LDFLAGS += -Wl,--exclude-libs=ALL
# ... loader targets now use a version script instead

# To avoid clashing implementations of TLS,
# we define our own, simpler __init_tp -- wrapping DOESN'T WORK...
$(PRELOAD_TARGETS) $(LOADER_TARGETS): LDFLAGS += -Wl,--wrap,__init_tp
# ... we can just use musl's for -ld.so, but for preload we need more.
$(PRELOAD_TARGETS): LDFLAGS += -Wl,-z,muldefs -Wl,--defsym,__init_tp=__wrap___init_tp

# we insert our startup logic by wrapping donald's enter()
$(LOADER_TARGETS): LDFLAGS += -Wl,--wrap,enter
# we also experimentally wrap donald's load_one_phdr()
$(LOADER_TARGETS): LDFLAGS += -Wl,--wrap,load_one_phdr
# we also really really wrap donald's get_loadee_path and get_loadee_base_addr_hint
$(LOADER_TARGETS): LDFLAGS += \
-Wl,--wrap,get_loadee_path -Wl,--wrap,get_loadee_base_addr_hint
# we use librunt's own file metadata thingy
$(LOADER_TARGETS): LDFLAGS += \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--wrap,__runt_files_metadata_by_addr \
-Wl,--defsym,__private_strdup=strdup \
-Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free

$(LOADER_TARGETS): LDLIBS += -Bstatic \
  $(srcroot)/build/$(arch)/libsystrap.a \
  -Wl,-u,dlsym $(LIBRUNT_DIR)/build/$(librunt_frag)-$(arch)/librunt_preload.a \
  dlmalloc.a \
  $(LIBC_A)


trace-syscalls.o: CFLAGS += -DCHAIN_LOADER
noop-syscalls.o: CFLAGS += -DNOOP_SYSCALL_ACTION -DDONALD_NAME=\"noop-syscalls-ld\" -DCHAIN_LOADER
noop-syscalls.o: trace-syscalls.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

trace-syscalls.so: trace-syscalls.o
$(PRELOAD_TARGETS): $(TRACER_OBJS) fake-tls.o $(srcroot)/build/$(arch)/libsystrap.a dlmalloc.a
	$(CC) -fuse-ld=gold \
		-static-libgcc -shared -o "$@" \
		$(filter-out version-script,$(filter-out %.a,$+)) \
		$(LDFLAGS) $(LDLIBS) \
		-Wl,-soname=$@

# ask for a spare .dynamic slot
$(LOADER_TARGETS): LDFLAGS += -Wl,--spare-dynamic-tags=5

$(LDSO_OBJS) trace-syscalls.o: CFLAGS += -DDONALD_NAME=\"trace-syscalls-ld\"
$(LDSO_OBJS): CFLAGS += -DCHAIN_LOADER
$(CHAIN_LOADER_OBJS): CFLAGS += -DCHAIN_LOADER

# don't use standard relocation sections... the dynamic tags we need are special
# XXX: this controls what premain.o looks for, but how do we get these in .dynamic?
include $(srcroot)/example/wraparound.h.mk
premain.o: wraparound.h
premain.o: CFLAGS += -include wraparound.h \
  -DRELA_DT_VALUE=$(DT_BOOTSTRAP_RELA) \
  -DRELASZ_DT_VALUE=$(DT_BOOTSTRAP_RELASZ) \
  -DRELAENT_DT_VALUE=$(DT_BOOTSTRAP_RELAENT)

DYNAPPEND ?= $(shell which $${ELFTIN:+$${ELFTIN}/dynappend/}dynappend)
DYNSUBST ?= $(shell which $${ELFTIN:+$${ELFTIN}/dynsubst/}dynsubst)
ifeq ($(DYNAPPEND),)
$(warning No DYNAPPEND or ELFTIN, so trace-syscalls-ld.so will not support debugging properly (ELFTIN is $(ELFTIN)).)
endif
ifeq ($(DYNSUBST),)
$(error No DYNSUBST or ELFTIN, so can't build a wraparound loader.)
endif
# FIXME: localize all global symbols except maybe _start?
export SHELL := /bin/bash             # for '<<<'
.DELETE_ON_ERROR:                     # don't leave unfinished built files lying around
trace-syscalls-ld.so: trace-syscalls.o
noop-syscalls-ld.so: noop-syscalls.o
$(LOADER_TARGETS): trace-syscalls-ld.lds $(LDSO_OBJS) $(CHAIN_LOADER_OBJS) $(TRACER_OBJS) $(srcroot)/build/$(arch)/libsystrap.a
	$(CC) $(CFLAGS) -fuse-ld=bfd \
            -Bsymbolic -nostdlib -nostartfiles -static-libgcc -shared -o "$@" \
            $(filter-out version-script,$(filter-out %.lds,$(filter-out %.a,$+))) \
            $(LDFLAGS) $(LDLIBS) -lgcc -Wl,-Bsymbolic \
            -T $(filter %.lds,$+) -Wl,-soname=trace-syscalls-ld.so
	if [ -n "$(DYNAPPEND)" ]; then $(DYNAPPEND) $@ 21 ; fi # DT_DYNAMIC
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_RELA'    | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_RELA); }" ) || \
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_REL'     | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_REL); }" )
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_RELASZ'  | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_RELASZ); }" ) || \
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_RELSZ'   | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_RELSZ); }" )
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_RELAENT' | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_RELAENT); }" ) || \
	$(DYNSUBST) $@ $$( awk "BEGIN { print `cpp -include /usr/include/elf.h -o - <<<'DT_RELENT'  | tail -n1` ;}" ) $$( awk "BEGIN { print $(DT_BOOTSTRAP_RELENT); }" )

trace-syscalls-ld.lds: $(shell which ld) $(THIS_MAKEFILE)
	USE_LD=ld.bfd $(CC) $(CFLAGS) -fuse-ld=bfd -nostdlib -nostartfiles -shared \
      -Wl,--verbose 2>&1 |  \
        LC_ALL=C \
          sed -e '/^=========/,/^=========/!d;/^=========/d'    \
              -e 's/\. = .* + SIZEOF_HEADERS;/& _begin = . - SIZEOF_HEADERS;/' \
              -e 's/\. = DATA_SEGMENT_ALIGN.*/. = DATA_SEGMENT_ALIGN (CONSTANT (COMMONPAGESIZE), CONSTANT (COMMONPAGESIZE));/' \
          > "$@" || (rm -f $@; false)

.PHONY: clean
clean:
	rm -f trace-syscalls.so trace-syscalls-ld.so noop-syscalls-ld.so
	rm -f $(ALL_OBJS) noop-syscalls.o dlmalloc.a
	rm -f $(patsubst %.o,%.d,$(ALL_OBJS) noop-syscalls.o) noop-syscalls.o
	rm -f syscall-macros.h $(SYS)-syscall-macros.h
	rm -f trace-syscalls-ld.lds
	rm -f trace-syscalls-ld.so.map
	rm -f trace-syscalls.so.map

endif # run-from-srcroot test
