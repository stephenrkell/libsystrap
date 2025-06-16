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
arch := $(shell m=`uname -m`; case "$$m" in (x86_64) echo x86_64 ;; (*) echo "$$m" ;; esac)
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	mkdir -p $(srcroot)/build/$(arch)
	$(MAKE) -C $(srcroot)/build/$(arch) -f $(srcroot)/example/Makefile $(MAKECMDGOALS)
else
# the rest: we take our arch from the current dir
arch := $(notdir $(realpath .))
vpath %.c $(srcroot)/example
vpath %.s $(srcroot)/example
vpath %.lds $(srcroot)/example

# set arch options based on the name of the build dir

.PHONY: default
default: trace-syscalls.so trace-syscalls-ld.so

SYS := $(shell uname -s | tr A-Z a-z )

ifneq ($(shell gcc $(CFLAGS) -print-multiarch | sed 's/-.*//' ),$(arch))
$(error GCC does not agree that the architecture is `$(arch)')
endif

# if we are doing a 32-on-64 build, add -m32
ifeq ($(arch) $(shell uname -m),i386 x86_64)
CFLAGS += -m32
LDFLAGS += -m32
endif

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
LIBC_A ?= $(shell echo '$(LIBC_A_PATTERN)' | env arch='$(arch)' envsubst )
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
endif
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer
CFLAGS += -I$(srcroot)/src
CFLAGS += -I$(srcroot)/include
CFLAGS += -I $(LIBRUNT_DIR)/include
CFLAGS += -std=c99

# musl has 'int' for line number, unlike glibc... librunt can hack around for us
# FIXME: should be a configure-time thing perhaps? in which repo?
# Problem is that configure might not see same libc headers as we plumb through here.
CFLAGS += -DASSERT_FAIL_LINE_SIGNED

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

C_SRC := $(filter-out %.inc.c,$(wildcard $(srcroot)/example/*.c))
C_DEPS := $(patsubst %.c,%.d,$(C_SRC))
DEPS := $(C_DEPS)
LOCAL_OBJS := $(filter-out pre-entry.o,$(filter-out write-footprints.o,$(patsubst %.c,%.o,$(notdir $(C_SRC)))))
$(info LOCAL_OBJS is $(LOCAL_OBJS))

$(DEPS): %.d: %.c
	$(CC) -MG -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

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
# XXX: don't build this here. Use the version built by src/Makefile
linux-syscall-macros.h:
	( /usr/bin/cpp -E -dM -o - /usr/include/`gcc $(CFLAGS) -print-multiarch`/asm/unistd.h </dev/null | \
           grep '#define *__NR_' | sort | uniq | \
           sed -r 's/^#define *__NR_([^[:blank:]]*)[[:blank:]]*([0-9]*)/#ifdef SYS_\1\nSYSCALL(\1)\n#endif/') > "$@" || (rm -f "$@"; false)
freebsd-syscall-macros.h:
	cat /usr/include/sys/syscall.h | grep 'SYS_[a-z][A-Za-z0-9_]*' | cut -f2 | \
    sed 's/SYS_\(.*\)/SYSCALL(\1)/' > "$@" || (rm -f "$@"; false)
#vpath %.h $(srcroot)/build/$(arch)
syscall-macros.h: $(SYS)-syscall-macros.h
	cp "$<" "$@"

# FIXME: make our dynamic symbols hidden! 
# We don't want user code calling into our exit(), hence having us make its syscalls.
# NOTE: the --whole-archive is only necessary for debugging, to ensure that
# functions we might want to call from the debugger are actually linked in
trace-syscalls.so: LDLIBS := -Bstatic \
	$(srcroot)/build/$(arch)/libsystrap.a \
	-Wl,--whole-archive $(LIBRUNT_DIR)/lib/librunt_preload.a -Wl,--no-whole-archive \
	-ldl

# FIXME: what's the right way to pull in libgcc.a? It seems that
# the compiler should do it for us, but for some reason it doesn't.
trace-syscalls.so: LDLIBS += \
	dlmalloc.a \
	$(LD_SO) \
	$(LIBC_A) -lunwind-$(UNWIND_MACHINE) -lunwind -lpthread -lgcc

# we used to insist -Wl,--hash-style=sysv here, but relf.h now groks GNU-style
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
-fno-lto -nostdlib -Wl,--no-as-needed
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr \
-Wl,--defsym,__private_strdup=strdup
# hmm -- is this necessary now? FIXME: CHECK
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,stat=raw_stat
# don't use lazy binding -- it's bad if we've removed exec permission
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
	-Wl,-z,now
# generate a map file, for debugging
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += -Wl,-Map,$@.map
# don't re-export symbols from any archives we link in
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
      -Wl,--exclude-libs=ALL

# To avoid clashing implementations of TLS,
# we define our own, simpler __init_tp -- wrapping DOESN'T WORK...
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += -Wl,--wrap,__init_tp
# ... we can just use musl's for -ld.so, but for preload we need more.
trace-syscalls.so: LDFLAGS += -Wl,-z,muldefs -Wl,--defsym,__init_tp=__wrap___init_tp

# we insert our startup logic by wrapping enter()
trace-syscalls-ld.so: LDFLAGS += -Wl,--wrap,enter -Wl,--wrap,load_one_phdr \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--wrap,__runt_files_metadata_by_addr
trace-syscalls-ld.so: LDLIBS += -Bstatic \
  $(srcroot)/build/$(arch)/libsystrap.a \
  $(LIBRUNT_DIR)/lib/librunt_preload.a \
  $(LIBC_A)

trace-syscalls.so: trace-syscalls.o syscall-names.o dlmalloc.a fake-tls.o

trace-syscalls.so: $(srcroot)/build/$(arch)/libsystrap.a
	$(CC) -shared -static-libgcc \
		-fuse-ld=gold \
		-Wl,-soname=$@ \
		-o "$@" $(filter-out %.a,$+) \
		$(LDFLAGS) $(LDLIBS)

LDSO_OBJS := premain.o main.o entry.o load.o pre-entry.o debug.o start.o
# ask for a spare .dynamic slot
trace-syscalls-ld.so: LDFLAGS += -Wl,--spare-dynamic-tags=5

$(LDSO_OBJS): CFLAGS += -DDONALD_NAME=\"trace-syscalls-ld\" \
  -DCHAIN_LOADER \
  -DCHAIN_LOADER_COVER_TRACKS_H='"$(srcroot)/example/chain-decls.h"' \
  -DCHAIN_LOADER_COVER_TRACKS_INC='"$(srcroot)/example/chain.inc.c"'

bootstrap.o: CFLAGS += -DCHAIN_LOADER

DYNAPPEND ?= $(shell which dynappend)
# FIXME: localize all global symbols except maybe _start?
trace-syscalls-ld.so: trace-syscalls-ld.lds $(LDSO_OBJS) $(filter-out fake-tls.o,$(LOCAL_OBJS)) dynamic-list $(srcroot)/build/$(arch)/libsystrap.a
	$(CC) $(CFLAGS) -fuse-ld=bfd \
            -Bsymbolic -nostdlib -nostartfiles -static-libgcc -shared -o "$@" \
            $(filter-out dynamic-list,$(filter-out %.lds,$(filter-out %.a,$+))) \
            $(LDFLAGS) $(LDLIBS) -lgcc -Wl,-Bsymbolic \
            -T $(filter %.lds,$+) -Wl,-soname=ld-linux.so.2 \
            -Wl,--dynamic-list,dynamic-list
	if [ -n "$(DYNAPPEND)" ]; then $(DYNAPPEND) $@ 21 ; fi # DT_DYNAMIC

# There is no way to make _DYNAMIC a dynamic symbol.
# A bit of a HACK, but we look for _init and _fini to find our own load address
# (in find_r_debug()), so try to export them.
# XXX: I think this does nothing, because dynamic-list does not affect the dynamic symbol
# table for shared libraries.
dynamic-list:
	printf '{ etext; _init; _fini; };\n' >$@ || (rm -f $@; false)

trace-syscalls-ld.lds: $(shell which ld) $(THIS_MAKEFILE)
	USE_LD=ld.bfd $(CC) -fuse-ld=bfd -nostdlib -nostartfiles -shared \
      -Wl,--verbose 2>&1 |  \
        LC_ALL=C \
          sed -e '/^=========/,/^=========/!d;/^=========/d'    \
              -e 's/\. = .* + SIZEOF_HEADERS;/& _begin = . - SIZEOF_HEADERS;/' \
              -e 's/\. = DATA_SEGMENT_ALIGN.*/. = DATA_SEGMENT_ALIGN (CONSTANT (COMMONPAGESIZE), CONSTANT (COMMONPAGESIZE));/' \
          > "$@" || (rm -f $@; false)

.PHONY: clean
clean:
	rm -f trace-syscalls.so trace-syscalls-ld.so
	rm -f $(LOCAL_OBJS) $(LDSO_OBJS) dlmalloc.o
	rm -f $(patsubst %.o,%.d,$(LOCAL_OBJS) $(LDSO_OBJS) dlmalloc.o)
	rm -f syscall-macros.h $(SYS)-syscall-macros.h
	rm -f dynamic-list
	rm -f trace-syscalls-ld.lds
	rm -f trace-syscalls-ld.so.map
	rm -f trace-syscalls.so.map

endif # run-from-srcroot test
