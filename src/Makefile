THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..
srcdir := $(srcroot)/src

# run-from-srcroot case:
# if the current dir is the source dir, change to the output directory
# and re-invoke this makefile from there.
# If we don't know which output directory we want, we want the production one.
ifeq ($(realpath .),$(realpath $(srcdir)))
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS := default
endif
# FIXME: before we can do a multiarch build, we need multiarch version
# of our dependencies: at least xed and librunt and musl; others?
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	for arch in `m=$$(uname -m); case "$$m" in (x86_64) echo x86_64 ;; (*) echo "$$m" ;; esac`; do \
             mkdir -p $(srcroot)/build/$${arch} && \
             $(MAKE) -C $(srcroot)/build/$${arch} -f $(srcdir)/Makefile $(MAKECMDGOALS); \
        done
else
# the rest: we take our arch from the current dir
arch := $(notdir $(realpath .))
vpath %.c $(srcdir)
vpath %.s $(srcdir)

# don't delete intermediates
.SECONDARY:

.PHONY: default
default: libsystrap.a

CONTRIB := $(srcroot)/contrib
CONFIG ?= $(CONTRIB)/config.mk

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

ifneq ($(MAKECMDGOALS),clean)
include $(CONFIG)
endif

# if we are doing a 32-on-64 build, add -m32
ifeq ($(arch) $(shell uname -m),i386 x86_64)
CFLAGS += -m32
LDFLAGS += -m32
endif

# we are to be linked with the librunt archive
CFLAGS += -DIN_LIBRUNT_DSO
# musl has 'int' for line number, unlike glibc... librunt can hack around for us
# FIXME: should be a configure-time thing perhaps? in which repo?
# Problem is that configure might not see same libc headers as we plumb through here.
CFLAGS += -DASSERT_FAIL_LINE_SIGNED
CFLAGS += -DSYSTRAP_DEFINE_FILE
CFLAGS += -I$(srcroot)/include
CFLAGS += -g
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer
# the decoder we use nowadays is the "official" Intel one
CFLAGS += -DUSE_XED

ifeq ($(DEBUG),)
CFLAGS += -DNDEBUG
else
# HMM... we have temporarily disabled opdis. But good to get a second
# opinion beside xed... maybe use udis86 instead? FIXME
#instr.o: CFLAGS += -DUSE_OPDIS
endif

# LIBC_CFLAGS_PATTERN is now expected to be self-sufficient
# e.g. using musl we should be able to build without pulling in ambient glibc stuff
# we use envsubst to expand the pattern
LIBC_CFLAGS := $(shell echo '$(LIBC_CFLAGS_PATTERN)' | env arch="$(arch)" envsubst )
$(info LIBC_CFLAGS is $(LIBC_CFLAGS))
CFLAGS += -nostdinc $(LIBC_CFLAGS)

C_SRC := $(wildcard $(srcdir)/*.c)
$(info C_SRC is $(C_SRC))
C_DEPS := $(patsubst %.c,%.d,$(notdir $(C_SRC)))
$(info C_DEPS is $(C_DEPS))
DEPS := $(C_DEPS)
OBJS := $(patsubst %.c,%.o,$(notdir $(C_SRC)))

$(C_DEPS): %.d: %.c
	$(CC) -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

ifneq ($(realpath $(XED_DIR)),)
CFLAGS += -I$(XED_DIR)/include
endif
ifneq ($(realpath $(LIBX86EMULATE_DIR)),)
CFLAGS += -I$(LIBX86EMULATE_DIR)/src
OBJS += x86_decode.o
endif
# always add librunt
CFLAGS += -I$(LIBRUNT_DIR)/include

CFLAGS += -std=c99

vpath x86_decode.c $(LIBX86EMULATE_DIR)/src
x86_decode.o: CFLAGS += -include $(LIBX86EMULATE_DIR)/src/x86_defs.h -include stdio.h
x86_decode.o instr.o: CFLAGS += -std=gnu11

$(info OBJS is $(OBJS))
# Also extract archives and re-add their members to our archive.  This allows
# clients to link to us without concern for these dependencies, which they
# probably don't have available in PIC form.
# XXX: for now we create one big .os, to avoid dumping a large pile of uncleanable
# .o detritus into the build directory. However, that is not so great -- it
# means that the whole xed archive will be linked in unconditionally, i.e. even if
# the client doesn't need all of it.
xed.os: $(XED_A)
	ld -r -o $@ --whole-archive $< --no-whole-archive

libsystrap.a: $(OBJS) xed.os
	$(AR) r "$@" $+

.PHONY: clean
clean:
	rm -f libsystrap.a
	rm -f $(OBJS) xed.os
	rm -f $(patsubst %.o,%.d,$(OBJS))

endif # run-from-srcdir test
