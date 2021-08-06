.PHONY: default
default: $(foreach t,hello time,run-$(t)-$(MODE).stamp)

# FIXME: we skip 'read' and 'write' as they exit nonzero even on success

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/../..)
$(info srcroot is $(srcroot))

include $(srcroot)/test/rules.mk

# quick hack to get the dynamic linker path
LDSO ?= $(shell ldd /bin/true | grep ld-linux | cut -f2 | sed 's/[[:blank:]].*//')

ifeq ($(MODE),preload)
PREFIX := LD_PRELOAD=$(srcroot)/example/trace-syscalls.so
else
ifeq ($(MODE),chain)
PREFIX := $(srcroot)/example/trace-syscalls-ld.so
endif
endif

CFLAGS += -g -fPIC

# freestanding C tests (not hello)
time read write: LDFLAGS += -nostdlib -nostartfiles -ffreestanding

time: LDFLAGS += -no-pie
time: LDLIBS += $(LDSO)
