# common as mk

CONFIG ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/contrib/config.mk
ifneq ($(MAKECMDGOALS),clean)
include $(CONFIG)
endif

# LIBC_CFLAGS_PATTERN is now expected to be self-sufficient
# e.g. using musl we should be able to build without pulling in ambient glibc stuff
# we use envsubst to expand the pattern
ifeq ($(shell which envsubst),)
$(error "Please install 'gettext-base' or any package providing 'envsubst'")
endif
LIBC_CFLAGS := $(shell echo '$(LIBC_CFLAGS_PATTERN)' | env arch="$(arch)" envsubst )
$(info LIBC_CFLAGS is $(LIBC_CFLAGS))
