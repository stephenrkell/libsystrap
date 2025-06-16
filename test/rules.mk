THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/..)
$(info srcroot is $(srcroot))

PRELOAD_BINARY := $(srcroot)/build/$(shell uname -m)/trace-syscalls.so
CHAIN_BINARY := $(srcroot)/build/$(shell uname -m)/trace-syscalls-ld.so

ifeq ($(realpath $(PRELOAD_BINARY)),)
$(error Please build $(PRELOAD_BINARY) first)
endif
ifeq ($(realpath $(CHAIN_BINARY)),)
$(error Please build $(CHAIN_BINARY) first)
endif
run-%-preload.stamp: % $(PRELOAD_BINARY)
	LD_PRELOAD=$(PRELOAD_BINARY) ./$* && touch $@
run-%-chain.stamp: % $(CHAIN_BINARY)
	$(CHAIN_BINARY) ./$* && touch $@
run-%.stamp: %
	./$*

.PHONY: clean
clean::
	rm -f run-*-*.stamp
