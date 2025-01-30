THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
TOPDIR := $(realpath $(dir $(THIS_MAKEFILE)))

# Since we don't yet use autoconfig...
# allow a config.mk at top level to override that in contrib
toplevel_config := $(wildcard $(TOPDIR)/config.mk)
# $(info toplevel_config is $(toplevel_config))
ifneq ($(toplevel_config),)
CONFIG ?= $(toplevel_config)
export CONFIG
endif

.PHONY: default
default: all

.PHONY: all
all: src lib example

.PHONY: clean
clean:
	$(MAKE) -C example clean
	$(MAKE) -C lib clean
	$(MAKE) -C src clean

.PHONY: run-tests
run-tests: test
	$(MAKE) -C test checkrun

.PHONY: test
test: src
	$(MAKE) -C test

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: lib
lib: src
	$(MAKE) -C lib

.PHONY: example
example: src lib
	$(MAKE) -C example
