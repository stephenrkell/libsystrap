THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
TOPDIR := $(dir $(THIS_MAKEFILE))

.PHONY: default
default: all

.PHONY: all
all: src lib example

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
