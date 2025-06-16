# support tests
# XXX: these are really tests of libx86decode, so should move them there
#ALLTESTS := x86-decode x86-operands
ALLTESTS :=
.PHONY: default
default: $(foreach t,$(ALLTESTS),run-$(t).stamp)

include ../rules.mk

.PHONY: clean
clean::
	rm -f x86-decode x86-operands *.stamp

CFLAGS += -g -fPIC

x86-decode: CFLAGS += -I$(srcroot)/include -std=gnu11
x86-decode: LDLIBS += $(srcroot)/build/$(shell uname -m)/x86_decode.o

x86-operands: LDLIBS += -L$(srcroot)/build/$(shell uname -m) -lsystrap
x86-operands: CFLAGS += -I$(srcroot)/include
