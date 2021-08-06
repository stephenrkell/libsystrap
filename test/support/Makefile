.PHONY: default
default: $(foreach t,x86-decode x86-operands,run-$(t).stamp)

run-%.stamp: %
	./$* && touch $@

.PHONY: clean
clean:
	rm -f x86-decode x86-operands *.stamp

CFLAGS += -g -fPIC

# support tests
x86-decode: CFLAGS += -I../libsystrap -std=gnu11
x86-decode: LDLIBS += ../libsystrap/x86_decode.o -ludis86

x86-operands: LDLIBS += -L../libsystrap -lsystrap
x86-operands: CFLAGS += -I../libsystrap
