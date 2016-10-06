CFLAGS += -g

default: hello true getpid time read write

true getpid time read write: LDFLAGS += -Wl,-nostdlib -nostartfiles -ffreestanding

x86-decode: CFLAGS += -I../libsystrap -std=gnu11
x86-decode: LDLIBS += ../libsystrap/x86_decode.o -ludis86

x86-operands: LDLIBS += -L../libsystrap -lsystrap
x86-operands: CFLAGS += -I../libsystrap

segv: LDLIBS += -L../libsystrap -lsystrap
segv: CFLAGS += -I../libsystrap
