.PHONY: default
default: libsystrap.a

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

CONTRIB := $(srcroot)/contrib
CONFIG ?= $(CONTRIB)/config.mk

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

include $(CONFIG)

CFLAGS += -DSYSTRAP_DEFINE_FILE
CFLAGS += -I$(srcroot)/include
CFLAGS += -g
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer

instr.o: CFLAGS += -DUSE_XED

ifeq ($(DEBUG),)
CFLAGS += -DNDEBUG
else
# HMM... we have temporarily disabled opdis. But good to get a second
# opinion beside xed... maybe use udis86 instead? FIXME
#instr.o: CFLAGS += -DUSE_OPDIS
endif

CFLAGS += -I/usr/include/$(shell $(CC) -dumpmachine)

C_SRC := $(wildcard *.c)
S_SRC := $(wildcard *.s)
CC_SRC := $(wildcard *.cc)

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
CC_DEPS := $(patsubst %.cc,.%.d,$(CC_SRC))
DEPS := $(C_DEPS) $(CC_DEPS)
OBJS := $(patsubst %.c,%.o,$(C_SRC)) $(patsubst %.cc,%.o,$(CC_SRC)) $(patsubst %.s,%.o,$(S_SRC))

DEPS += .trap-syscalls-exec.d

$(CC_DEPS): .%.d: %.cc
	$(CXX) -MM $(CXXFLAGS) $+ > "$@" || rm -f "$@"
$(C_DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

ifneq ($(realpath $(UDIS86_DIR)),)
CFLAGS += -I$(UDIS86_DIR)
endif
ifneq ($(realpath $(OPDIS_DIR)),)
CFLAGS += -I$(OPDIS_DIR)
endif
ifneq ($(realpath $(LIBOPCODES_DIR)),)
CFLAGS += -I$(LIBOPCODES_DIR)/include
endif
ifneq ($(realpath $(BFD_DIR)),)
CFLAGS += -I$(BFD_DIR)
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

CXXFLAGS := $(CXXFLAGS) $(CFLAGS) # eagerly latch CFLAGS now; don't want later additions
CFLAGS += -std=c99
CXXFLAGS += -std=c++11 $(LLVM_CXXFLAGS)

vpath x86_decode.c $(LIBX86EMULATE_DIR)/src
x86_decode.o: CFLAGS += -include $(LIBX86EMULATE_DIR)/src/x86_defs.h -include stdio.h
x86_decode.o instr.o: CFLAGS += -std=gnu11

ifneq ($(shell uname -s),FreeBSD)
ARCHIVES := $(LIBUDIS86_A) $(LIBOPDIS_A) $(LIBOPCODES_A) $(LIBBFD_A) $(LIBIBERTY_A) $(XED_A)
else
ARCHIVES := $(XED_A)
endif

# Also extract 	$(LIBOPDIS_A), $(LIBOPCODES_A), $(LIBBFD_A) and $(LIBIBERTY_A),
# and re-add their members to our archive.  This allows clients to link to us
# without concern for these dependencies, which they probably don't have
# available in PIC form.
libsystrap.a: $(OBJS)
	objs_list=$$( for fname in $(ARCHIVES); do \
		$(AR) vx "$$fname"; done | \
		grep '^x - ' | sed 's/^x - //' | tee objs_list ); \
	$(AR) r "$@" $^ $${objs_list}; \
	rm -f $$objs_list

.PHONY: clean
clean:
	rm -f libsystrap.a
	rm -f *.o
	rm -f .*.d
