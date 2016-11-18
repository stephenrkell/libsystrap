.PHONY: default
default: libsystrap.a

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SRCROOT := $(realpath $(dir $(THIS_MAKEFILE)))/..

CONTRIB := $(SRCROOT)/contrib
CONFIG := $(CONTRIB)/config.mk

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

include $(CONFIG)

CFLAGS += -DRELF_DEFINE_STRUCTURES
CFLAGS += -DSYSTRAP_DEFINE_FILE

ifeq ($(LIBALLOCS_DIR),)
$(error Please install the liballocs source tree and set LIBALLOCS_DIR)
endif

vpath %.c $(LIBALLOCS_DIR)/src

CFLAGS += -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer

instr.o: CFLAGS += -DUSE_X86_DECODE

ifeq ($(DEBUG),)
CFLAGS += -DNDEBUG
else
instr.o: CFLAGS += -DUSE_OPDIS
endif

CFLAGS += -I $(UDIS86_DIR)
CFLAGS += -I $(OPDIS_DIR)
CFLAGS += -I $(LIBOPCODES_DIR)/include
CFLAGS += -I $(BFD_DIR)
CFLAGS += -I $(LIBALLOCS_DIR)/include

CXXFLAGS := $(CXXFLAGS) $(CFLAGS) # eagerly latch CFLAGS now; don't want later additions
CFLAGS += -std=c99
CXXFLAGS += -std=c++11 $(LLVM_CXXFLAGS)

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

x86_decode.o: CFLAGS += -include x86_defs.h -include stdio.h 
x86_decode.o instr.o: CFLAGS += -std=gnu11

#-DUSE_UDIS86 \

ifneq ($(shell uname -s),FreeBSD)
ARCHIVES := $(LIBUDIS86_A) $(LIBOPDIS_A) $(LIBOPCODES_A) $(LIBBFD_A) $(LIBIBERTY_A)
else
ARCHIVES :=
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
