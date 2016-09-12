/******************************************************************************
 * x86_defs.h.c
 * 
 * Supporting definitions for
 * generic x86 (32-bit and 64-bit) instruction decoder (NOT emulator).
 * 
 * Portions copyright 2016, Stephen Kell.
 * Based on x86_emulate.h, which is
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <stdint.h>
#include <err.h> /* for warnx() */
#include <stdlib.h>

//#include <xen/config.h>
//#include <xen/types.h>
//#include <xen/lib.h>
//#include <asm/regs.h>

// just pick the bits we need

typedef char bool_t;

#define likely(x)     __builtin_expect(!!(x),1)
#define unlikely(x)   __builtin_expect(!!(x),0)

#define inline        __inline__
#define always_inline __inline__ __attribute__ ((always_inline))
#define noinline      __attribute__((noinline))

#define noreturn      __attribute__((noreturn))

#define __packed      __attribute__((packed))

#ifndef assert_failed
#define assert_failed(p)                                        \
do {                                                            \
    warnx("Assertion '%s' failed, line %d, file %s\n", p ,     \
                   __LINE__, __FILE__);                         \
    BUG();                                                      \
} while (0)
#endif

struct cpu_user_regs;
#define asm __asm__

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
/* Anonymous union includes both 32- and 64-bit names (e.g., eax/rax). */
#define __DECL_REG(name) union { \
    uint64_t r ## name, e ## name; \
    uint32_t _e ## name; \
}
#else
/* Non-gcc sources must always use the proper 64-bit name (e.g., rax). */
#define __DECL_REG(name) uint64_t r ## name
#endif

struct cpu_user_regs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    __DECL_REG(bp);
    __DECL_REG(bx);
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    __DECL_REG(ax);
    __DECL_REG(cx);
    __DECL_REG(dx);
    __DECL_REG(si);
    __DECL_REG(di);
    uint32_t error_code;    /* private */
    uint32_t entry_vector;  /* private */
    __DECL_REG(ip);
    uint16_t cs, _pad0[1];
    uint8_t  saved_upcall_mask;
    uint8_t  _pad1[3];
    __DECL_REG(flags);      /* rflags.IF == !saved_upcall_mask */
    __DECL_REG(sp);
    uint16_t ss, _pad2[3];
    uint16_t es, _pad3[3];
    uint16_t ds, _pad4[3];
    uint16_t fs, _pad5[3]; /* Non-zero => takes precedence over fs_base.     */
    uint16_t gs, _pad6[3]; /* Non-zero => takes precedence over gs_base_usr. */
};
typedef struct cpu_user_regs cpu_user_regs_t;

#ifndef NDEBUG
#define ASSERT(p) \
    do { if ( unlikely(!(p)) ) assert_failed(#p); } while (0)
#define ASSERT_UNREACHABLE() assert_failed("unreachable")
#define debug_build() 1
#else
#define ASSERT(p) do { if ( 0 && (p) ); } while (0)
#define ASSERT_UNREACHABLE() do { } while (0)
#define debug_build() 0
#endif

#define BUG_ON(p)  do { if (unlikely(p)) BUG();  } while (0)

#define BUG() abort()


#include "x86_emulate.h"

/*
 * This flag is set in an exception frame when registers R12-R15 did not get
 * saved.
 */
#define _TRAP_regs_partial 16
#define TRAP_regs_partial  (1 << _TRAP_regs_partial)

#define _TRAP_regs_dirty   17
#define TRAP_regs_dirty    (1 << _TRAP_regs_dirty)

#define mark_regs_dirty(r) ({ \
        struct cpu_user_regs *r__ = (r); \
        ASSERT(!((r__)->entry_vector & TRAP_regs_partial)); \
        r__->entry_vector |= TRAP_regs_dirty; \
})

#define cpu_has_amd_erratum(nr)  0 
     // cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)

int
x86_decode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops);

