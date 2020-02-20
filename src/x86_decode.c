/******************************************************************************
 * x86_decode.c
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder (NOT emulator).
 * 
 * Portions copyright 2016, Stephen Kell.
 * Based on x86_emulate.c, which is
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
 
/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define DstNone     (0<<1) /* No destination operand. */
#define DstImplicit (0<<1) /* Destination operand is implicit in the opcode. */
#define DstBitBase  (1<<1) /* Memory operand, bit string. */
#define DstReg      (2<<1) /* Register operand. */
#define DstEax      DstReg /* Register EAX (aka DstReg with no ModRM) */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcInvalid  (0<<3) /* Unimplemented opcode. */
#define SrcNone     (1<<3) /* No source operand. */
#define SrcImplicit (1<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (2<<3) /* Register operand. */
#define SrcMem      (3<<3) /* Memory operand. */
#define SrcMem16    (4<<3) /* Memory operand (16-bit). */
#define SrcImm      (5<<3) /* Immediate operand. */
#define SrcImmByte  (6<<3) /* 8-bit sign-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)
/* All operands are implicit in the opcode. */
#define ImplicitOps (DstImplicit|SrcImplicit)

static uint8_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps, ImplicitOps,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps, ImplicitOps,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps, ImplicitOps,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x40 - 0x4F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x50 - 0x5F */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x60 - 0x67 */
    ImplicitOps, ImplicitOps, DstReg|SrcMem|ModRM, DstReg|SrcNone|ModRM|Mov,
    0, 0, 0, 0,
    /* 0x68 - 0x6F */
    ImplicitOps|Mov, DstReg|SrcImm|ModRM|Mov,
    ImplicitOps|Mov, DstReg|SrcImmByte|ModRM|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x70 - 0x77 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x78 - 0x7F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM|Mov, DstMem|SrcReg|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstMem|SrcReg|ModRM|Mov, DstReg|SrcNone|ModRM,
    DstReg|SrcMem16|ModRM|Mov, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x97 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x98 - 0x9F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xA0 - 0xA7 */
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xA8 - 0xAF */
    ByteOp|DstEax|SrcImm, DstEax|SrcImm,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xB0 - 0xB7 */
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    /* 0xB8 - 0xBF */
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ImplicitOps, ImplicitOps,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov, // <-- VEX prefixes here
    ByteOp|DstMem|SrcImm|ModRM|Mov, DstMem|SrcImm|ModRM|Mov,
    /* 0xC8 - 0xCF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xD8 - 0xDF */
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM|Mov, ImplicitOps|ModRM|Mov,
    /* 0xE0 - 0xE7 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xE8 - 0xEF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xF0 - 0xF7 */
    0, ImplicitOps, 0, 0,
    ImplicitOps, ImplicitOps,
    ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM,
    /* 0xF8 - 0xFF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

static uint8_t twobyte_table[256] = {
    /* 0x00 - 0x07 */
    SrcMem16|ModRM, ImplicitOps|ModRM, 0, 0, 0, ImplicitOps, ImplicitOps, 0,
    /* 0x08 - 0x0F */
    ImplicitOps, ImplicitOps, 0, /* 0 */ ImplicitOps /* ud2! */, 0, ImplicitOps|ModRM, 0, 0,
    /* 0x10 - 0x17 */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, SrcReg|DstMem|ModRM, 0, 0, SrcMem|DstReg|ModRM, 0,
    /* 0x18 - 0x1F */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    /* 0x20 - 0x27 */
    ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM, ImplicitOps|ModRM,
    0, 0, 0, 0,
    /* 0x28 - 0x2F */
    ImplicitOps|ModRM, ImplicitOps|ModRM, SrcReg|DstReg|ModRM, ImplicitOps|ModRM, SrcReg|DstReg|ModRM, 0, SrcReg|DstReg|ModRM, 0,
    /* 0x30 - 0x37 */
    ImplicitOps, ImplicitOps, ImplicitOps, 0,
    ImplicitOps, ImplicitOps, 0, 0,
    /* 0x38 - 0x3F */
    /* threebyte */ 0, 0, /* threebyte */ 0, 0, 0, 0, 0, 0,
    /* 0x40 - 0x47 */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x48 - 0x4F */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x50 - 0x57 */
    0, 0, 0, 0, SrcMem|DstReg|ModRM, SrcMem|DstReg|ModRM, SrcReg|DstReg|ModRM, SrcReg|DstReg|ModRM, 
    /* 0x58 - 0x5f */
    SrcMem|DstReg|ModRM, SrcMem|DstReg|ModRM, 0, 0, SrcReg|DstReg|ModRM, 0, SrcReg|DstReg|ModRM, 0,
    /* 0x60 - 0x67 */
    DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM, DstReg|SrcReg|ModRM, 0, ImplicitOps|ModRM, 0, SrcReg|DstReg|ModRM, 0, 
    /* 0x68 - 0x6f */
    0, 0, SrcReg|DstReg|ModRM, 0, DstReg|SrcReg|ModRM, 0, DstReg|SrcMem|ModRM|Mov, ImplicitOps|ModRM,
    /* 0x70 - 0x7F */
    DstReg|ModRM|SrcImmByte, 0, 0, DstReg|ModRM|SrcImmByte, DstReg|SrcMem|ModRM, 0, DstReg|SrcReg|ModRM, 0, 0, 0, 0, 0, 0, 0, DstReg|SrcMem|ModRM, ImplicitOps|ModRM,
    /* 0x80 - 0x87 */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x88 - 0x8F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x90 - 0x97 */
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    /* 0x98 - 0x9F */
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    ByteOp|DstMem|SrcNone|ModRM|Mov, ByteOp|DstMem|SrcNone|ModRM|Mov,
    /* 0xA0 - 0xA7 */
    ImplicitOps, ImplicitOps, ImplicitOps, DstBitBase|SrcReg|ModRM,
    DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM, 0, 0,
    /* 0xA8 - 0xAF */
    ImplicitOps, ImplicitOps, 0, DstBitBase|SrcReg|ModRM,
    DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ImplicitOps|ModRM, DstReg|SrcMem|ModRM,
    /* 0xB0 - 0xB7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    DstReg|SrcMem|ModRM|Mov, DstBitBase|SrcReg|ModRM,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xB8 - 0xBF */
    SrcReg|DstReg|ModRM, 0, DstBitBase|SrcImmByte|ModRM, DstBitBase|SrcReg|ModRM,
    DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    0, DstMem|SrcReg|ModRM|Mov,
    0, 0, SrcReg|DstReg|ModRM|SrcImmByte, ImplicitOps|ModRM,
    /* 0xC8 - 0xCF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0xD0 - 0xD7 */
    0, 0, 0, 0, DstReg|SrcReg|ModRM, 0, SrcReg|DstMem|ModRM, DstReg|SrcReg|ModRM|Mov,
    /* 0xD8 - 0xDF */
    0, 0, SrcMem|DstReg|ModRM, ImplicitOps|ModRM, 0, 0, DstReg|SrcMem|ModRM, SrcReg|DstReg|ModRM,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, DstReg|SrcMem|ModRM, 0, 0, 0, DstReg|SrcMem|ModRM,
    /* 0xF0 - 0xFF */
    SrcMem|DstReg|ModRM, 0, 0, 0, SrcReg|DstReg|ModRM, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, 0, 0, SrcReg|DstReg|ModRM, 0
};

static uint8_t threebyte_table_38[256] = {
    [0x00] = SrcReg|DstReg|ModRM,
    [0x17] = SrcReg|DstReg|ModRM,
    [0x29] = SrcReg|DstReg|ModRM
};

static uint8_t threebyte_table_3a[256] = {
    [0xf] = SrcReg|DstReg|ModRM|SrcImmByte,
    [0x63] = DstReg|ModRM|SrcImmByte
};

/* HACK: must be same definition as in x86_emulate.c, for compatibility. */
enum { OP_REG, OP_MEM, OP_IMM, OP_NONE } dummy;

#define REX_PREFIX 0x40
#define REX_B 0x01
#define REX_X 0x02
#define REX_R 0x04
#define REX_W 0x08

#define vex_none 0

enum vex_opcx {
    vex_0f = vex_none + 1,
    vex_0f38,
    vex_0f3a,
};

enum vex_pfx {
    vex_66 = vex_none + 1,
    vex_f3,
    vex_f2
};

#define VEX_PREFIX_DOUBLE_MASK 0x1
#define VEX_PREFIX_SCALAR_MASK 0x2

static const uint8_t sse_prefix[] = { 0x66, 0xf3, 0xf2 };

#define SET_SSE_PREFIX(dst, vex_pfx) do { \
    if ( vex_pfx ) \
        (dst) = sse_prefix[(vex_pfx) - 1]; \
} while (0)

union vex {
    uint8_t raw[2];
    struct {
        uint8_t opcx:5;
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t pfx:2;
        uint8_t l:1;
        uint8_t reg:4;
        uint8_t w:1;
    };
};

#define copy_REX_VEX(ptr, rex, vex) do { \
    if ( (vex).opcx != vex_none ) \
        ptr[0] = 0xc4, ptr[1] = (vex).raw[0], ptr[2] = (vex).raw[1]; \
    else if ( mode_64bit() ) \
        ptr[1] = rex | REX_PREFIX; \
} while (0)

#define rep_prefix()   (vex.pfx >= vex_f3)
#define repe_prefix()  (vex.pfx == vex_f3)
#define repne_prefix() (vex.pfx == vex_f2)

/* Type, address-of, and value of an instruction's operand. */
struct operand {
    operand_type_t type;
    unsigned int bytes;

    /* Up to 128-byte operand value, addressable as ulong or uint32_t[]. */
    union {
        unsigned long val;
        uint32_t bigval[4];
    };

    /* Up to 128-byte operand value, addressable as ulong or uint32_t[]. */
    union {
        unsigned long orig_val;
        uint32_t orig_bigval[4];
    };

    /* OP_REG: Pointer to register field. */
    unsigned long *reg;

    /* OP_MEM: Segment and offset. Also remember any register(s) it came from. */
    struct {
        enum x86_segment seg;
        unsigned long    off;
        unsigned fromreg1, fromreg2;
    } mem;
};
#ifdef __x86_64__
#define REG_POISON ((unsigned long *) 0x8086000000008086UL) /* non-canonical */
#else
#define REG_POISON NULL /* 32-bit builds are for user-space, so NULL is OK. */
#endif

typedef union {
    uint64_t mmx;
    uint64_t __attribute__ ((aligned(16))) xmm[2];
    uint64_t __attribute__ ((aligned(32))) ymm[4];
} mmval_t;

/*
 * While proper alignment gets specified above, this doesn't get honored by
 * the compiler for automatic variables. Use this helper to instantiate a
 * suitably aligned variable, producing a pointer to access it.
 */
#define DECLARE_ALIGNED(type, var)                                   \
    long __##var[sizeof(type) + __alignof(type) - __alignof(long)];  \
    type *const var##p =                                             \
        (void *)((long)(__##var + __alignof(type) - __alignof(long)) \
                 & -__alignof(type))

/* MSRs. */
#define MSR_TSC          0x00000010
#define MSR_SYSENTER_CS  0x00000174
#define MSR_SYSENTER_ESP 0x00000175
#define MSR_SYSENTER_EIP 0x00000176
#define MSR_EFER         0xc0000080
#define EFER_SCE         (1u<<0)
#define EFER_LMA         (1u<<10)
#define MSR_STAR         0xc0000081
#define MSR_LSTAR        0xc0000082
#define MSR_CSTAR        0xc0000083
#define MSR_FMASK        0xc0000084
#define MSR_TSC_AUX      0xc0000103

/* Control register flags. */
#define CR0_PE    (1<<0)
#define CR4_TSD   (1<<2)

/* EFLAGS bit definitions. */
#define EFLG_VIP  (1<<20)
#define EFLG_VIF  (1<<19)
#define EFLG_AC   (1<<18)
#define EFLG_VM   (1<<17)
#define EFLG_RF   (1<<16)
#define EFLG_NT   (1<<14)
#define EFLG_IOPL (3<<12)
#define EFLG_OF   (1<<11)
#define EFLG_DF   (1<<10)
#define EFLG_IF   (1<<9)
#define EFLG_TF   (1<<8)
#define EFLG_SF   (1<<7)
#define EFLG_ZF   (1<<6)
#define EFLG_AF   (1<<4)
#define EFLG_PF   (1<<2)
#define EFLG_CF   (1<<0)

/* Exception definitions. */
#define EXC_DE  0
#define EXC_DB  1
#define EXC_BP  3
#define EXC_OF  4
#define EXC_BR  5
#define EXC_UD  6
#define EXC_TS 10
#define EXC_NP 11
#define EXC_SS 12
#define EXC_GP 13
#define EXC_PF 14
#define EXC_MF 16

/* Segment selector error code bits. */
#define ECODE_EXT (1 << 0)
#define ECODE_IDT (1 << 1)
#define ECODE_TI  (1 << 2)

/*
 * Instruction emulation:
 * Most instructions are emulated directly via a fragment of inline assembly
 * code. This allows us to save/restore EFLAGS and thus very easily pick up
 * any modified flags.
 */

#if defined(__x86_64__)
#define _LO32 "k"          /* force 32-bit operand */
#define _STK  "%%rsp"      /* stack pointer */
#define _BYTES_PER_LONG "8"
#elif defined(__i386__)
#define _LO32 ""           /* force 32-bit operand */
#define _STK  "%%esp"      /* stack pointer */
#define _BYTES_PER_LONG "4"
#endif

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size)                                         \
({ unsigned long _x = 0, _eip = _regs.eip;                              \
   if ( !mode_64bit() ) _eip = (uint32_t)_eip; /* ignore upper dword */ \
   _regs.eip += (_size); /* real hardware doesn't truncate */           \
   generate_exception_if((uint8_t)(_regs.eip - ctxt->regs->eip) > 15,   \
                         EXC_GP, 0);                                    \
   rc = ops->insn_fetch(x86_seg_cs, _eip, &_x, (_size), ctxt);          \
   if ( rc ) goto done;                                                 \
   _x;                                                                  \
})
#define insn_fetch_type(_type) ((_type)insn_fetch_bytes(sizeof(_type)))

#define truncate_word(ea, byte_width)           \
({  unsigned long __ea = (ea);                  \
    unsigned int _width = (byte_width);         \
    ((_width == sizeof(unsigned long)) ? __ea : \
     (__ea & ((1UL << (_width << 3)) - 1)));    \
})
#define truncate_ea(ea) truncate_word((ea), ad_bytes)

#define mode_64bit() (def_ad_bytes == 8)

#define fail_if(p)                                      \
do {                                                    \
    rc = (p) ? X86EMUL_UNHANDLEABLE : X86EMUL_OKAY;     \
    if ( rc ) goto done;                                \
} while (0)

#define generate_exception_if(p, e, ec)                                   \
({  if ( (p) ) {                                                          \
        fail_if(ops->inject_hw_exception == NULL);                        \
        rc = ops->inject_hw_exception(e, ec, ctxt) ? : X86EMUL_EXCEPTION; \
        goto done;                                                        \
    }                                                                     \
})

/*
 * Given byte has even parity (even number of 1s)? SDM Vol. 1 Sec. 3.4.3.1,
 * "Status Flags": EFLAGS.PF reflects parity of least-sig. byte of result only.
 */
static bool_t even_parity(uint8_t v)
{
    asm ( "test %b0,%b0; setp %b0" : "=a" (v) : "0" (v) );
    return v;
}

struct fpu_insn_ctxt {
    uint8_t insn_bytes;
    uint8_t exn_raised;
};

static unsigned long _get_rep_prefix(
    const struct cpu_user_regs *int_regs,
    int ad_bytes)
{
    return (ad_bytes == 2) ? (uint16_t)int_regs->ecx :
           (ad_bytes == 4) ? (uint32_t)int_regs->ecx :
           int_regs->ecx;
}

#define get_rep_prefix() ({                                             \
    unsigned long max_reps = 1;                                         \
    if ( rep_prefix() )                                                 \
        max_reps = _get_rep_prefix(&_regs, ad_bytes);                   \
    if ( max_reps == 0 )                                                \
    {                                                                   \
        /* Skip the instruction if no repetitions are required. */      \
        dst.type = OP_NONE;                                             \
        goto report;                                                    \
    }                                                                   \
    max_reps;                                                           \
})

void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs *regs, int highbyte_regs)
{
    void *p;

    switch ( modrm_reg )
    {
    case  0: p = &regs->eax; break;
    case  1: p = &regs->ecx; break;
    case  2: p = &regs->edx; break;
    case  3: p = &regs->ebx; break;
    case  4: p = (highbyte_regs ?
                  ((unsigned char *)&regs->eax + 1) :
                  (unsigned char *)&regs->esp); break;
    case  5: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ecx + 1) :
                  (unsigned char *)&regs->ebp); break;
    case  6: p = (highbyte_regs ?
                  ((unsigned char *)&regs->edx + 1) :
                  (unsigned char *)&regs->esi); break;
    case  7: p = (highbyte_regs ?
                  ((unsigned char *)&regs->ebx + 1) :
                  (unsigned char *)&regs->edi); break;
#if defined(__x86_64__)
    case  8: p = &regs->r8;  break;
    case  9: p = &regs->r9;  break;
    case 10: p = &regs->r10; break;
    case 11: p = &regs->r11; break;
    case 12: mark_regs_dirty(regs); p = &regs->r12; break;
    case 13: mark_regs_dirty(regs); p = &regs->r13; break;
    case 14: mark_regs_dirty(regs); p = &regs->r14; break;
    case 15: mark_regs_dirty(regs); p = &regs->r15; break;
#endif
    default: BUG(); p = NULL; break;
    }

    return p;
}

#define decode_segment_failed x86_seg_tr
static enum x86_segment
decode_segment(uint8_t modrm_reg)
{
    switch ( modrm_reg )
    {
    case 0: return x86_seg_es;
    case 1: return x86_seg_cs;
    case 2: return x86_seg_ss;
    case 3: return x86_seg_ds;
    case 4: return x86_seg_fs;
    case 5: return x86_seg_gs;
    default: break;
    }
    return decode_segment_failed;
}

static bool_t
in_realmode(
	struct x86_emulate_ctxt *ctxt,
	const struct x86_emulate_ops  *ops)
{
	//unsigned long cr0;
	//int rc;
	//
	//if ( ops->read_cr == NULL )
	//	return 0;
	//
	//rc = ops->read_cr(0, &cr0, ctxt);
	//return (!rc && !(cr0 & CR0_PE));
	return 0;
}


int
x86_decode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops,
    const struct x86_decode_ops *decode_ops)
{
    /* Shadow copy of register state. Committed on successful emulation. */
    struct cpu_user_regs _regs = *ctxt->regs;

    uint8_t b, d, sib, sib_index, sib_base, twobyte = 0, threebyte = 0, rex_prefix = 0;
    uint8_t modrm = 0, modrm_mod = 0, modrm_reg = 0, modrm_rm = 0;
    union vex vex = {};
    unsigned int op_bytes, def_op_bytes, ad_bytes, def_ad_bytes;
    bool_t lock_prefix = 0;
    int override_seg = -1, rc = X86EMUL_OKAY;
    struct operand src = { .reg = REG_POISON };
    struct operand dst = { .reg = REG_POISON };
    enum x86_swint_type swint_type;
    DECLARE_ALIGNED(mmval_t, mmval);
    /*
     * Data operand effective address (usually computed from ModRM).
     * Default is a memory operand relative to segment DS.
     */
    struct operand ea = { .type = OP_MEM, .reg = REG_POISON };
    ea.mem.seg = x86_seg_ds; /* gcc may reject anon union initializer */
    ea.mem.fromreg1 = (unsigned) -1;
    ea.mem.fromreg2 = (unsigned) -1;

    ctxt->retire.byte = 0;

    op_bytes = def_op_bytes = ad_bytes = def_ad_bytes = ctxt->addr_size/8;
    if ( op_bytes == 8 )
    {
        op_bytes = def_op_bytes = 4;
#ifndef __x86_64__
        return X86EMUL_UNHANDLEABLE;
#endif
    }

    /* Prefix bytes. */
    for ( ; ; )
    {
        switch ( b = insn_fetch_type(uint8_t) )
        {
        case 0x66: /* operand-size override */
            op_bytes = def_op_bytes ^ 6;
            if ( !vex.pfx )
                vex.pfx = vex_66;
            break;
        case 0x67: /* address-size override */
            ad_bytes = def_ad_bytes ^ (mode_64bit() ? 12 : 6);
            break;
        case 0x2e: /* CS override */
            override_seg = x86_seg_cs;
            break;
        case 0x3e: /* DS override */
            override_seg = x86_seg_ds;
            break;
        case 0x26: /* ES override */
            override_seg = x86_seg_es;
            break;
        case 0x64: /* FS override */
            override_seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            override_seg = x86_seg_gs;
            break;
        case 0x36: /* SS override */
            override_seg = x86_seg_ss;
            break;
        case 0xf0: /* LOCK */
            lock_prefix = 1;
            break;
        case 0xf2: /* REPNE/REPNZ */
            vex.pfx = vex_f2;
            break;
        case 0xf3: /* REP/REPE/REPZ */
            vex.pfx = vex_f3;
            break;
        case 0x40 ... 0x4f: /* REX */
            if ( !mode_64bit() )
                goto done_prefixes;
            rex_prefix = b;
            continue;
        default:
            goto done_prefixes;
        }

        /* Any legacy prefix after a REX prefix nullifies its effect. */
        rex_prefix = 0;
    }
 done_prefixes:

    if ( rex_prefix & REX_W )
        op_bytes = 8;

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 )
    {
        /* Two-byte opcode? */
        if ( b == 0x0f )
        {
            twobyte = 1;
            b = insn_fetch_type(uint8_t);
            d = twobyte_table[b];
            
            if ( d == 0 )
            {
                if ( b == 0x38 || b == 0x3a )
                {
                    twobyte = 0;
                    threebyte = b;
                    b = insn_fetch_type(uint8_t);
                    d = (threebyte == 0x38 ? threebyte_table_38 : threebyte_table_3a)[b];
                }
            }
        }

        /* Unrecognised? */
        if ( d == 0 )
            goto cannot_emulate;
    }

    /* Lock prefix is allowed only on RMW instructions. */
    generate_exception_if((d & Mov) && lock_prefix, EXC_UD, -1);

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        modrm = insn_fetch_type(uint8_t);
        modrm_mod = (modrm & 0xc0) >> 6;

        if ( !twobyte && !threebyte && ((b & ~1) == 0xc4) )
            switch ( def_ad_bytes )
            {
            default:
                BUG();
            case 2:
                if ( in_realmode(ctxt, ops) || (_regs.eflags & EFLG_VM) )
                    break;
                /* fall through */
            case 4:
                if ( modrm_mod != 3 )
                    break;
                /* fall through */
            case 8:
                /* VEX */
                generate_exception_if(rex_prefix || vex.pfx, EXC_UD, -1);

                vex.raw[0] = modrm;
                if ( b & 1 ) // 0xc5, a.k.a. two-byte VEX
                {
                    vex.raw[1] = modrm; // init then modify
                    vex.opcx = vex_0f;
                    vex.x = 1;
                    vex.b = 1;
                    vex.w = 0;
                }
                else // 0xc4, a.k.a. three-byte VEX
                {
                    vex.raw[1] = insn_fetch_type(uint8_t); // we've now fetched *three* bytes: 0xc[45], modrm/vex[0], and vex[1]
                    if ( mode_64bit() )
                    {
                        if ( !vex.b )
                            rex_prefix |= REX_B;
                        if ( !vex.x )
                            rex_prefix |= REX_X;
                        if ( vex.w )
                        {
                            rex_prefix |= REX_W;
                            op_bytes = 8;
                        }
                    }
                }
                if ( mode_64bit() && !vex.r )
                    rex_prefix |= REX_R;

                /* currently:
                 * 'b' has the first byte, 0xc[45]
                 * 'modrm' has the second physical byte
                 * 'vex.raw[1]' may have the third physical byte, if we're three-byte-VEX.
                 *
                 * We haven't read the opcode yet!
                 * BUT we know that it begins 0f,
                 *      and we may know that it begins 0f 38 or 0f 3a.
                 * We want to proceed with using 'b' to index the twobyte table.
                 * So we need to set 'b' to the byte that comes after '0f'. */
                switch (vex.opcx)
                {
                    case vex_0f:
                        b = insn_fetch_type(uint8_t);
                        goto vex_supplied_after_0f;
                    case vex_0f38:
                        b = threebyte = 0x38;
                        goto vex_supplied_after_0f;
                    case vex_0f3a:
                        b = threebyte = 0x3a;
                        goto vex_supplied_after_0f;
                    default: fail_if(1);
                }
                /* Don't fail on 38 and 3a.
                 * Here's what qemu does.
                 
                  -- remember the 3byte; it's either 3a, 38 or (plain 0f case) the actual next by
                  
                  -- look up properties of the 3byte (need_modrm, ...)
                          in the *twobyte* table,
                          i.e. for instructions 0f xx ..., we look up xx
                  -- some of them say IS_3BYTE_OPCODE; if so, we fetch the actual third byte, "op
                          and look up the same properties in two separate tables:
                             one for the "38" three-byte opcodes,
                             one for the "3a" three-byte opcodes.
                          
   if (prefixes & PREFIX_VEX_0F)
    {
      used_prefixes |= PREFIX_VEX_0F | PREFIX_VEX_0F38 | PREFIX_VEX_0F3A;
      if (prefixes & PREFIX_VEX_0F38)
        threebyte = 0x38;
      else if (prefixes & PREFIX_VEX_0F3A)
        threebyte = 0x3a;
      else
        threebyte = *codep++;
      goto vex_opcode;
    }
  if (*codep == 0x0f)
    {
      fetch_data(info, codep + 2);
      threebyte = codep[1];
      codep += 2;
    vex_opcode:
      dp = &dis386_twobyte[threebyte];
      need_modrm = twobyte_has_modrm[threebyte];
      uses_DATA_prefix = twobyte_uses_DATA_prefix[threebyte];
      uses_REPNZ_prefix = twobyte_uses_REPNZ_prefix[threebyte];
      uses_REPZ_prefix = twobyte_uses_REPZ_prefix[threebyte];
      uses_LOCK_prefix = (threebyte & ~0x02) == 0x20;
      if (dp->name == NULL && dp->op[0].bytemode == IS_3BYTE_OPCODE)
   {
          fetch_data(info, codep + 2);
     op = *codep++;
     switch (threebyte)
       {
       case 0x38:
         uses_DATA_prefix = threebyte_0x38_uses_DATA_prefix[op];
         uses_REPNZ_prefix = threebyte_0x38_uses_REPNZ_prefix[op];
         uses_REPZ_prefix = threebyte_0x38_uses_REPZ_prefix[op];
         break;
       case 0x3a:
         uses_DATA_prefix = threebyte_0x3a_uses_DATA_prefix[op];
         uses_REPNZ_prefix = threebyte_0x3a_uses_REPNZ_prefix[op];
         uses_REPZ_prefix = threebyte_0x3a_uses_REPZ_prefix[op];
         break;
       default:
         break;
       }
   }
    }
  else
    {
                 */
                
                /* we're definitely a two- or three-byte insn here */
            vex_supplied_after_0f:
                d = twobyte_table[b];

                /* Unrecognised? */
                if ( d == 0 )
                {
                    if (threebyte == 0x38 || threebyte == 0x3a)
                    {
                        b = insn_fetch_type(uint8_t);
                        d = (threebyte == 0x38 ? threebyte_table_38 : threebyte_table_3a)[b];
                    }
                    
                    if (d == 0) goto cannot_emulate;
                }
                else twobyte = 1;
                /* Now we're past the opcode and can fetch the actual modrm byte. */
                modrm = insn_fetch_type(uint8_t);
                modrm_mod = (modrm & 0xc0) >> 6;

                break;
            } /* end if b in {0xc4,0xc5} */

        modrm_reg = ((rex_prefix & 4) << 1) | ((modrm & 0x38) >> 3);
        modrm_rm  = modrm & 0x07;

        if ( modrm_mod == 3 )
        {
            modrm_rm |= (rex_prefix & 1) << 3;
            ea.type = OP_REG;
            ea.reg  = decode_register(
                modrm_rm, &_regs, (d & ByteOp) && (rex_prefix == 0));
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            switch ( modrm_rm )
            {
            case 0:
                ea.mem.off = _regs.ebx + _regs.esi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebx);
                ea.mem.fromreg2 = offsetof(struct cpu_user_regs, esi);
                break;
            case 1:
                ea.mem.off = _regs.ebx + _regs.edi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebx);
                ea.mem.fromreg2 = offsetof(struct cpu_user_regs, edi);
                break;
            case 2:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = _regs.ebp + _regs.esi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebp);
                ea.mem.fromreg2 = offsetof(struct cpu_user_regs, ss);
                break;
            case 3:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = _regs.ebp + _regs.edi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebp);
                ea.mem.fromreg2 = offsetof(struct cpu_user_regs, edi);
                break;
            case 4:
                ea.mem.off = _regs.esi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, esi);
                break;
            case 5:
                ea.mem.off = _regs.edi;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, edi);
                break;
            case 6:
                if ( modrm_mod == 0 )
                    break;
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = _regs.ebp;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebp);
                break;
            case 7:
                ea.mem.off = _regs.ebx;
                ea.mem.fromreg1 = offsetof(struct cpu_user_regs, ebx);
                break;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 )
                    ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            if ( modrm_rm == 4 )
            {
                sib = insn_fetch_type(uint8_t);
                sib_index = ((sib >> 3) & 7) | ((rex_prefix << 2) & 8);
                sib_base  = (sib & 7) | ((rex_prefix << 3) & 8);
                if ( sib_index != 4 ) {
                    long *ptr = (long*)decode_register(sib_index, &_regs, 0);
                    ea.mem.off = *ptr;
                    ea.mem.fromreg1 = (char*) ptr - (char*) &_regs;
                }
                ea.mem.off <<= (sib >> 6) & 3;
                if ( (modrm_mod == 0) && ((sib_base & 7) == 5) )
                    ea.mem.off += insn_fetch_type(int32_t);
                else if ( sib_base == 4 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += _regs.esp;
                    if ( !twobyte && !threebyte && (b == 0x8f) )
                        /* POP <rm> computes its EA post increment. */
                        ea.mem.off += ((mode_64bit() && (op_bytes == 4))
                                       ? 8 : op_bytes);
                }
                else if ( sib_base == 5 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += _regs.ebp;
                    ea.mem.fromreg2 = offsetof(struct cpu_user_regs, ebp);
                }
                else
                {
                    long *ptr = (long*)decode_register(sib_base, &_regs, 0);
                    ea.mem.off += *ptr;
                    ea.mem.fromreg2 = (char*) ptr - (char*) &_regs;
                }
            }
            else
            {
                modrm_rm |= (rex_prefix & 1) << 3;
                long *ptr = (long *)decode_register(modrm_rm, &_regs, 0);
                ea.mem.off = *ptr;
                ea.mem.fromreg1 = (char*) ptr - (char*) &_regs;
                if ( (modrm_rm == 5) && (modrm_mod != 0) )
                    ea.mem.seg = x86_seg_ss;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm & 7) != 5 )
                    break;
                ea.mem.off = insn_fetch_type(int32_t);
                if ( !mode_64bit() )
                    break;
                /* Relative to RIP of next instruction. Argh! */
                ea.mem.off += _regs.eip;
                if ( (d & SrcMask) == SrcImm )
                    ea.mem.off += (d & ByteOp) ? 1 :
                        ((op_bytes == 8) ? 4 : op_bytes);
                else if ( (d & SrcMask) == SrcImmByte )
                    ea.mem.off += 1;
                else if ( !twobyte && !threebyte && ((b & 0xfe) == 0xf6) &&
                          ((modrm_reg & 7) <= 1) )
                    /* Special case in Grp3: test has immediate operand. */
                    ea.mem.off += (d & ByteOp) ? 1
                        : ((op_bytes == 8) ? 4 : op_bytes);
                else if ( twobyte && ((b & 0xf7) == 0xa4) )
                    /* SHLD/SHRD with immediate byte third operand. */
                    ea.mem.off++;
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
            ea.mem.off = truncate_ea(ea.mem.off);
        } /* end else 32/64-bit ModR/M decode */
    } /* end if apparently ModRM */
    
    /* really finished opcode decode now, so ... */
    if (decode_ops->saw_opcode)
    {
        if (threebyte) decode_ops->saw_opcode(0x0f << 8 | (threebyte << 8) | b);
        else if (twobyte) decode_ops->saw_opcode((0x0f << 8) | b);
        else decode_ops->saw_opcode(b);
    }

    if ( override_seg != -1 && ea.type == OP_MEM )
        ea.mem.seg = override_seg;

    /* Early operand adjustments. */
    if ( !twobyte && !threebyte )
        switch ( b )
        {
        case 0xf6 ... 0xf7: /* Grp3 */
            switch ( modrm_reg & 7 )
            {
            case 0 ... 1: /* test */
                d = (d & ~SrcMask) | SrcImm;
                break;
            case 4: /* mul */
            case 5: /* imul */
            case 6: /* div */
            case 7: /* idiv */
                d = (d & (ByteOp | ModRM)) | DstImplicit | SrcMem;
                break;
            }
            break;
        case 0xff: /* Grp5 */
            switch ( modrm_reg & 7 )
            {
            case 2: /* call (near) */
            case 4: /* jmp (near) */
            case 6: /* push */
                if ( mode_64bit() && op_bytes == 4 )
                    op_bytes = 8;
                /* fall through */
            case 3: /* call (far, absolute indirect) */
            case 5: /* jmp (far, absolute indirect) */
                d = DstNone|SrcMem|ModRM;
                break;
            }
            break;
        }

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcNone: /* case SrcImplicit: */
        src.type = OP_NONE;
        break;
    case SrcReg:
        src.type = OP_REG;
        if ( d & ByteOp )
        {
            src.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            src.val = *(uint8_t *)src.reg;
            src.bytes = 1;
        }
        else
        {
            src.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (src.bytes = op_bytes) )
            {
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        break;
    case SrcMem16:
        ea.bytes = 2;
        goto srcmem_common;
    case SrcMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
    srcmem_common:
        src = ea;
        if ( src.type == OP_REG )
        {
            switch ( src.bytes )
            {
            case 1: src.val = *(uint8_t  *)src.reg; break;
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        //else if ( (rc = read_ulong(src.mem.seg, src.mem.off,
        //                           &src.val, src.bytes, ctxt, ops)) )
        //    goto done;
        break;
    case SrcImm:
        src.type  = OP_IMM;
        src.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( src.bytes == 8 ) src.bytes = 4;
        /* NB. Immediates are sign-extended as necessary. */
        switch ( src.bytes )
        {
        case 1: src.val = insn_fetch_type(int8_t);  break;
        case 2: src.val = insn_fetch_type(int16_t); break;
        case 4: src.val = insn_fetch_type(int32_t); break;
        }
        break;
    case SrcImmByte:
        src.type  = OP_IMM;
        src.bytes = 1;
        src.val   = insn_fetch_type(int8_t);
        break;
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case DstNone: /* case DstImplicit: */
        /*
         * The only implicit-operands instructions allowed a LOCK prefix are
         * CMPXCHG{8,16}B, MOV CRn, MOV DRn.
         */
        generate_exception_if(
            lock_prefix &&
            ((b < 0x20) || (b > 0x23)) && /* MOV CRn/DRn */
            (b != 0xc7),                  /* CMPXCHG{8,16}B */
            EXC_UD, -1);
        dst.type = OP_NONE;
        break;

    case DstReg:
        generate_exception_if(lock_prefix, EXC_UD, -1);
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.reg = decode_register(modrm_reg, &_regs, (rex_prefix == 0));
            dst.val = *(uint8_t *)dst.reg;
            dst.bytes = 1;
        }
        else
        {
            dst.reg = decode_register(modrm_reg, &_regs, 0);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        break;
    case DstBitBase:
        if ( ((d & SrcMask) == SrcImmByte) || (ea.type == OP_REG) )
        {
            src.val &= (op_bytes << 3) - 1;
        }
        else
        {
            /*
             * EA       += BitOffset DIV op_bytes*8
             * BitOffset = BitOffset MOD op_bytes*8
             * DIV truncates towards negative infinity.
             * MOD always produces a positive result.
             */
            if ( op_bytes == 2 )
                src.val = (int16_t)src.val;
            else if ( op_bytes == 4 )
                src.val = (int32_t)src.val;
            if ( (long)src.val < 0 )
            {
                unsigned long byte_offset;
                byte_offset = op_bytes + (((-src.val-1) >> 3) & ~(op_bytes-1));
                ea.mem.off -= byte_offset;
                src.val = (byte_offset << 3) + src.val;
            }
            else
            {
                ea.mem.off += (src.val >> 3) & ~(op_bytes - 1);
                src.val &= (op_bytes << 3) - 1;
            }
        }
        /* Becomes a normal DstMem operation from here on. */
        d = (d & ~DstMask) | DstMem;
    case DstMem:
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst = ea;
        if ( dst.type == OP_REG )
        {
            generate_exception_if(lock_prefix, EXC_UD, -1);
            switch ( dst.bytes )
            {
            case 1: dst.val = *(uint8_t  *)dst.reg; break;
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        else if ( !(d & Mov) ) /* optimisation - avoid slow emulated read */
        {
            //if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
            //                      &dst.val, dst.bytes, ctxt, ops)) )
            //    goto done;
            //dst.orig_val = dst.val;
        }
        break;
    }

    if ( twobyte )
        goto twobyte_insn;

    if ( threebyte == 0x38 )
        goto threebyte_insn_38;

    if ( threebyte == 0x3a )
        goto threebyte_insn_3a;


    // fetch mostly finished here...

    switch ( b )
    {

    case 0x68: /* push imm{16,32,64} */
        src.val = ((op_bytes == 2)
                   ? (int32_t)insn_fetch_type(int16_t)
                   : insn_fetch_type(int32_t));
        goto push;

    case 0x6a: /* push imm8 */
        src.val = insn_fetch_type(int8_t);
    push:
        break;

    case 0x70 ... 0x7f: /* jcc (short) */ {
        int rel = insn_fetch_type(int8_t);
        // if ( test_cc(b, _regs.eflags) )
        //     jmp_rel(rel);
        break;
    }

    case 0x9a: /* call (far, absolute) */ {
        struct segment_register reg;
        uint16_t sel;
        uint32_t eip;

        generate_exception_if(mode_64bit(), EXC_UD, -1);
        fail_if(ops->read_segment == NULL);

        eip = insn_fetch_bytes(op_bytes);
        sel = insn_fetch_type(uint16_t);
        break;
    }

    case 0xa0 ... 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
        /* Source EA is not encoded via ModRM. */
        dst.type  = OP_REG;
        dst.reg   = (unsigned long *)&_regs.eax;
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        int srk_tmp = insn_fetch_bytes(ad_bytes);
        //if ( (rc = read_ulong(ea.mem.seg, tmp,
        //                      &dst.val, dst.bytes, ctxt, ops)) != 0 )
        //    goto done;
        break;

    case 0xa2 ... 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Destination EA is not encoded via ModRM. */
        dst.type  = OP_MEM;
        dst.mem.seg = ea.mem.seg;
        dst.mem.off = insn_fetch_bytes(ad_bytes);
        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.val   = (unsigned long)_regs.eax;
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        if ( dst.bytes == 8 ) /* Fetch more bytes to obtain imm64 */
            src.val = ((uint32_t)src.val |
                       ((uint64_t)insn_fetch_type(uint32_t) << 32));
        //dst.reg = decode_register(
        //    (b & 7) | ((rex_prefix & 1) << 3), &_regs, 0);
        //dst.val = src.val;
        break;

    case 0xc2: /* ret imm16 (near) */
    case 0xc3: /* ret (near) */ {
        int offset = (b == 0xc2) ? insn_fetch_type(uint16_t) : 0;
        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        //if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + offset),
        //                      &dst.val, op_bytes, ctxt, ops)) != 0 )
        //    goto done;
        //_regs.eip = dst.val;
        break;
    }

    case 0xc8: /* enter imm16,imm8 */ {
        uint16_t size = insn_fetch_type(uint16_t);
        uint8_t depth = insn_fetch_type(uint8_t) & 31;
//         int i;
// 
//         dst.type = OP_REG;
//         dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
//         dst.reg = (unsigned long *)&_regs.ebp;
//         if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
//                               &_regs.ebp, dst.bytes, ctxt)) )
//             goto done;
//         dst.val = _regs.esp;
// 
//         if ( depth > 0 )
//         {
//             for ( i = 1; i < depth; i++ )
//             {
//                 unsigned long ebp, temp_data;
//                 ebp = truncate_word(_regs.ebp - i*dst.bytes, ctxt->sp_size/8);
//                 if ( (rc = read_ulong(x86_seg_ss, ebp,
//                                       &temp_data, dst.bytes, ctxt, ops)) ||
//                      (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
//                                       &temp_data, dst.bytes, ctxt)) )
//                     goto done;
//             }
//             if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
//                                   &dst.val, dst.bytes, ctxt)) )
//                 goto done;
//         }
// 
//         sp_pre_dec(size);
        break;
    }

    case 0xca: /* ret imm16 (far) */
    case 0xcb: /* ret (far) */ {
        int offset = (b == 0xca) ? insn_fetch_type(uint16_t) : 0;
        //if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
        //                      &dst.val, op_bytes, ctxt, ops)) ||
        //     (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + offset),
        //                      &src.val, op_bytes, ctxt, ops)) ||
        //     (rc = load_seg(x86_seg_cs, src.val, 1, ctxt, ops)) )
        //    goto done;
        //_regs.eip = dst.val;
        break;
    }
	
    case 0xcd: /* int imm8 */
        src.val = insn_fetch_type(uint8_t);
//        swint_type = x86_swint_int;
//    swint:
//        rc = inject_swint(swint_type, src.val,
//                          _regs.eip - ctxt->regs->eip,
//                          ctxt, ops) ? : X86EMUL_EXCEPTION;
//        goto done;
    break; // srk added

    case 0xd4: /* aam */ {
        unsigned int base = insn_fetch_type(uint8_t);
        //uint8_t al = _regs.eax;
        //generate_exception_if(mode_64bit(), EXC_UD, -1);
        //generate_exception_if(base == 0, EXC_DE, -1);
        //*(uint16_t *)&_regs.eax = ((al / base) << 8) | (al % base);
        //_regs.eflags &= ~(EFLG_SF|EFLG_ZF|EFLG_PF);
        //_regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        //_regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        //_regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0xd5: /* aad */ {
        unsigned int base = insn_fetch_type(uint8_t);
        //uint16_t ax = _regs.eax;
        //generate_exception_if(mode_64bit(), EXC_UD, -1);
        //*(uint16_t *)&_regs.eax = (uint8_t)(ax + ((ax >> 8) * base));
        //_regs.eflags &= ~(EFLG_SF|EFLG_ZF|EFLG_PF);
        //_regs.eflags |= ((uint8_t)_regs.eax == 0) ? EFLG_ZF : 0;
        //_regs.eflags |= (( int8_t)_regs.eax <  0) ? EFLG_SF : 0;
        //_regs.eflags |= even_parity(_regs.eax) ? EFLG_PF : 0;
        break;
    }

    case 0xe0 ... 0xe2: /* loop{,z,nz} */ {
        int rel = insn_fetch_type(int8_t);
//         int do_jmp = !(_regs.eflags & EFLG_ZF); /* loopnz */
//         if ( b == 0xe1 )
//             do_jmp = !do_jmp; /* loopz */
//         else if ( b == 0xe2 )
//             do_jmp = 1; /* loop */
//         switch ( ad_bytes )
//         {
//         case 2:
//             do_jmp &= --(*(uint16_t *)&_regs.ecx) != 0;
//             break;
//         case 4:
//             do_jmp &= --(*(uint32_t *)&_regs.ecx) != 0;
//             _regs.ecx = (uint32_t)_regs.ecx; /* zero extend in x86/64 mode */
//             break;
//         default: /* case 8: */
//             do_jmp &= --_regs.ecx != 0;
//             break;
//         }
//         if ( do_jmp )
//             jmp_rel(rel);
        break;
    }

    case 0xe3: /* jcxz/jecxz (short) */ {
        int rel = insn_fetch_type(int8_t);
        //if ( (ad_bytes == 2) ? !(uint16_t)_regs.ecx :
        //     (ad_bytes == 4) ? !(uint32_t)_regs.ecx : !_regs.ecx )
        //    jmp_rel(rel);
        break;
    }

    case 0xe4: /* in imm8,%al */
    case 0xe5: /* in imm8,%eax */
    case 0xe6: /* out %al,imm8 */
    case 0xe7: /* out %eax,imm8 */
    case 0xec: /* in %dx,%al */
    case 0xed: /* in %dx,%eax */
    case 0xee: /* out %al,%dx */
    case 0xef: /* out %eax,%dx */ {
        unsigned int port = ((b < 0xe8)
                             ? insn_fetch_type(uint8_t)
                             : (uint16_t)_regs.edx);
        op_bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
//         if ( (rc = ioport_access_check(port, op_bytes, ctxt, ops)) != 0 )
//             goto done;
//         if ( b & 2 )
//         {
//             /* out */
//             fail_if(ops->write_io == NULL);
//             rc = ops->write_io(port, op_bytes, _regs.eax, ctxt);
//         }
//         else
//         {
//             /* in */
//             dst.type  = OP_REG;
//             dst.bytes = op_bytes;
//             dst.reg   = (unsigned long *)&_regs.eax;
//             fail_if(ops->read_io == NULL);
//             rc = ops->read_io(port, dst.bytes, &dst.val, ctxt);
//         }
//         if ( rc != 0 )
//             goto done;
        break;
    }

    case 0xe8: /* call (near) */ {
        int rel = ((op_bytes == 2)
                   ? (int32_t)insn_fetch_type(int16_t)
                   : insn_fetch_type(int32_t));
        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        // src.val = _regs.eip;
        // jmp_rel(rel);
        goto push;
    }

    case 0xe9: /* jmp (near) */ {
        int rel = ((op_bytes == 2)
                   ? (int32_t)insn_fetch_type(int16_t)
                   : insn_fetch_type(int32_t));
        // jmp_rel(rel);
        break;
    }

    case 0xea: /* jmp (far, absolute) */ {
        uint16_t sel;
        uint32_t eip;
        generate_exception_if(mode_64bit(), EXC_UD, -1);
        eip = insn_fetch_bytes(op_bytes);
        sel = insn_fetch_type(uint16_t);
        //if ( (rc = load_seg(x86_seg_cs, sel, 0, ctxt, ops)) != 0 )
        //    goto done;
        //_regs.eip = eip;
        break;
    }

    case 0xeb: /* jmp (short) */ {
        int rel = insn_fetch_type(int8_t);
        //jmp_rel(rel);
        break;
    }
    }

 report:
 done:
    //printf("Op size %d bytes, ip %p, rc %d, len %d\n", op_bytes, (void*) _regs.eip, rc,
    //    (char*) _regs.eip - (char*) ctxt->regs->eip);

#define ARGS(op) \
                op.type, \
                op.bytes, \
                &op.bigval[0], \
                &op.orig_bigval[0], \
                (op.type == OP_REG) ? op.reg : NULL, \
                (op.type == OP_MEM) ? &op.mem.seg : NULL, \
                (op.type == OP_MEM) ? &op.mem.off : NULL, \
                (op.type == OP_MEM) ? &op.mem.fromreg1 : NULL, \
                (op.type == OP_MEM) ? &op.mem.fromreg2 : NULL \
    
    if (rc == 0)
    {
        if (decode_ops->saw_operand)
        {
            if (src.type != OP_NONE
                && decode_ops->saw_operand(
                        ARGS(src)
                    )) return -X86EMUL_USER_ABORT;

            if (dst.type != OP_NONE
                &&  decode_ops->saw_operand(
                        ARGS(dst)
                    )) return -X86EMUL_USER_ABORT;

            if ((ea.type = OP_REG /* make "sure" we really do have a memory addr operand */
                    || (ea.type == OP_MEM && (d & ModRM)))
                &&  decode_ops->saw_operand(
                        ARGS(ea)
                    )) return -X86EMUL_USER_ABORT;
        }
        if (decode_ops->next_instr && 
                decode_ops->next_instr((unsigned char*) _regs.eip)) return -X86EMUL_USER_ABORT;
    }
    
    if (decode_ops->finished_decode && decode_ops->finished_decode()) return -X86EMUL_USER_ABORT;
    
    return (rc == 0) ? (char*) _regs.eip - (char*) ctxt->regs->eip : -rc;

 twobyte_insn:
    switch ( b )
    {

    case 0x80 ... 0x8f: /* jcc (near) */ {
        int rel = ((op_bytes == 2)
                   ? (int32_t)insn_fetch_type(int16_t)
                   : insn_fetch_type(int32_t));
        //if ( test_cc(b, _regs.eflags) )
        //    jmp_rel(rel);
        break;
    }

    case 0xa4: /* shld imm8,r,r/m */
    case 0xa5: /* shld %%cl,r,r/m */
    case 0xac: /* shrd imm8,r,r/m */
    case 0xad: /* shrd %%cl,r,r/m */ {
        uint8_t shift, width = dst.bytes << 3;
        shift = (b & 1) ? (uint8_t)_regs.ecx : insn_fetch_type(uint8_t);
//         if ( (shift &= width - 1) == 0 )
//             break;
//         dst.orig_val = truncate_word(dst.val, dst.bytes);
//         dst.val = ((shift == width) ? src.val :
//                    (b & 8) ?
//                    /* shrd */
//                    ((dst.orig_val >> shift) |
//                     truncate_word(src.val << (width - shift), dst.bytes)) :
//                    /* shld */
//                    ((dst.orig_val << shift) |
//                     ((src.val >> (width - shift)) & ((1ull << shift) - 1))));
//         dst.val = truncate_word(dst.val, dst.bytes);
//         _regs.eflags &= ~(EFLG_OF|EFLG_SF|EFLG_ZF|EFLG_PF|EFLG_CF);
//         if ( (dst.val >> ((b & 8) ? (shift - 1) : (width - shift))) & 1 )
//             _regs.eflags |= EFLG_CF;
//         if ( ((dst.val ^ dst.orig_val) >> (width - 1)) & 1 )
//             _regs.eflags |= EFLG_OF;
//         _regs.eflags |= ((dst.val >> (width - 1)) & 1) ? EFLG_SF : 0;
//         _regs.eflags |= (dst.val == 0) ? EFLG_ZF : 0;
//         _regs.eflags |= even_parity(dst.val) ? EFLG_PF : 0;
        break;
    }
    }
    goto report;

 threebyte_insn_38:
    switch (b)
    {
        default: goto report;
    }
    goto report;

 threebyte_insn_3a:
    switch (b)
    {
        default: goto report;
    }
    goto report;

 cannot_emulate:
    return X86EMUL_UNHANDLEABLE;
}
