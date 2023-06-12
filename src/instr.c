#define _GNU_SOURCE
#include "instr.h" /* our API -- in C */
#include <sys/types.h>
#include "raw-syscalls-defs.h"
#include "librunt.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <err.h>

#ifndef NO_TLS
#define THREAD __thread
#else
#define THREAD
#endif

__attribute__((visibility("hidden")))
_Bool is_ud2(const unsigned char *ins)
{
	return ins[0] == 0x0f && ins[1] == 0x0b;
}
/* We have four different ways of calculating the instruction length:
 * x86-decode (preferred), libudis86, opdis (slowest) and xed (not evaluated).
 * We want to allow configuration to select any one or more of these.
 * If none is defined, we select one or two based on NDEBUG. */

#if !defined(USE_X86_DECODE) && !defined(USE_UDIS86) && !defined(USE_OPDIS) && !defined(USE_XED)
#ifdef NDEBUG
#define USE_X86_DECODE
#else
#define USE_X86_DECODE
#define USE_OPDIS
#endif
#endif

#ifdef USE_XED
#include <xed/xed-interface.h>
#endif
#ifdef USE_UDIS86
#include <udis86.h>
#endif
#ifdef USE_X86_DECODE
#include "x86_defs.h"
#endif
#ifdef USE_OPDIS
#include <opdis/opdis.h>
#include <opdis/x86_decoder.h>
#endif

#ifdef USE_UDIS86
static ud_t ud_obj;
static void init_udis86() __attribute__((constructor));
static void init_udis86()
{
	ud_init(&ud_obj);
#if defined(__x86_64__)
	ud_set_mode(&ud_obj, 64); // FIXME: sysdep
#elif defined(__i386__)
	ud_set_mode(&ud_obj, 32); // FIXME: sysdep, UNTESTED. -srk
#else
#error "Unrecognised x86 architecture."
#endif
}
static int instr_len_udis86(unsigned char *ins, unsigned char *end)
{
	ud_set_input_buffer(&ud_obj, (const uint8_t *) ins, 15 /* HACK */);
	int ud_ret = ud_decode(&ud_obj);
	if (ud_ret)
	{
		unsigned ud_len = ud_insn_len(&ud_obj);
		return ud_len;
	}
	else return -1;
}
#endif
#ifdef USE_XED
_Bool xed_done_init __attribute__((visibility("hidden"))) = 0;
static int instr_len_xed(unsigned char *ins, unsigned char *end)
{
    if (!xed_done_init)
    {
        xed_tables_init();
        xed_done_init = 1;
    }

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd,
#if defined(__x86_64__)
			XED_MACHINE_MODE_LONG_64,
			XED_ADDRESS_WIDTH_64b
#elif defined(__i386__)
			XED_MACHINE_MODE_LEGACY_32,
			XED_ADDRESS_WIDTH_32b
#else
#error "Unrecognised x86 architecture."
#endif
    );

    xed_error_enum_t xed_error = xed_decode(&xedd, ins, end-ins);
    if (xed_error == XED_ERROR_NONE)
    {
        return xed_decoded_inst_get_length(&xedd);
    }
    else return -1;
}
#endif
#ifdef USE_X86_DECODE
static THREAD unsigned const char *limit;
static THREAD struct cpu_user_regs regs = {
};
static THREAD struct x86_emulate_ctxt ctxt = {
#if defined(__x86_64__)
	.addr_size = 64,
	.sp_size = 64
#elif defined(__i386__)
	.addr_size = 32,
	.sp_size = 32
#else
#error "Unrecognised x86 architecture."
#endif
};
static void *my_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *dpos = dest;
	const unsigned char *spos = src;
	while (n > 0)
	{
		*dpos++ = *spos++;
		--n;
	}
	return dest;
}

static int insn_fetch(
        enum x86_segment seg,
        unsigned long offset,
        void *p_data,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt)
{
	if ((unsigned const char *) offset + bytes > limit) return X86EMUL_EXCEPTION;
	my_memcpy(p_data, (void*) offset, bytes);
	return X86EMUL_OKAY;
}
static struct x86_emulate_ops ops = {
	.insn_fetch = insn_fetch
};
static int next_instr(unsigned char *pos)
{
	/* FIXME: use this instead of return value. */
	return 0;
}
struct x86_decode_ops decode_ops = {
	.next_instr = next_instr
};

static int instr_len_x86_decode(unsigned const char *ins, unsigned const char *end)
{
	limit = end;
	if (!ctxt.regs) ctxt.regs = &regs;
	ctxt.regs->rip = (uintptr_t) ins;
	int x86_decode_len = x86_decode(&ctxt, &ops, &decode_ops);
	// int x86_decode_err = (x86_decode_len > 0) ? 0 : -x86_decode_len;
	if (x86_decode_len < 1) return -1;
	return x86_decode_len;
}

typedef void saw_operand_client_cb(int /*type*/, unsigned int /*bytes*/, uint32_t */*val*/,
		unsigned long */*p_reg*/, int */*p_mem_seg*/, unsigned long */*p_mem_off*/,
		int */*p_fromreg1*/, int */*p_fromreg2*/, void */*arg*/);
static THREAD struct
{
	saw_operand_client_cb *client_cb;
	void *arg;
} active_cb_state;

int convert_one_reg(unsigned regnum)
{
#if defined(__x86_64__)
#define CASE(frag, FRAG) case (offsetof(struct cpu_user_regs, frag)): return DWARF_X86_64_ ## FRAG;
#elif defined(__i386__)
#define CASE(frag, FRAG) case (offsetof(struct cpu_user_regs, frag)): return DWARF_X86_ ## FRAG;
#else
#error "Unrecognised x86 architecture."
#endif

	switch (regnum)
	{
#if defined(__x86_64__)
		CASE(r15, R15)
		CASE(r14, R14)
		CASE(r13, R13)
		CASE(r12, R12)
		CASE(rbp, RBP)
		CASE(rbx, RBX)
		CASE(r11, R11)
		CASE(r10, R10)
		CASE(r9,  R9)
		CASE(r8,  R8)
		CASE(rax, RAX)
		CASE(rcx, RCX)
		CASE(rdx, RDX)
		CASE(rsi, RSI)
		CASE(rdi, RDI)
		CASE(rip, RIP)
#elif defined(__i386__)
		CASE(ebp, EBP)
		CASE(ebx, EBX)
		CASE(eax, EAX)
		CASE(ecx, ECX)
		CASE(edx, EDX)
		CASE(esi, ESI)
		CASE(edi, EDI)
		CASE(eip, EIP)
#else
#error "Unrecognised x86 architecture."
#endif
		case (unsigned)-1:
		default:
			return -1;
	}
#undef CASE
}
int relay_operand(operand_type_t type, unsigned int bytes,
		uint32_t *val,
		uint32_t *origval,
		unsigned long *p_reg,
		enum x86_segment *p_mem_seg,
		unsigned long *p_mem_off,
		unsigned long *p_fromreg1,
		unsigned long *p_fromreg2)
{
	/* We need to translate register numbers from x86_decode's internal numbering
	 * into DWARF register numbers. */
	int converted_reg;
	int converted_fromreg1;
	int converted_fromreg2;
	active_cb_state.client_cb(type, bytes, origval, 
		p_reg ? (converted_reg = convert_one_reg(*p_reg), &converted_reg) : NULL,
		(int*) p_mem_seg, p_mem_off, 
		p_fromreg1 ? (converted_fromreg1 = convert_one_reg(*p_fromreg1), &converted_fromreg1) : NULL,
		p_fromreg2 ? (converted_fromreg2 = convert_one_reg(*p_fromreg2), &converted_fromreg2) : NULL, 
		active_cb_state.arg);
	return 0;
}
struct x86_decode_ops operand_decode_ops = {
	.saw_operand = relay_operand
};

int enumerate_operands(unsigned const char *ins, unsigned const char *end,
	void *mcontext_as_void,
	void (*saw_operand)(int /*type*/, unsigned int /*bytes*/, uint32_t */*val*/,
		unsigned long */*p_reg*/, int */*p_mem_seg*/, unsigned long */*p_mem_off*/,
		int *p_fromreg1, int *p_fromreg2,
		void */*arg*/),
	void *arg
	)
{
	mcontext_t *mcontext = (mcontext_t *) mcontext_as_void;
	/* Call the decoder, passing our spiffy callback. 
	 * When it hears about an operand, it will call the user's
	 * callback. */
	active_cb_state.client_cb = saw_operand;
	active_cb_state.arg = arg;
	limit = end;
// NOTE: this is glibc's mcontext structure, not the kernel's
#define COPY_REG(rname, RNAME) .rname = mcontext->gregs[REG_ ## RNAME]
	struct cpu_user_regs regs = {
#if defined(__x86_64__)
		COPY_REG(r15, R15),
		COPY_REG(r14, R14),
		COPY_REG(r13, R13),
		COPY_REG(r12, R12),
		COPY_REG(rbp, RBP),
		COPY_REG(rbx, RBX),
		COPY_REG(r11, R11),
		COPY_REG(r10, R10),
		COPY_REG(r9, R9),
		COPY_REG(r8, R8),
		COPY_REG(rax, RAX),
		COPY_REG(rcx, RCX),
		COPY_REG(rdx, RDX),
		COPY_REG(rsi, RSI),
		COPY_REG(rdi, RDI),
		.rip = (uint64_t) ins,
		COPY_REG(rsp, RSP),
#elif defined(__i386__)
		COPY_REG(ebp, EBP),
		COPY_REG(ebx, EBX),
		COPY_REG(eax, EAX),
		COPY_REG(ecx, ECX),
		COPY_REG(edx, EDX),
		COPY_REG(esi, ESI),
		COPY_REG(edi, EDI),
		.eip = (uint32_t) ins,
		COPY_REG(esp, ESP),
#else
#error "Unrecognised x86 architecture."
#endif
/* Common registers */
		COPY_REG(cs, CSGSFS) & 0xff,
		COPY_REG(eflags, EFL),
		//COPY_REG(ss, SS),
		//COPY_REG(es, ES),
		//COPY_REG(ds, DS),
		.gs = (mcontext->gregs[REG_CSGSFS] & 0xff00) >> 16,
		.fs = (mcontext->gregs[REG_CSGSFS] & 0xff0000) >> 8,
	};
	struct x86_emulate_ctxt ctxt = {
#if defined(__x86_64__)
		.addr_size = 64,
		.sp_size = 64,
#elif defined(__i386__)
		.addr_size = 32,
		.sp_size = 32,
#else
#error "Unrecognised x86 architecture."
#endif
		.regs = &regs
	};
	
	int x86_decode_len = x86_decode(&ctxt, &ops, &operand_decode_ops);
	// int x86_decode_err = (x86_decode_len > 0) ? 0 : -x86_decode_len;
	if (x86_decode_len < 1) return -1;
	return 0;
}

#endif
#ifdef USE_OPDIS
#define MAX_INSN_LENGTH 16
#define OPDIS_BUF_LEN 32
#define OPDIS_MAX_OPERANDS 5 /* ? */
#define OPDIS_ASCII_SZ 64 /* ? */
#define OPDIS_MNEMONIC_SZ 12 /* ? */
#define OPDIS_OP_ASCII_SZ 8 /* ? */
static opdis_t o;
static THREAD opdis_insn_t *cur_insn;
static THREAD opdis_off_t  cur_insn_len;
static int decode_cb(const opdis_insn_buf_t in, opdis_insn_t * out,
	   const opdis_byte_t * buf, opdis_off_t offset,
	   opdis_vma_t vma, opdis_off_t length, void * arg)
{
	int ret = /* opdis_x86_att_decoder */ opdis_default_decoder(in, out, buf, offset, vma, length, NULL);
	if (ret) *((opdis_off_t *) arg) = length;
	return ret; /* i.e. always stop disassembling after a single instruction */
}
static void display_cb(const opdis_insn_t *i, void *arg) { return; }
static opdis_insn_t *get_opdis_insn(unsigned char *ins, unsigned char *end)
{
	uintptr_t len = (uintptr_t) end - (uintptr_t) ins;
	opdis_buffer_t buf = {
		.len = (len > MAX_INSN_LENGTH) ? MAX_INSN_LENGTH : len,
		.data = ins,
		.vma = (bfd_vma) ins
	};
	assert(buf.len <= MAX_INSN_LENGTH);
	if (!o)
	{
		o = opdis_init();
		/* Unbelievably, opdis_insn_t won't tell us the encoded length of the instruction. 
		 * So we have to snarf it via a custom decoder. */
#if defined(__x86_64__)
		opdis_set_arch(o, bfd_arch_i386, bfd_mach_x86_64, NULL);
#elif defined(__i386__)
		opdis_set_arch(o, bfd_arch_i386, bfd_mach_i386_i386 /* or bfd_mach_x64_32? */, NULL);
#else
#error "Unrecognised x86 architecture."
#endif
		opdis_set_display(o, display_cb, NULL);
		opdis_set_decoder(o, decode_cb, &cur_insn_len);
		// assert(o->buf);
		// assert(o->buf->string);
	}
	if (!cur_insn)
	{
		cur_insn = opdis_insn_alloc_fixed(OPDIS_ASCII_SZ, OPDIS_MNEMONIC_SZ,
			OPDIS_MAX_OPERANDS, OPDIS_OP_ASCII_SZ);
	}
	opdis_insn_clear(cur_insn);
	/* Don't let opdis see ud2 -- seems not to like it? */
	if (is_ud2(ins))
	{
		cur_insn_len = 2;
		return NULL;
	}
	/* Now do the one-instruction decode. */
	unsigned int ret = opdis_disasm_insn(o, &buf, (opdis_vma_t) ins, cur_insn);
	if (!ret) return NULL;
	if (cur_insn->status == opdis_decode_invalid) return NULL;
	if (cur_insn_len == 0)
	{
		/* ud2 shows up with a "length" of 0 in the callback. 
		 * but its size == 2. FIXME: why wasn't "size" good enough
		 * earlier, but is now? */
		cur_insn_len = cur_insn->size;
	}
	return cur_insn;
}
static int instr_len_opdis(unsigned char *ins, unsigned char *end)
{
	get_opdis_insn((unsigned char *) ins, (unsigned char *) end);
	return cur_insn_len;
}
#endif /* opdis */

static void print_hex_bytes(int fd, unsigned char *start, unsigned char *end)
{
	for (unsigned char *pos = start; pos != end; ++pos)
	{
        unsigned char high = *pos >> 4;
        unsigned char low = *pos & 0xf;

        char hex_byte[3];
        hex_byte[0] = (high > 9) ? ('a' + high - 10) : ('0' + high);
        hex_byte[1] = (low > 9) ? ('a' + low - 10) : ('0' + low);
        hex_byte[2] = (pos == end - 1) ? '\n' : ' ';
		raw_write(fd, hex_byte, 3);
	}
}

unsigned long
__attribute__((visibility("protected")))
instr_len(unsigned const char *ins, unsigned const char *end)
{
	// don't let the decoders see ud2
	if (end - ins > 1 && is_ud2(ins)) return 2;
	
	int len = 1;
	_Bool got_len = 0;
	/* Calling warnx won't work if we're trapping our libc's instructions.
     * To avoid problems, we use raw write syscalls instead. */
#define TRY_DECODER(fragment) \
	int fragment ## _len = instr_len_ ## fragment((unsigned char *)ins, (unsigned char*) end); \
	do { if (fragment ## _len > 0) \
	{ \
		if (got_len && len != fragment ## _len) \
		{ \
            write_string(#fragment " disagreed with earlier decode about" \
                "instruction length at "); \
            write_ulong((unsigned long) ins); \
            write_string("\n"); \
			print_hex_bytes(2, (unsigned char *)ins, (unsigned char*) ins + \
				(((int) fragment ## _len > len) ? (int) fragment ## _len : len)); \
		} \
		got_len = 1; \
		len = fragment ## _len; \
	} \
	else \
	{ \
		write_string(#fragment " could not decode instruction at "); \
        write_ulong((unsigned long) ins); \
        write_string("\n"); \
	} } while (0)
	
#ifdef USE_X86_DECODE
	TRY_DECODER(x86_decode);
#endif
#ifdef USE_XED
	TRY_DECODER(xed);
#endif
#ifdef USE_UDIS86
	TRY_DECODER(udis86);
#endif
#ifdef USE_OPDIS
	TRY_DECODER(opdis);
#endif
	if (!got_len) { /* we could warn here */ }
	return len;
}

int is_sysenter_instr(unsigned const char *ins, unsigned const char *end)
{
	if ((end >= ins + 2) && *ins == 0x0f && *(ins+1) == 0x34) return 2;
	return 0;
}
int is_int80_instr(unsigned const char *ins, unsigned const char *end)
{
	if ((end >= ins + 2) && *ins == 0xcd && *(ins+1) == 0x80) return 2;
	return 0;
}
int is_syscall_instr(unsigned const char *ins, unsigned const char *end)
{
	/* Using opdis for this is non-portable and slow, so we don't do it. 
	 * It's non-portable because opdis doesn't actually know give us the 
	 * mnemonic for an instruction. Instead, if you want the isolated mnemonic, 
	 * you're supposed to write your own decoder. See: 
	 * http://mkfs.github.io/content/opdis/doc/api/howtos.html#howto_app_decoder
	 * ... although there are two special decoders for x86 that do give us 
	 * mnemonics. We want to support other architectures.
	 * 
	 * opdis is also slow (lots of string manipulations). So we just use
	 * the raw byte sequences here.
	 */
	// opdis_insn_t *insn = get_opdis_insn((unsigned char *) ins);
	// if (!insn) return 0;
	// if (!(insn->status & opdis_decode_mnem)) return 0;
	// return 0 == strcmp(insn->mnemonic, "syscall")
	// 		|| 0 == strcmp(insn->mnemonic, "sysenter")
	// 		|| (0 == strcmp(insn->mnemonic, "int"
	// 			/*&& (insn->operands[0] == 0x80 || insn->operands[0] == 0x81)*/));
	if (((end >= ins + 2) && *ins == 0x0f && *(ins+1) == 0x05) /* syscall */
	 || is_sysenter_instr(ins, end) /* sysenter */
	 || is_int80_instr(ins, end))
	{
		return 2;
	}
	return 0;
}
