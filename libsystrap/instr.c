#include "instr.h" /* our API -- in C */
#include <assert.h>
#include <string.h>
#include <err.h>
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
/* 
#include <memory>

#include <llvm/Config/llvm-config.h>
#include <llvm/Config/config.h>
#include <llvm/Support/MemoryObject.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCDisassembler.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>

class WholeVASMemoryObject : public llvm::MemoryObject 
{
public:
	uint64_t getBase() const { return 0; }
	uint64_t getExtent() const { return (uintptr_t) -1; }
	int readByte(uint64_t addr, uint8_t *byte) const 
	{
		*byte = *(char*) addr;
		return 0;
	}
};

static WholeVASMemoryObject whole_vas;

static const llvm::MCDisassembler& disas()
{
	static bool fail = llvm::InitializeNativeTarget() || llvm::InitializeNativeTargetDisassembler();
	static std::string triple = llvm::sys::getDefaultTargetTriple();
	static std::string error;
	static const llvm::Target *target = llvm::TargetRegistry::lookupTarget(triple, error);
	static llvm::MCSubtargetInfo *sub_target
	 = target->createMCSubtargetInfo(triple, llvm::sys::getHostCPUName(), "");
	static llvm::MCRegisterInfo *reg_info
	 = target->createMCRegInfo(triple);
	static llvm::MCAsmInfo *asm_info
	 = reg_info ? target->createMCAsmInfo(*reg_info, triple) : nullptr;
	static llvm::MCContext *context 
	 = (asm_info && reg_info) ? new llvm::MCContext(asm_info, reg_info, 0) : nullptr;
	static llvm::MCDisassembler *disassembler
	 = asm_info ? target->createMCDisassembler(*sub_target, *context) : nullptr;
	
	assert(!fail);
	assert(disassembler);
	return *disassembler;
}

unsigned long
__attribute__((visibility("protected")))
instr_len(unsigned char *ins)
{
	llvm::MCInst i;
	uint64_t sz;
	disas().getInstruction(i, sz, whole_vas, (uintptr_t) ins, llvm::nulls(), llvm::nulls());
	return sz;
}

*/
static _Bool is_ud2(const unsigned char *ins)
{
	return ins[0] == 0x0f && ins[1] == 0x0b;
}
/* We have three different ways of calculating the instruction length: 
 * x86-decode (preferred), libudis86, and opdis (slowest).
 * We want to allow configuration to select any one or more of these.
 * If none is defined, we select one or two based on NDEBUG. */

#if !defined(USE_X86_DECODE) && !defined(USE_UDIS86) && !defined(USE_OPDIS)
#ifdef NDEBUG
#define USE_X86_DECODE
#else
#define USE_X86_DECODE
#define USE_OPDIS
#endif
#endif

#ifdef USE_UDIS86
static ud_t ud_obj;
static void init_udis86() __attribute__((constructor));
static void init_udis86()
{
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64); // FIXME: sysdep
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
#ifdef USE_X86_DECODE
static __thread unsigned const char *limit;
static __thread struct cpu_user_regs regs = {
};
static __thread struct x86_emulate_ctxt ctxt = {
	.addr_size = 64,
	.sp_size = 64
};
static int insn_fetch(
        enum x86_segment seg,
        unsigned long offset,
        void *p_data,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt)
{
	if ((unsigned const char *) offset + bytes > limit) return X86EMUL_EXCEPTION;
	memcpy(p_data, (void*) offset, bytes);
	return X86EMUL_OKAY;
}
static struct x86_emulate_ops ops = {
	.insn_fetch = insn_fetch
};
static int instr_len_x86_decode(unsigned const char *ins, unsigned const char *end)
{
	limit = end;
	if (!ctxt.regs) ctxt.regs = &regs;
	ctxt.regs->rip = (uintptr_t) ins;
	int x86_decode_len = x86_decode(&ctxt, &ops);
	// int x86_decode_err = (x86_decode_len > 0) ? 0 : -x86_decode_len;
	if (x86_decode_len < 1) return -1;
	return x86_decode_len;
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
static __thread opdis_insn_t *cur_insn;
static __thread opdis_off_t  cur_insn_len;
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
		opdis_set_arch(o, bfd_arch_i386, bfd_mach_x86_64, NULL);
		opdis_set_display(o, display_cb, NULL);
		opdis_set_decoder(o, decode_cb, &cur_insn_len);
		assert(o->buf);
		assert(o->buf->string);
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

unsigned long
__attribute__((visibility("protected")))
instr_len(unsigned const char *ins, unsigned const char *end)
{
	// don't let the decoders see ud2
	if (end - ins > 1 && is_ud2(ins)) return 2;
	
	int len = 1;
	_Bool got_len = 0;
	
#define TRY_DECODER(fragment) \
	int fragment ## _len = instr_len_ ## fragment((unsigned char *)ins, (unsigned char*) end); \
	do { if (fragment ## _len > 0) \
	{ \
		if (got_len && len != fragment ## _len) \
		{ \
			warnx(#fragment " disagreed with earlier decode about instruction length" \
				" at %p (gave %d, vs %d)", \
				ins, (int) fragment ## _len, len); \
		} \
		got_len = 1; \
		len = fragment ## _len; \
	} \
	else \
	{ \
		warnx(#fragment " could not decode instruction at %p", ins); \
	} } while (0)
	
#ifdef USE_X86_DECODE
	TRY_DECODER(x86_decode);
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
	
	/* syscall */
	if ((end >= ins + 2) && *ins == 0x0f && *(ins+1) == 0x05) return 2;
	/* sysenter */
	if ((end >= ins + 2) && *ins == 0x0f && *(ins+1) == 0x34) return 2;
	/* int 80 */
	if ((end >= ins + 2) && *ins == 0xcd && *(ins+1) == 0x80) return 2;
	
	return 0;
}
