#include "instr.h" /* our API -- in C */
#include <assert.h>
#include <string.h>

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

#include <opdis/opdis.h>
#include <opdis/x86_decoder.h>

static opdis_t o;
static int decode_cb(const opdis_insn_buf_t in, opdis_insn_t * out,
	const opdis_byte_t * buf, opdis_off_t offset,
	opdis_vma_t vma, opdis_off_t length, void * arg);
// static decode_cb *orig_decode;

static void fini() __attribute__((destructor));
static void fini() 
{
	/* DON'T terminate us. This will free buffers that we need right up 
	 * until we do the exit() syscall. */
	// if (o) opdis_term(o);
}
#define OPDIS_BUF_LEN 32
#define OPDIS_MAX_OPERANDS 5 /* ? */
#define OPDIS_ASCII_SZ 64 /* ? */
#define OPDIS_MNEMONIC_SZ 12 /* ? */
#define OPDIS_OP_ASCII_SZ 8 /* ? */

static int decode_cb(const opdis_insn_buf_t in, opdis_insn_t * out,
	const opdis_byte_t * buf, opdis_off_t offset,
	opdis_vma_t vma, opdis_off_t length, void * arg)
{
	int ret = /* opdis_x86_att_decoder */ opdis_default_decoder(in, out, buf, offset, vma, length, NULL);
	if (ret) *((opdis_off_t *) arg) = length;
	return ret; /* i.e. always stop disassembling after a single instruction */
}

static void display_cb(const opdis_insn_t *i, void *arg)
{
	return;
}

/* static int display_cb */


static __thread opdis_insn_t *cur_insn;
static __thread opdis_off_t  cur_insn_len;

static opdis_insn_t *get_opdis_insn(unsigned char *ins, unsigned char *end)
{
	// unsigned char opdis_buf[OPDIS_BUF_LEN];
	opdis_buffer_t buf = {
		.len = end - ins,
		.data = ins,
		.vma = (bfd_vma) ins
	};
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
	/* Now do the one-instruction decode. */
	unsigned int ret = opdis_disasm_insn(o, &buf, (opdis_vma_t) ins, cur_insn);
	if (!ret) return NULL;
	if (cur_insn->status == opdis_decode_invalid) return NULL;
	assert(cur_insn_len != 0);
	return cur_insn;
}

unsigned long
__attribute__((visibility("protected")))
instr_len(unsigned const char *ins, unsigned const char *end)
{
	get_opdis_insn((unsigned char *) ins, end);
	
	return cur_insn_len;
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
