///usr/bin/[ "$0".bin -nt "$0" ] || \
  cc -I"$(dirname "$0")"/../contrib/xed/build-`uname -m`/include \
     -I"$(dirname "$0")"/../contrib/librunt/include \
     -DDONALD_LOAD_C=\""$(dirname "$0")"/../contrib/donald/src/load.c\" \
     -Wall ${CFLAGS:--Og} -g ${LDFLAGS} "$0" -o "$0".bin ${LDLIBS} \
     -L"$(dirname "$0")"/../contrib/xed/build-`uname -m`/lib -lxed <<EOSHELL || exit 1; exec "$0".bin "$@"; exit 42
#ifdef EOSHELL
$(
    # The top half of this file is a shell script.
    # The bottom half is a C program.
    # The output of the shell script will be available to the C preprocessor when compiling
    # the C program.
    # The hash-bang line above arranges that executing this file will compile if necessary,
    # then (always) run the C code.

    # Overall, this pattern fulfils the same purpoes as "configure && make && ./a.out"
    # but packaged as a single file that one can chmod +x and then execute directly.

    # This is pretty much arbitrary shell code, but the preprocessor will warn (harmlessly)
    # when our lines do not have properly matched single or double quotes. Some shell
    # idioms, like multi-line quoted strings, break this expectation and provoke a warning.
    # Also, we must not begin any line with [[:blank:]]*#[[:blank:]]*(if|else|elif|endif).

    # The output of this shell code is available to the C compiler by #including "/dev/stdin"
    # i.e. if it outputs something it should output C code.

    # To source any shell functions for testing, a good approach is:
    # source <( sed -n '/^\$($/,/STOP\ SOURCING/ p' ccwrap.c | tail -n+2 | head -n-1 )

    # STOP SOURCING HERE <-- leave this in place for the 'source' recipe (in comment above)
    # (I used to make it match ')' by itself, but that will also source any non-function
    # imperative code in the script... put such code below this comment.)
)
#else
#define EOSHELL
#endif
EOSHELL
// From here on we are in plain C and will never be run by the shell.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <err.h>
#include <assert.h>
#include <string.h> /* for strcmp() */
#include <linux/auxvec.h>  /* For AT_xxx definitions */
#include <xed/xed-interface.h>
#include DONALD_LOAD_C /* snarf donald's memory-mapping routines  */
#include "felf.h"

#ifndef MAX
#define MAX(a, b) ((a)>(b)?(a):(b))
#endif

struct mapping
{
	void *addr;
	off_t offset;
	size_t length;
} *mappings;
unsigned mappings_n;
struct mapping *mappings_limit;
#define VECTOR_APPEND(x, ent) \
	do { \
	    if (!x || x + x ## _n == x ## _limit) { \
		  /* grow */ \
		  size_t requested_n = (!x) ? 16 : 2 * (x ## _limit - x); \
		  x = realloc(x, requested_n * sizeof (*x)); \
		  if (!x) errx(EXIT_FAILURE, "reallocating %s", #x); \
		  x ## _limit = x + requested_n; \
		} \
		x[x ## _n++] = ent; \
	} while (0)

Elf64_Shdr **executable_shdrs;
unsigned executable_shdrs_n;
Elf64_Shdr **executable_shdrs_limit;

int fd;
ElfW(Phdr) phdrs[16];
unsigned n_phdrs;

Elf64_Sym **range_symbols;
unsigned range_symbols_n;
Elf64_Sym **range_symbols_limit;

Elf64_Sym **point_symbols;
unsigned point_symbols_n;
Elf64_Sym **point_symbols_limit;

Elf64_Sym *dynsym;
Elf64_Sym *dynsym_end;
Elf64_Sym *symtab;
Elf64_Sym *symtab_end;
unsigned char *strtab;
unsigned char *dynstr;
unsigned char *shstrtab;

unsigned long page_size;
#define ROUND_DOWN(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * ((uintptr_t) (p) / (align))))
#define ROUND_UP(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * (1 + ((uintptr_t) (p) / (align)))))

int compare_symbols(const void *pp_sym1_as_void, const void *pp_sym2_as_void)
{
	const Elf64_Sym *const *pp_sym1 = pp_sym1_as_void;
	const Elf64_Sym *const *pp_sym2 = pp_sym2_as_void;
	// compare firstly by value (increasing), secondly by size (increasing)
	if ( (*pp_sym1)->st_value != (*pp_sym2)->st_value ) return (long)(*pp_sym1)->st_value - (long)(*pp_sym2)->st_value;
	return (long)(*pp_sym1)->st_size - (long)(*pp_sym2)->st_size;
}
int compare_shdrs(const void *pp_shdr1_as_void, const void *pp_shdr2_as_void)
{
	const Elf64_Shdr *const *pp_shdr1 = pp_shdr1_as_void;
	const Elf64_Shdr *const *pp_shdr2 = pp_shdr2_as_void;
	return (long)(*pp_shdr1)->sh_addr - (long)(*pp_shdr2)->sh_addr;
}

static void *get_or_map_file_range(off_t offset, size_t length, void *ignored)
{
	/* Now we can try making a fresh mapping. But maybe an existing one will do. */
	unsigned midx = 0;
	for (; midx < mappings_n; ++midx)
	{
		struct mapping *m = mappings + midx;
		if ((unsigned long) m->offset <= (unsigned long) offset
			&& (unsigned long) m->offset + m->length >= (unsigned long) offset + length)
		{
			return m->addr + (offset - m->offset);
		}
	}
	off_t rounded_offset = ROUND_DOWN(offset, page_size);
	length += offset - rounded_offset;
	length = ROUND_UP(length, page_size);
	void *ret = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, rounded_offset);
	if (ret == MAP_FAILED) return NULL;
	VECTOR_APPEND(mappings,
		((struct mapping) { .addr = ret, .offset = rounded_offset, .length = length })
	);
	return (char*) ret + (offset - rounded_offset);
}

static long visit(unsigned long kind, void *data, size_t datasz, Elf64_Off fileoff, Elf64_Addr vaddr,
	Elf64_Shdr *shdr_if_applicable, void *auxdata_if_applicable, void *arg);

static void print_decoded(xed_decoded_inst_t *p_xedd, Elf64_Addr vaddr, unsigned char *mapped_addr, unsigned instr_len);
static _Bool print;
static _Bool print_extra;
static Elf64_Sym **current_range_sympp = NULL;
static Elf64_Sym **current_point_sympp = NULL;

struct interesting
{
	/* the order of the enum will give us the sort order,,, we want incoming branch
	 * to come first, writeback to come last */
	enum { INCOMING_BRANCH, READ_RAX, SYSCALL, WRITE_RAX, WRITE_RAX_IMMEDIATE } kind;
	Elf64_Addr vaddr;
	unsigned char *mapped_addr;
} *interesting;
unsigned interesting_n;
struct interesting *interesting_limit;

int compare_interesting(const void *ip1_as_void, const void *ip2_as_void)
{
	/* we want to sort in vaddr order, and incoming branches to come first. */
	const struct interesting *ip1 = ip1_as_void;
	const struct interesting *ip2 = ip2_as_void;
	if (ip1->vaddr == ip2->vaddr) return (int) ip1->kind - (int) ip2->kind;
	return ip1->vaddr - ip2->vaddr;
}

int main(int argc, char **argv)
{
	if (argc < 2) errx(EXIT_FAILURE, "need a file to load");
	char *var = getenv("SYSTRAP_DEBUG_LEVEL");
	if (var && atoi(var) > 0) print = 1;
	if (var && atoi(var) > 1) print_extra = 1;
	fd = open(argv[1], O_RDONLY);
	if (fd == -1) err(EXIT_FAILURE, "could not open `%s'", argv[1]);
	page_size = 4096; //(loadee.ehdr.e_machine == EM_386) ? 4096 :
	            //(loadee.ehdr.e_machine == EM_X86_64) ? 4096 : (errx(EXIT_FAILURE, "unrecognised ELF machine"), 0);
	struct loadee_info loadee = load_from_fd(fd, argv[1], 0, phdrs, &n_phdrs);
	if (!loadee.base_addr) err(EXIT_FAILURE, "could not load `%s'", argv[1]);
	/* Our initial mappings mirror the LOAD phdrs. Populate our 'mappings' array
	 * with this information, i.e. the stuff we just loaded. */
	Elf64_Phdr phdrs[loadee.ehdr.e_phnum];
	for (unsigned i = 0; i < loadee.ehdr.e_phnum; ++i)
	{
		ssize_t nread = read(fd, &phdrs[i], sizeof (Elf64_Phdr));
		if (nread != sizeof (Elf64_Phdr)) err(EXIT_FAILURE, "reading phdrs");
		if (phdrs[i].p_type == PT_LOAD) VECTOR_APPEND(mappings, ((struct mapping) {
				.addr = (void*)((uintptr_t) loadee.base_addr + phdrs[i].p_vaddr),
				.offset = phdrs[i].p_offset,
				.length = phdrs[i].p_filesz
	    }));
	}

	/* Do some ELF visiting. We want to collect
	 * - the vaddr ranges of executable text sections
	 * - any other ranges not in a section but in a PF_X phdr?
	 * - symbols (range and point symbols) */
	long visit_ret = visit_elf_64((unsigned long) -1, visit, NULL, get_or_map_file_range, NULL);
	if (visit_ret < 0) err(EXIT_FAILURE, "visit_elf_64() returned %ld", visit_ret);
	qsort(range_symbols, range_symbols_n, sizeof (Elf64_Sym *), compare_symbols);
	qsort(point_symbols, point_symbols_n, sizeof (Elf64_Sym *), compare_symbols);
	qsort(executable_shdrs, executable_shdrs_n, sizeof (Elf64_Shdr *), compare_shdrs);

	xed_tables_init();
	xed_decoded_inst_t xedd = (struct xed_decoded_inst_s) { ._decoded_length = 0 };
	xed_decoded_inst_set_mode(&xedd,
		(loadee.ehdr.e_machine == EM_386) ? XED_MACHINE_MODE_LEGACY_32 :
		(loadee.ehdr.e_machine == EM_X86_64) ? XED_MACHINE_MODE_LONG_64 : (err(EXIT_FAILURE, "unsupported ELF machine"), 0),
		(loadee.ehdr.e_machine == EM_386) ? XED_ADDRESS_WIDTH_32b :
		(loadee.ehdr.e_machine == EM_X86_64) ? XED_ADDRESS_WIDTH_64b : (err(EXIT_FAILURE, "unsupported ELF machine"), 0)
	);
	xed_decoded_inst_t xedd_init = xedd;
	
	/* Now we have code shdrs, symbols... iterate XED over the instructions in address
	 * order. Keep track of our current symbol(s). */
	for (unsigned i = 0; i < executable_shdrs_n; ++i)
	{
		Elf64_Shdr *shdr = executable_shdrs[i];
		if (print) printf("Disassembly of section '%s'\n",
				shstrtab ? (char*) &shstrtab[shdr->sh_name] : "(no name)");
		unsigned char *addr_mapped = get_or_map_file_range(
			shdr->sh_offset, shdr->sh_size, NULL);
		unsigned char *addr_mapped_end = addr_mapped + shdr->sh_size;
		unsigned instr_len;
		Elf64_Addr vaddr;
		for (unsigned char *i_addr = addr_mapped; i_addr < addr_mapped_end; i_addr += instr_len)
		{
			xedd = xedd_init;
			vaddr = i_addr - addr_mapped + shdr->sh_addr;
			xed_error_enum_t xed_error = xed_decode(&xedd, i_addr, addr_mapped_end - i_addr);
			if (xed_error != XED_ERROR_NONE)
			{
				warnx("could not decode at vaddr %lx (%s); will retry at next byte",
					(long)(i_addr - addr_mapped + shdr->sh_addr),
					xed_error_enum_t2str(xed_error));
				instr_len = 1;
				continue;
			}
			instr_len = xed_decoded_inst_get_length(&xedd);

			// advance symbol pointers
			if (!current_range_sympp) current_range_sympp = range_symbols;
			while (current_range_sympp != range_symbols + range_symbols_n && !(
				vaddr >= (*current_range_sympp)->st_value &&
				vaddr <  (*current_range_sympp)->st_value + (*current_range_sympp)->st_size)) ++current_range_sympp;
			if (!current_point_sympp) current_point_sympp = point_symbols;
			while (current_point_sympp != point_symbols + point_symbols_n && !(
				vaddr >= (*current_point_sympp)->st_value &&
				(current_point_sympp + 1 == point_symbols + point_symbols_n || 
					(*current_point_sympp + 1)->st_value > vaddr))) ++current_point_sympp;
			if (print) print_decoded(&xedd, vaddr, i_addr, instr_len);

			/* Next we want incoming branch edges. Assume a branch is incoming at an instruction
			 * that is
			 * - target of a direct barnch
			 * - a return address, i.e. the next instruction following a call or syscall
			 * - referenced by a %rip-relative memory operand (e.g. in an lea, but not only that)
			 * - at offset 0 from a function symbol (whether range or point)
			 *
			 * Let's do one big linear scan for
			 * - all the above (branch targets, return addrs, %rip-rel memory operands, 0-from-sym)
			 * - reads of %rax, %eax, %ax, %ah, %al
			 * - writes to %rax, %eax, %ax, %ah, %al
			 * - system calls
			 *
			 * Append to a big vector, then sort the vector by vaddr and traverse backwards.
			 * Incoming branches sort before any same-address record of interest.
			 *
			 * If we can search backwards from any system call, and find
			 * its write to %rax
			 * before we find an incoming branch of read of %rax
			 * then we have a rebindable syscall.
			 * (A referent is relocatable iff all references to it are rebindable.)
			 *
			 * IDEA: flag privileged instructions if seen in disassembly
			 */
			xed_int64_t disp;
			xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
			xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xedd);
#define INTERESTING_VECTOR_APPEND(toks) do { \
	if (print) printf("INTERESTING HERE: vaddr %lx, kind %d\n", (long)((toks).vaddr), (int)((toks).kind)); \
	VECTOR_APPEND(interesting, toks); } while(0)

			if (/*IS_DIRECT_BRANCH(&xedd)*/ 0 != (disp = xed_decoded_inst_get_branch_displacement(&xedd)))
			{
				// this includes calls!
				// add the branch target
				INTERESTING_VECTOR_APPEND(((struct interesting) {
					.kind = INCOMING_BRANCH,
					.vaddr = vaddr + instr_len + disp,
					.mapped_addr = i_addr + instr_len + disp
				}));
				if (/*IS_CALL(&xedd)*/ iclass == XED_ICLASS_CALL_NEAR
						|| iclass == XED_ICLASS_CALL_FAR)
				{
					// for calls we additionally add the return address as an incoming edge
					INTERESTING_VECTOR_APPEND(((struct interesting) {
						.kind = INCOMING_BRANCH,
						.vaddr = vaddr + instr_len,
						.mapped_addr = i_addr + instr_len
					}));
				}
			}
			
			if (/*IS_SYSCALL(&xedd)*/category == XED_CATEGORY_SYSCALL
				|| (category == XED_CATEGORY_INTERRUPT && (*i_addr != 0xcc)))
			{
				INTERESTING_VECTOR_APPEND(((struct interesting) {
					.kind = SYSCALL,
					.vaddr = vaddr,
					.mapped_addr = i_addr
				}));
				INTERESTING_VECTOR_APPEND(((struct interesting) {
					.kind = INCOMING_BRANCH,
					.vaddr = vaddr + instr_len,
					.mapped_addr = i_addr + instr_len
				}));
			}
			if (/*HAS_MEMOP_WITH_RIP_BASE(&xedd)*/ 1 <= xed_decoded_inst_number_of_memory_operands(&xedd)
				&& 1 <= xed_decoded_inst_get_scale(&xedd, 0)  // and not indexed/scaled
				&& XED_REG_INVALID == xed_decoded_inst_get_index_reg(&xedd, 0)
				&& XED_REG_RIP == xed_decoded_inst_get_base_reg(&xedd, 0) )
			{
				long disp = xed_decoded_inst_get_memory_displacement(&xedd, 0);
				INTERESTING_VECTOR_APPEND(((struct interesting) {
					.kind = INCOMING_BRANCH,
					.vaddr = vaddr + instr_len + disp,
					.mapped_addr = i_addr + instr_len + disp
				}));
			}
			// FIXME: do the second-memop case
			unsigned n_ops = xed_decoded_inst_noperands(&xedd);
			for (unsigned i_op = 0; i_op < n_ops; ++i_op)
			{
				xed_operand_t const *op = xed_inst_operand(xed_decoded_inst_inst(&xedd), i_op);
				xed_operand_enum_t name = xed_operand_name(op);
				xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, name);
				
				if (!(reg == XED_REG_RAX
						|| reg == XED_REG_EAX
						|| reg == XED_REG_AX
						|| reg == XED_REG_AL
						|| reg == XED_REG_AH)) continue;
				if (/*WRITES_RAX(&xedd)*/ 
						xed_operand_written(op))
				{
					if (XED_ICLASS_MOV == xed_decoded_inst_get_iclass(&xedd)
						&& 0 != xed_decoded_inst_get_immediate_width(&xedd))
					{
						INTERESTING_VECTOR_APPEND(((struct interesting) {
							.kind = WRITE_RAX_IMMEDIATE,
							.vaddr = vaddr,
							.mapped_addr = i_addr
						}));
					}
					else
					{
						INTERESTING_VECTOR_APPEND(((struct interesting) {
							.kind = WRITE_RAX,
							.vaddr = vaddr,
							.mapped_addr = i_addr
						}));
					}
				}
				if (xed_operand_read(op)) // READS_RAX
				{
					INTERESTING_VECTOR_APPEND(((struct interesting) {
						.kind = READ_RAX,
						.vaddr = vaddr,
						.mapped_addr = i_addr
					}));
				}
			} // end for operand
		} // end for ip
		
		/* scan for symbols falling within htis section */
		for (unsigned j = 0; j < range_symbols_n; ++j)
		{
			if (range_symbols[j]->st_value >= shdr->sh_addr &&
					range_symbols[j]->st_value < shdr->sh_addr + shdr->sh_size)
			{
				VECTOR_APPEND(interesting, ((struct interesting) {
								.kind = INCOMING_BRANCH,
								.vaddr = range_symbols[j]->st_value,
								.mapped_addr = addr_mapped - shdr->sh_addr
									 + range_symbols[j]->st_value 
							}));
			}
		}
		for (unsigned j = 0; j < point_symbols_n; ++j)
		{
			if (point_symbols[j]->st_value >= shdr->sh_addr &&
					point_symbols[j]->st_value < shdr->sh_addr + shdr->sh_size)
			{
				VECTOR_APPEND(interesting, ((struct interesting) {
								.kind = INCOMING_BRANCH,
								.vaddr = point_symbols[j]->st_value,
								.mapped_addr = addr_mapped - shdr->sh_addr
									 + point_symbols[j]->st_value 
							}));
			}
		}
	} // end for section
	Elf64_Shdr *highest_text_shdr = (executable_shdrs_n > 0)
		 ? executable_shdrs[executable_shdrs_n - 1] : NULL;
	Elf64_Addr text_vaddr_limit = highest_text_shdr
			? highest_text_shdr->sh_addr + highest_text_shdr->sh_size
			: 0;
	/* Now sort the interesting stuff */
	qsort(interesting, interesting_n, sizeof (struct interesting), compare_interesting);
	/* Now walk backwards through the interesting stuff. */
	struct interesting *seen_syscall = NULL;
	struct interesting *seen_write_rax_immediate = NULL;
	int32_t pun_value;
	for (int i = interesting_n - 1; i >= 0; --i)
	{
		struct interesting *it = &interesting[i];
		switch (it->kind)
		{
			case SYSCALL:
				seen_syscall = it;
				break;
			case INCOMING_BRANCH:
				if (!seen_syscall) continue;
				goto clear_syscall_and_report;
			case READ_RAX:
				if (!seen_syscall) continue;
				goto clear_syscall_and_report;
			case WRITE_RAX:
				// writing %rax with a non-immediate value is no good to us
				if (!seen_syscall) continue;
				goto clear_syscall_and_report;
			case WRITE_RAX_IMMEDIATE:
				if (!seen_syscall) continue;
				seen_write_rax_immediate = it;
				/* if we got here, we've searched backwards from a syscall and
				 * not seen any leaks of %rax or writes of %rax or incoming branches
				 * between that syscall and here, in reverse program counter order.
				 * So */
				goto clear_syscall_and_report;
			clear_syscall_and_report:
				memcpy(&pun_value, seen_syscall->mapped_addr + 2, 4);
				printf("syscall at vaddr %lx, pun value %d == %08x",
					(long) seen_syscall->vaddr,
					pun_value,
					pun_value);
				printf(", rax'able? %s", (pun_value > 0) ? "yes" : "no");
				long branch_reference_vaddr = seen_syscall->vaddr + 2; // HACK
				printf(", rip'able? %s",
					((long) branch_reference_vaddr + pun_value < 0) ? "likely yes"
					: (pun_value > ((long) text_vaddr_limit - (long) branch_reference_vaddr)) ?
					/* either YES or POSSIBLY */
					( 
						(pun_value - ((long) text_vaddr_limit - (long) branch_reference_vaddr) > 1048576) ? "likely yes" : "possibly no"
					)
					: "no"
				);
				if (0l <= (long) branch_reference_vaddr + pun_value
					&& text_vaddr_limit >= branch_reference_vaddr + pun_value + 6 /* far call operand length*/)
				{
					printf(", LDT punnable? bytes are %02x %02x %02x %02x %02x %02x, conclusion %s",
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 0),
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 1),
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 2),
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 3),
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 4),
						(unsigned)*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 5),
						((*((unsigned char*) seen_syscall->mapped_addr + 2 + pun_value + 4) & 7) == 7) ? "LDT-punnable" : "LDT-unpunnable");
				}
				/* other techniques are needed for low-magnitude negative puns that
				 * fail LDT punning, rip punning and rax punning. Try a piggy-backing technique using
				 * "e8-patch": in the 256-byte windows available via a 5-byte e8 pun (*or* a 2-byte short jump? hmm, can't return?),
				 * is there (1) some unreachable nop space, (2) another patched syscall?
				 * use (1) directly; for (2) jump to it and use stack to disambiguate (FIXME: details)
				 * OTHER TECHNIQUES here presumably? i.e. the above don't seem likely very fruitful.
				 *
				 * IDEA: "known register values" -- pun against other regs if knowable?
				 *       will many syscall sites pass constant args? not in libc, but maybe in open-coded cases
				 *  ^^ yes, worth investigating
				 * PROBLEM of executable rodata: remove execute permission from the overlap,
				 *    on a trap, can copy the code elsewhere and run that, if it's PIC
				 *      (CHECK safety of this! need to patch references to text/rodata outside this range?
				 *       obvious problem: outgoing direct references to *writable* data, but they go via the GOT?)
				 * PROBLEM of jump tables in text:
				 *   -- they are rare
				 *   -- simple static analysis looking for the jmps? WHAT would this need to look for?
				 *         short answer: a memory-indirect register-indexed jump with an offset suspiciously like a text vaddr
				 *   -- MPK-remove execute permission from those detected? no, page is too coarse
				 *   -- MPK-remove read permission from any failed decode +/- one page
				 *   -- MPK-remove read permission from all text (except where LDT-punning)?
				 *          We move the dependency on MPK support away from the common case of
				 *          null-pointer checking, to the rare case of in-text jump tables
				 * PROBLEM of programs switching to 32-bit mode
				 *   -- they can only do this if they have an lcall or ljmp (or lret)
				 *   -- we can scan for this? what about breaches of control-flow integrity?
				 * PROBLEM of hypocrisy: we are using punning techniques while assuming
				 *   the off-the-shelf programs don't do this? need to treat this carefully
				 *   and support as many wacky things as possible
				 * 
				 * HOW NOT to break debugging:
				 *      (chain loader stuff)
				 *      pun-aware disassembler: inject additional branch targets and detect overlap (pun)
				 *      unwind information in trampolines etc
				 *      strace -i  is an interesting case... needs to unwind
				 *
				 * INSANE idea: 'lret' punning -- is this useful?
				 * e.g stack addresses often have 7 or f in the sixth byte!
				 * obvious issue is that the lret does not save where it came from.
				 * If rbp is a bona fide frame pointer, we can get the return address.
				 * So if there is only one syscall in the entire call tree
				 * (that is statically knowable) it might make sense to do.
				 */
				printf(", %s",
					seen_write_rax_immediate ? "rebindable" : "not rebindable"
				);
				if (seen_write_rax_immediate) printf(" by write at %lx", seen_write_rax_immediate->vaddr);
				printf("\n");
				seen_syscall = NULL;
				seen_write_rax_immediate = NULL;
		}
		if (i == 0 && seen_syscall) goto clear_syscall_and_report;
	}
}

static void print_decoded(xed_decoded_inst_t *p_xedd, Elf64_Addr vaddr, unsigned char *mapped_addr, unsigned instr_len)
{
	/* we can use xedd to figure out what instruction this is... does it branch?
	 * which registers does it read or write?
	 * Let's just print what we can get out of XED --
	 * address, instruction mnenonic, disassembly if it will, category, operands
	 *
	 * OK, having reviewed, let's confine our attention to the following:
	 *
	 * - N memory operands        (recurse down these separately)
	 * - immediate                (ignore second immediate)
	 * - branch displacement
	 * - register0.. until INVALID
	 * ... AH, we can use xed_inst_* to enumerate operands sensibly after all
	 *
	 * One thing remaining: can we find out whether a register is written to?
	 * That is quite semantic, and xed is quite syntactic. Use gdb / 'rw_' field?
	 * Maybe the 'iform' has this information? AHA, got it in xed_operand_{read,written}
	 *
	 */
	#define BUFLEN  1000
	char buffer[BUFLEN];
	bzero(buffer, BUFLEN);
	if (!xed_format_context(XED_SYNTAX_ATT, p_xedd, buffer, BUFLEN, 0, 0, 0))
	{ err(EXIT_FAILURE, "disassembling"); }
#define HAVE_CURRENT_RANGE_SYM (current_range_sympp && current_range_sympp != range_symbols + range_symbols_n)
#define HAVE_CURRENT_POINT_SYM (current_point_sympp && current_point_sympp != point_symbols + point_symbols_n)
#define STRTAB_FOR_SYM(sym) \
(((sym) >= dynsym && (sym) < dynsym_end) ? dynstr : \
(((sym) >= symtab && (sym) < symtab_end) ? strtab : NULL))
	printf("%8lx <%s+%4lx> (len %-2d) %-28s", vaddr,
		(HAVE_CURRENT_RANGE_SYM && (*current_range_sympp)->st_name)
			? (char*) &STRTAB_FOR_SYM(*current_range_sympp)[(*current_range_sympp)->st_name]
			: (HAVE_CURRENT_POINT_SYM && (*current_point_sympp)->st_name)
				? (char*) &STRTAB_FOR_SYM(*current_point_sympp)[(*current_point_sympp)->st_name]
				: "no symbol",
		HAVE_CURRENT_RANGE_SYM ? (long)(
			vaddr - (*current_range_sympp)->st_value
		) : HAVE_CURRENT_POINT_SYM ? (long)(
			vaddr - (*current_point_sympp)->st_value
		) : (long)0,
		(int) instr_len,
		buffer);
		if (print_extra) printf("iclass %s, iform %s, %d operands (inst: %d) of which %d memops, immediate width %ld bits, second immediate %ld, output reg %ld (%s), reg %ld (%s), reg0 %ld (%s), reg1 %ld (%s), reg2 %ld (%s) brdisp %ld",
			xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(p_xedd)),
			xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(p_xedd)),
			(int) xed_decoded_inst_noperands(p_xedd),
			(int) xed_inst_noperands(xed_decoded_inst_inst(p_xedd)),
			(int) xed_decoded_inst_number_of_memory_operands(p_xedd),
			// number of immediates?
			(long) xed_decoded_inst_get_immediate_width_bits(p_xedd),
			(long) xed_decoded_inst_get_second_immediate(p_xedd),
			// output register?
			(long) xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_OUTREG),
			xed_reg_enum_t2str(xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_OUTREG)),
			(long) xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG),
			xed_reg_enum_t2str(xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG)),
			(long) xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG0),
			xed_reg_enum_t2str(xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG0)),
			(long) xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG1),
			xed_reg_enum_t2str(xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG1)),
			(long) xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG2),
			xed_reg_enum_t2str(xed_decoded_inst_get_reg(p_xedd, XED_OPERAND_REG2)),
			(long) xed_decoded_inst_get_branch_displacement(p_xedd)
		);
	char buf[100];
	bzero(buf, sizeof buf);
	//xed_operand_values_dump(xed_decoded_inst_operands(&xedd), buf, sizeof buf);
	if (print_extra)
	{
		xed_operand_values_print_short(xed_decoded_inst_operands(p_xedd), buf, sizeof buf);
		printf(" (%s)", buf);
	}
	printf(" [");
	for (unsigned i = 0; i < xed_decoded_inst_noperands(p_xedd); ++i)
	{
		if (i != 0) printf(", ");
		/* for now, just print something for each operand.
		 * - which register, if any
		 * - read or written */
		xed_operand_t const *op = xed_inst_operand(xed_decoded_inst_inst(p_xedd), i);
		xed_operand_enum_t name = xed_operand_name(op);
		xed_reg_enum_t reg = xed_decoded_inst_get_reg(p_xedd, name);
		printf("%s(%s)", xed_operand_enum_t2str(name), xed_reg_enum_t2str(reg));
		if (xed_operand_read_and_written(op)) printf(":rw");
		else if (xed_operand_read(op)) printf(":r");
		else if (xed_operand_written(op)) printf(":w");

	}
	printf("]\n");

}

static long visit(unsigned long kind, void *data, size_t datasz, Elf64_Off fileoff, Elf64_Addr vaddr,
	Elf64_Shdr *maybe_shdr, void *auxdata, void *ignored)
{
	switch (kind)
	{
		case ELF_VISIT_SHDRS:
			/* snarf any executable shdrs */
			for (unsigned i = 0; i < datasz / ((Elf64_Ehdr *) auxdata)->e_shentsize; ++i)
			{
				Elf64_Shdr *shdr = (void*)((char*) data + i * ((Elf64_Ehdr *) auxdata)->e_shentsize);
				if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags & SHF_EXECINSTR)
				{
					/* collect the section header; we will sort it later */
					VECTOR_APPEND(executable_shdrs, shdr);
				}
			}
			if (maybe_shdr) shstrtab = get_or_map_file_range(maybe_shdr->sh_offset, maybe_shdr->sh_size, NULL);
			break;
		case ELF_VISIT_DYNSYM: dynsym = data; dynsym_end = (void*)((char*)data + datasz); dynstr = auxdata; goto common_symtab;
		case ELF_VISIT_SYMTAB: symtab = data; symtab_end = (void*)((char*)data + datasz); strtab = auxdata; goto common_symtab;
		common_symtab:
			/* collect the symbol data; we will sort it later */
			for (unsigned i = 0; i < maybe_shdr->sh_size / maybe_shdr->sh_entsize; ++i)
			{
				Elf64_Sym *sym = (void*)((char*) data + i * maybe_shdr->sh_entsize);
				if (sym->st_shndx != SHN_UNDEF)
				{
					if (sym->st_size) {
						VECTOR_APPEND(range_symbols, sym);
					} else {
						VECTOR_APPEND(point_symbols, sym);
					}
				}
			}
			break;
		default:
			break;
	}
	return 0;
}

#if 0

xed_uint_t xed_decoded_inst_avx512_dest_elements 	( 	const xed_decoded_inst_t *  	p	) 	
Returns the maximum number elements processed for an AVX512 vector instruction.
Scalars report 1 element.
		
xed_bool_t xed_decoded_inst_conditionally_writes_registers 	( 	const xed_decoded_inst_t *  	p	) 	
		
xed_uint32_t xed_decoded_inst_get_attribute 	( 	const xed_decoded_inst_t *  	p,
		xed_attribute_enum_t  	attr 
Returns 1 if the attribute is defined for this instruction.

xed_attributes_t xed_decoded_inst_get_attributes 	( 	const xed_decoded_inst_t *  	p	) 	
Returns the attribute bitvector

xed_reg_enum_t xed_decoded_inst_get_base_reg 	( 	const xed_decoded_inst_t *  	p,

xed_int64_t xed_decoded_inst_get_branch_displacement 	( 	const xed_decoded_inst_t *  	p	) 	

xed_uint_t xed_decoded_inst_get_branch_displacement_width 	( 	const xed_decoded_inst_t *  	p	) 	
Result in BYTES

xed_uint_t xed_decoded_inst_get_branch_displacement_width_bits 	( 	const xed_decoded_inst_t *  	p	) 	
Result in BITS

static XED_INLINE xed_category_enum_t xed_decoded_inst_get_category 	( 	const xed_decoded_inst_t *  	p	) 	
Return the instruction xed_category_enum_t enumeration

xed_bool_t xed_decoded_inst_get_default_flags_values 	( 	const xed_decoded_inst_t *  	xedd,
		xed_flag_dfv_t *  	p 
Extracts the default flags values into the provided xed_flag_dfv_t struct. Returns 0 if the DFV is invalid.

static XED_INLINE xed_extension_enum_t xed_decoded_inst_get_extension 	( 	const xed_decoded_inst_t *  	p	) 	
Return the instruction xed_extension_enum_t enumeration

static XED_INLINE xed_iclass_enum_t xed_decoded_inst_get_iclass 	( 	const xed_decoded_inst_t *  	p	) 	
Return the instruction xed_iclass_enum_t enumeration.

static XED_INLINE xed_iform_enum_t xed_decoded_inst_get_iform_enum 	( 	const xed_decoded_inst_t *  	p	) 	
Return the instruction iform enum of type xed_iform_enum_t .

static XED_INLINE unsigned int xed_decoded_inst_get_iform_enum_dispatch 	( 	const xed_decoded_inst_t *  	p	) 	

xed_uint_t xed_decoded_inst_get_immediate_is_signed 	( 	const xed_decoded_inst_t *  	p	) 	
Return true if the first immediate (IMM0) is signed

xed_uint_t xed_decoded_inst_get_immediate_width 	( 	const xed_decoded_inst_t *  	p	) 	
Return the immediate width in BYTES.

xed_uint_t xed_decoded_inst_get_immediate_width_bits 	( 	const xed_decoded_inst_t *  	p	) 	
Return the immediate width in BITS.

xed_reg_enum_t xed_decoded_inst_get_index_reg 	( 	const xed_decoded_inst_t *  	p,

static XED_INLINE xed_chip_enum_t xed_decoded_inst_get_input_chip 	( 	const xed_decoded_inst_t *  	p	) 	
Return the user-specified xed_chip_enum_t chip name, or XED_CHIP_INVALID if not set.

static XED_INLINE xed_isa_set_enum_t xed_decoded_inst_get_isa_set 	( 	xed_decoded_inst_t const *const  	p	) 	
Return the instruction xed_isa_set_enum_t enumeration

static XED_INLINE xed_uint_t xed_decoded_inst_get_length 	( 	const xed_decoded_inst_t *  	p	) 	
Return the length of the decoded instruction in bytes.

static XED_INLINE xed_uint_t xed_decoded_inst_get_machine_mode_bits 	( 	const xed_decoded_inst_t *  	p	) 	
Returns 16/32/64 indicating the machine mode with in bits. This is derived from the input mode information.

unsigned int xed_decoded_inst_get_memop_address_width 	( 	const xed_decoded_inst_t *  	p,
		xed_uint_t  	memop_idx 
Returns the addressing width in bits (16,32,64) for MEM0 (memop_idx==0) or MEM1 (memop_idx==1).
This factors in things like whether or not the reference is an implicit stack push/pop reference, the machine mode and

xed_int64_t xed_decoded_inst_get_memory_displacement 	( 	const xed_decoded_inst_t *  	p,

xed_uint_t xed_decoded_inst_get_memory_displacement_width 	( 	const xed_decoded_inst_t *  	p,
Result in BYTES

xed_uint_t xed_decoded_inst_get_memory_displacement_width_bits 	( 	const xed_decoded_inst_t *  	p,
Result in BITS

unsigned int xed_decoded_inst_get_memory_operand_length 	( 	const xed_decoded_inst_t *  	p,

xed_uint8_t xed_decoded_inst_get_modrm 	( 	const xed_decoded_inst_t *  	p	) 	
Returns the modrm byte

xed_uint_t xed_decoded_inst_get_nprefixes 	( 	const xed_decoded_inst_t *  	p	) 	
Returns the number of legacy prefixes.

xed_uint32_t xed_decoded_inst_get_operand_width 	( 	const xed_decoded_inst_t *  	p	) 	
Returns the operand width in bits: 8/16/32/64.

xed_reg_enum_t xed_decoded_inst_get_reg 	( 	const xed_decoded_inst_t *  	p,
		xed_operand_enum_t  	reg_operand 		
Return the specified register operand. The specifier is of type xed_operand_enum_t .

const xed_simple_flag_t* xed_decoded_inst_get_rflags_info 	( 	const xed_decoded_inst_t *  	p	) 	
This can return 0 if the flags are really not used by this instruction.

xed_uint_t xed_decoded_inst_get_scale 	( 	const xed_decoded_inst_t *  	p,

static XED_INLINE xed_uint8_t xed_decoded_inst_get_second_immediate 	( 	const xed_decoded_inst_t *  	p	) 	
Return the second immediate.

xed_reg_enum_t xed_decoded_inst_get_seg_reg 	( 	const xed_decoded_inst_t *  	p,

xed_int32_t xed_decoded_inst_get_signed_immediate 	( 	const xed_decoded_inst_t *  	p	) 	

static XED_INLINE xed_uint_t xed_decoded_inst_get_stack_address_mode_bits 	( 	const xed_decoded_inst_t *  	p	) 	
Returns 16/32/64 indicating the stack addressing mode with in bits. This is derived from the input mode information.

xed_uint64_t xed_decoded_inst_get_unsigned_immediate 	( 	const xed_decoded_inst_t *  	p	) 	

static XED_INLINE xed_uint64_t xed_decoded_inst_get_user_data 	( 	xed_decoded_inst_t *  	p	) 	
Return a user data field for arbitrary use by the user after decoding.

xed_bool_t xed_decoded_inst_has_default_flags_values 	( 	const xed_decoded_inst_t *  	xedd	) 	
Returns a non-zero value if the instruction supports "Default Flags Values" (DFV).

xed_uint32_t xed_decoded_inst_has_mpx_prefix 	( 	const xed_decoded_inst_t *  	p	) 	
Returns 1 if the instruction has mpx prefix.

static const XED_INLINE xed_inst_t* xed_decoded_inst_inst 	( 	const xed_decoded_inst_t *  	p	) 	
Return the xed_inst_t structure for this instruction. This is the route to the basic operands form information.

xed_bool_t xed_decoded_inst_is_apx_zu 	( 	const xed_decoded_inst_t *  	p	) 	
Return non-zero value for APX-Promtoed zero-upper instructions (ZU).

xed_bool_t xed_decoded_inst_is_broadcast 	( 	const xed_decoded_inst_t *  	p	) 	

xed_bool_t xed_decoded_inst_is_broadcast_instruction 	( 	const xed_decoded_inst_t *  	p	) 	
Return 1 for broadcast instruction. (NOT including AVX512 load-op instructions) 0 otherwise. Just a category check.

xed_bool_t xed_decoded_inst_is_prefetch 	( 	const xed_decoded_inst_t *  	p	) 	
Returns true if the instruction is a prefetch

xed_uint32_t xed_decoded_inst_is_xacquire 	( 	const xed_decoded_inst_t *  	p	) 	
Returns 1 if the instruction is xacquire.

xed_uint32_t xed_decoded_inst_is_xrelease 	( 	const xed_decoded_inst_t *  	p	) 	
Returns 1 if the instruction is xrelease.

xed_bool_t xed_decoded_inst_masked_vector_operation 	( 	xed_decoded_inst_t *  	p	) 	
Returns 1 iff the instruction uses destination-masking. This is 0 for blend operations that use their mask field as a control.

xed_bool_t xed_decoded_inst_masking 	( 	const xed_decoded_inst_t *  	p	) 	
Returns true if the instruction uses write-masking.

xed_bool_t xed_decoded_inst_mem_read 	( 	const xed_decoded_inst_t *  	p,

xed_bool_t xed_decoded_inst_mem_written 	( 	const xed_decoded_inst_t *  	p,

xed_bool_t xed_decoded_inst_mem_written_only 	( 	const xed_decoded_inst_t *  	p,

xed_bool_t xed_decoded_inst_merging 	( 	const xed_decoded_inst_t *  	p	) 	
Returns true if the instruction uses write-masking with merging.

static XED_INLINE unsigned int xed_decoded_inst_noperands 	( 	const xed_decoded_inst_t *  	p	) 	
Return the number of operands.

xed_uint_t xed_decoded_inst_number_of_memory_operands 	( 	const xed_decoded_inst_t *  	p	) 	

xed_operand_action_enum_t xed_decoded_inst_operand_action 	( 	const xed_decoded_inst_t *  	p,
Interpret the operand action in light of AVX512 masking and zeroing/merging.
If masking and merging are used together, the dest operand may also be read. If masking and merging are used together, the elemnents of dest operand register may be conditionally written (so that input values live on in the output register).

unsigned int xed_decoded_inst_operand_element_size_bits 	( 	const xed_decoded_inst_t *  	p,
Return the size of an element in bits (for SSE and AVX operands)

xed_operand_element_type_enum_t xed_decoded_inst_operand_element_type 	( 	const xed_decoded_inst_t *  	p,
Return the type of an element of type xed_operand_element_type_enum_t (for SSE and AVX operands)

unsigned int xed_decoded_inst_operand_elements 	( 	const xed_decoded_inst_t *  	p,
Return the number of element in the operand (for SSE and AVX operands)

unsigned int xed_decoded_inst_operand_length 	( 	const xed_decoded_inst_t *  	p,
Deprecated ; returns the length in bytes of the operand_index'th operand.

unsigned int xed_decoded_inst_operand_length_bits 	( 	const xed_decoded_inst_t *  	p,
Return the length in bits of the operand_index'th operand.

static XED_INLINE xed_operand_values_t* xed_decoded_inst_operands 	( 	xed_decoded_inst_t *  	p	) 	
Obtain a non-constant pointer to the operands

static const XED_INLINE xed_operand_values_t* xed_decoded_inst_operands_const 	( 	const xed_decoded_inst_t *  	p	) 	
Obtain a constant pointer to the operands

xed_bool_t xed_decoded_inst_uses_embedded_broadcast 	( 	const xed_decoded_inst_t *  	p	) 	
Return 1 for AVX512 load-op instructions using the broadcast feature, 0 otherwise.

xed_bool_t xed_decoded_inst_uses_rflags 	( 	const xed_decoded_inst_t *  	p	) 	
This returns 1 if the flags are read or written.
This will return 0 otherwise. This will return 0 if the flags are really not used by this instruction. For some shifts/rotates, XED puts a flags operand in the operand array before it knows if the flags are used because of mode-dependent masking effects on the immediate.

static XED_INLINE xed_bool_t xed_decoded_inst_valid 	( 	const xed_decoded_inst_t *  	p	) 	
Return true if the instruction is valid

xed_bool_t xed_decoded_inst_valid_for_chip 	( 	xed_decoded_inst_t const *const  	p,
		xed_chip_enum_t  	chip 
Indicate if this decoded instruction is valid for the specified xed_chip_enum_t chip.

xed_bool_t xed_decoded_inst_valid_for_features 	( 	xed_decoded_inst_t const *const  	p,
		xed_chip_features_t const *const  	chip_features 
Indicate if this decoded instruction is valid for the specified xed_chip_features_t chip.

xed_uint_t xed_decoded_inst_vector_length_bits 	( 	xed_decoded_inst_t const *const  	p	) 	
Returns 128, 256 or 512 for operations in the VEX, EVEX (or XOP) encoding space and returns 0 for (most) nonvector operations. This usually the content of the VEX.L or EVEX.LL field, reinterpreted. Some GPR instructions (like the BMI1/BMI2) are encoded in the VEX space and return non-zero values from this API.

#endif
