#define RELF_DEFINE_STRUCTURES
#include <stddef.h>
#include <sys/types.h>
#include <assert.h>
#include "relf.h"
#include "raw-syscalls-impl.h"
#define _GNU_SOURCE
#include <elf.h>
#include <stdarg.h>
#include "systrap.h"
#include "systrap_private.h"
#include "syscall-names.h"

extern void *traces_out;

void print_post_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret)
	__attribute__((visibility("protected")));
void print_pre_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret)
	__attribute__((visibility("protected")));

/* These "weak" definitions may be overridden. */
void __attribute__((visibility("protected"),weak))
systrap_pre_handling(struct generic_syscall *gsp)
{
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.MC_REG(rip, RIP);
	struct link_map *calling_object = get_highest_loaded_object_below(calling_addr);
	print_pre_syscall(traces_out, gsp, calling_addr, calling_object, NULL);
}

void __attribute__((visibility("protected"),weak))
systrap_post_handling(struct generic_syscall *gsp)
{
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.MC_REG(rip, RIP);
	struct link_map *calling_object = get_highest_loaded_object_below(calling_addr);
	print_post_syscall(traces_out, gsp, calling_addr, calling_object, NULL);
}
