/*
 * Implementations of various substitution functions and helper functions
 * called during syscall emulation.
 */

#include "do-syscall.h"
#include "syscall-names.h"
#include <uniqtype.h> /* from liballocs; for walking footprints */
#include <string.h>
#include "uniqtype-bfs.h"

#include "elf.h"

#define REPLACE_ARGN(n_arg, count)				      \
	long int arg ## n_arg = gsp->args[ n_arg ];		     \
	gsp->args[ n_arg ] =					     \
		(long int) lock_memory(arg ## n_arg , (count), 0);

#define RESTORE_ARGN(n_arg, count)				      \
	free_memory(gsp->args[ n_arg ], arg ## n_arg, (count));	  \
	gsp->args[ n_arg ] = arg ## n_arg;


static struct uniqtype *uniqtype_for_syscall(int syscall_num)
{
	const char *syscall_name = syscall_names[syscall_num];
	if (!syscall_name)
	{
		debug_printf(1, "No name for syscall number %d\n", syscall_num);
		return NULL;
	}
	const char prefix[] = "__ifacetype_";
	char name_buf[SYSCALL_NAME_LEN + sizeof prefix + 1];
	strncpy(name_buf, prefix, sizeof prefix);
	strncat(name_buf + sizeof prefix - 1, syscall_name, sizeof name_buf - sizeof prefix + 1);
	name_buf[sizeof name_buf - 1] = '\0';
	
	struct uniqtype **found_ifacetype = hash_lookup(name_buf);
	assert(found_ifacetype);
	struct uniqtype *found_uniqtype = *found_ifacetype;
	assert(found_uniqtype);
	return found_uniqtype;
}

void __attribute__((visibility("protected")))
write_footprint(void *base, size_t len)
{
	fprintf(footprints_out, "n=0x%lx base=0x%p\n", len, (void*) base);
}

static void list_add(void *obj, struct uniqtype *t, void *arg)
{
	__uniqtype_node_rec **head = (__uniqtype_node_rec **) arg;
	__uniqtype_node_rec *new_node = calloc(1, sizeof (__uniqtype_node_rec));
	assert(new_node);
	new_node->obj = obj;
	new_node->t = t;
	new_node->free = free;
	new_node->next = *head;
	*head = new_node;
}

void __attribute__((visibility("protected")))
pre_handling(struct generic_syscall *gsp)
{
	/* Now walk the footprint. We print out a line per-syscall before and after
	 * to bracket the invididual footprint items. */
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.rip;
	struct link_map *calling_object = vaddr_to_link_map(calling_addr, NULL);
	
	/* send same output to stderr and, if we're writing them, footprints_out */
#define FOR_TRACE_STREAMS \
	for (void *stream = stderr; stream; \
			stream = (__write_footprints && footprints_out) ? ((stream == footprints_out) ? NULL : footprints_out) \
					                      : NULL)
	FOR_TRACE_STREAMS
	{
		fprintf(stream, "== %d == > %p (%s+0x%x) %s(...)\n",
			raw_getpid(), 
			calling_addr,
			calling_object->l_name,
			(char*) calling_addr - (char*) calling_object->l_addr,
			syscall_names[gsp->syscall_number]
		);
	}
	
	struct uniqtype *call = uniqtype_for_syscall(gsp->syscall_number);
	if (call)
	{
		debug_printf(1, "Syscall %s/%d has uniqtype at address %p\n",
				syscall_names[gsp->syscall_number], gsp->syscall_number, call);
		assert(UNIQTYPE_IS_SUBPROGRAM(call));
		/* Footprint enumeration is a breadth-first search from a set of roots. 
		 * Roots are (address, uniqtype) pairs.
		 * Every pointer argument to the syscall is a root. 
		 * (Note that the syscall arguments themselves don't live in memory,
		 * so we can't start directly from a unique root.)
		 */
		__uniqtype_node_rec *q_head = NULL;
		__uniqtype_node_rec *q_tail = NULL;
		for (int i = 1; i < call->nmemb; ++i)
		{
			struct uniqtype *arg_t = call->contained[i].ptr;
			if (UNIQTYPE_IS_POINTER_TYPE(arg_t))
			{
				void *ptr_value = (void*) gsp->args[i];
				struct uniqtype *pointee_type = UNIQTYPE_POINTEE_TYPE(arg_t);
				__uniqtype_node_rec *new_node = calloc(1, sizeof (new_node));
				assert(new_node);
				new_node->obj = ptr_value;
				new_node->t = pointee_type;
				new_node->free = free;
				__uniqtype_node_queue_push_tail(&q_head, &q_tail, new_node);
			}
		}
		/* Now explore the object graph. We will get a callback for each
		 * unique object (or <object, type> pair, eventually) that we visit. */
		__uniqtype_node_rec *list_head = NULL;
		__uniqtype_process_bfs_queue(&q_head, &q_tail, 
			__uniqtype_default_follow_ptr, NULL,
			list_add, &list_head);
		/* Now we have a list of objects constituting what we think the 
		 * footprint is. Output that to fd 7. */
		for (__uniqtype_node_rec *n = list_head; n; n = n->next)
		{
			write_footprint(n->obj, n->t->pos_maxoff);
		}
	}
	else
	{
		debug_printf(1, "Syscall %s(%d) has no uniqtype, so unknown footprint\n",
			syscall_names[gsp->syscall_number], gsp->syscall_number);
	}
}

void __attribute__((visibility("protected")))
post_handling(struct generic_syscall *gsp, long int ret)
{
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.rip;
	struct link_map *calling_object = vaddr_to_link_map(calling_addr, NULL);
	FOR_TRACE_STREAMS
	{
		fprintf(stream, "== %d == < %p (%s+0x%x) %s(...) = %p\n",
			raw_getpid(),
			calling_addr,
			calling_object->l_name,
			(char*) calling_addr - (char*) calling_object->l_addr,
			syscall_names[gsp->syscall_number],
			(void*) ret
		);
	}
}
#undef FOR_TRACE_STREAMS

static void *lock_memory(long int addr, unsigned long count, int copy)
{
	void *ptr = (void *) addr;
	if (!ptr) {
		return NULL;
	}

	if (__write_footprints) write_footprint(ptr, count);

#ifdef DEBUG_REMAP
	{
		void *ret = malloc(count);
		if (copy) {
			memcpy(ret, ptr, count);
		} else {
			memset(ret, 0, count);
		}
#ifdef DUMP_SYSCALLS
		debug_printf(1, "    Replacing guest address %p with host address %p\n", 
			(void*) addr, (void*) ret, 18);
#endif // DUMP_SYSCALLS

		return ret;
	}
#else
	return ptr;
#endif
}

static void free_memory(long int host_addr, long int guest_addr, unsigned long count)
{
	void *host_ptr __attribute__((unused)) = (void *) host_addr;
	void *guest_ptr __attribute__((unused)) = (void *) guest_addr;
#ifdef DEBUG_REMAP
	if (!host_ptr) {
		return;
	} else if (host_ptr == guest_ptr) {
		return;
	} else if (count > 0) {
		memcpy(guest_ptr, host_ptr, count);
	}

	free(host_ptr);
#endif
}

#define RESUME resume_from_sigframe( \
		ret, \
		gsp->saved_context, \
		instr_len((unsigned char *) gsp->saved_context->uc.uc_mcontext.rip, (unsigned char *) -1) \
	)

static void do_exit (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall1(gsp);
	post(gsp, ret);
	RESUME;
}

static void do_getpid (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall0(gsp);
	post(gsp, ret);
	RESUME;
}

static void do_time (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;
	REPLACE_ARGN(0, sizeof(__kernel_time_t));
	ret = do_syscall1(gsp);
	RESTORE_ARGN(0, sizeof(__kernel_time_t));
	
	post(gsp, ret);

	RESUME;
}

static void do_write (struct generic_syscall *gsp, post_handler *post)
{
	long int ret = do_syscall3(gsp);
	post(gsp, ret);
	RESUME;
}


static void do_read (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;

	REPLACE_ARGN(1, gsp->args[2]);
	ret = do_syscall3(gsp);
	RESTORE_ARGN(1, gsp->args[2]);

	post(gsp, ret);
	
	RESUME;
}
static void do_open (struct generic_syscall *gsp, post_handler *post)
{
	long int ret;
	ret = do_syscall3(gsp);
	post(gsp, ret);
	RESUME;
}

#define DECL_SYSCALL(x) [SYS_ ## x ] = do_ ## x ,
syscall_replacement *replaced_syscalls[SYSCALL_MAX] = {
	DECL_SYSCALL(read)
	DECL_SYSCALL(write)
	DECL_SYSCALL(open)
	DECL_SYSCALL(getpid)
	DECL_SYSCALL(exit)
	DECL_SYSCALL(time)
};
#undef DECL_SYSCALL
