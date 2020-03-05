#include "do-syscall.h"
#include "syscall-names.h"
#include <uniqtype.h> /* from liballocs; for walking footprints */
#include <string.h>
#include "elfutil.h"
#include "uniqtype-bfs.h"
#include <footprints.h>
#include "write-footprints.h"

_Bool __write_footprints;
void *footprints_out __attribute__((visibility("hidden"))) /* really FILE* */;
int footprint_fd __attribute__((visibility("hidden")));
char *footprints_spec_filename __attribute__((visibility("hidden")));
struct env_node *footprints_env __attribute__((visibility("hidden"))) = NULL;
struct footprint_node *footprints __attribute__((visibility("hidden"))) = NULL;

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
	
	struct uniqtype **found_ifacetype = sym_to_addr(hash_lookup_local(name_buf));
	if (!found_ifacetype) found_ifacetype = sym_to_addr(symbol_lookup_linear_local(name_buf));
	if (!found_ifacetype)
	{
		debug_printf(1, "No ifacetype for syscall %s (check kernel DWARF)\n", name_buf);
		return NULL;
	}
	struct uniqtype *found_uniqtype = *found_ifacetype;
	assert(found_uniqtype);
	return found_uniqtype;
}

void __attribute__((visibility("protected")))
write_footprint(void *base, size_t len, enum footprint_direction direction, const char *syscall)
{
	fprintf(footprints_out, "footprint: %s base=0x%016lx n=0x%016lx syscall=%s\n", footprint_direction_str[direction], (void*) base, (void*) len, syscall);
	fflush(footprints_out);
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

#define PRINT_BOTH(printer) do { \
	if (__write_footprints && footprints_out) { \
		printer(footprints_out, gsp, calling_addr, calling_object, ret); \
	} \
	if (__write_traces && traces_out) { \
		printer(traces_out, gsp, calling_addr, calling_object, ret); \
	} } while (0)

static void print_pre(struct generic_syscall *gsp, void *calling_addr, 
	struct link_map *calling_object, void *ret) 
{ PRINT_BOTH(print_pre_syscall); }

static void print_post(struct generic_syscall *gsp, void *calling_addr, 
	struct link_map *calling_object, void *ret) 
{ PRINT_BOTH(print_post_syscall); }

struct evaluator_state *supply_syscall_footprint(struct evaluator_state *eval,
                                                 struct footprint_node *fp,
                                                 struct env_node *footprints_env,
                                                 struct uniqtype *call,
                                                 long int args[static 6]) {
	eval = eval_footprint_with(eval, fp, footprints_env, call, args, true, FP_DIRECTION_READWRITE);
	while (!eval->finished) {
		assert(eval->need_memory_extents != NULL);
		struct extent_node *current = eval->need_memory_extents;
		while (current != NULL) {
			// just allow libfootprints to deref pointers
			eval->have_memory_extents = data_extent_node_new_with(current->extent.base, current->extent.length,
			                                                       (void*)current->extent.base,
			                                                       eval->have_memory_extents);
			current = current->next;
		}
		eval->need_memory_extents = NULL;
		eval = eval_footprint_with(eval, fp, footprints_env, call, args, true, FP_DIRECTION_READWRITE);
	}
	return eval;
}

void write_footprint_union(struct union_node *node, enum footprint_direction direction, const char *syscall_name) {
	struct union_node *current = node;
	while (current != NULL) {
		switch (current->expr->type) {
		case EXPR_EXTENT:
			write_footprint((void*) current->expr->extent.base, current->expr->extent.length, current->expr->direction, syscall_name);
			break;
		case EXPR_UNION:
			write_footprint_union(current->expr->unioned, current->expr->direction, syscall_name);
			break;
		default:
			assert(false);
		}
		current = current->next;
	}
}

void __attribute__((visibility("protected")))
systrap_pre_handling(struct generic_syscall *gsp)
{
	/* Now walk the footprint. We print out a line per-syscall before and after
	 * to bracket the invididual footprint items. */
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.MC_REG(rip);
	struct link_map *calling_object = get_link_map(calling_addr);
	print_pre(gsp, calling_addr, calling_object, NULL);
	
	struct uniqtype *call = uniqtype_for_syscall(gsp->syscall_number);
	if (call)
	{
		debug_printf(1, "Syscall %s/%d has uniqtype '%s' at address %p\n",
					 syscall_names[gsp->syscall_number], gsp->syscall_number, call->name, call);
		assert(UNIQTYPE_IS_SUBPROGRAM(call));
		/* Footprint enumeration is a breadth-first search from a set of roots. 
		 * Roots are (address, uniqtype) pairs.
		 * Every pointer argument to the syscall is a root. 
		 * (Note that the syscall arguments themselves don't live in memory,
		 * so we can't start directly from a unique root.)
		 */


		struct footprint_node *fp = get_footprints_for(footprints, syscall_names[gsp->syscall_number]);
		if (fp == NULL) {
			debug_printf(1, "(no footprint found for %s)\n", syscall_names[gsp->syscall_number]);
		} else {
			struct evaluator_state *eval = evaluator_state_new_with(construct_union(fp->exprs, FP_DIRECTION_READWRITE),
			                                                        footprints_env,
			                                                        NULL, NULL, NULL, false, debug_level > 0);
			eval = supply_syscall_footprint(eval, fp, footprints_env, call, gsp->args);
			assert(eval->finished);
			if (eval->result && __write_footprints && footprints_out) {
				write_footprint_union(eval->result, eval->result->expr->direction, syscall_names[gsp->syscall_number]);
			} else {
				debug_printf(1, "(no extents returned for %s)\n", syscall_names[gsp->syscall_number]);
			}
		}
	
		/* __uniqtype_node_rec *q_head = NULL; */
		/* __uniqtype_node_rec *q_tail = NULL; */
		/* for (int i = 1; i < call->nmemb; ++i) */
		/* { */
		/* 	struct uniqtype *arg_t = call->contained[i].ptr; */
		/* 	if (UNIQTYPE_IS_POINTER_TYPE(arg_t)) */
		/* 	{ */
		/* 		void *ptr_value = (void*) gsp->args[i]; */
		/* 		struct uniqtype *pointee_type = UNIQTYPE_POINTEE_TYPE(arg_t); */
		/* 		__uniqtype_node_rec *new_node = calloc(1, sizeof (new_node)); */
		/* 		assert(new_node); */
		/* 		new_node->obj = ptr_value; */
		/* 		new_node->t = pointee_type; */
		/* 		new_node->free = free; */
		/* 		__uniqtype_node_queue_push_tail(&q_head, &q_tail, new_node); */
		/* 	} */
		/* } */

/* Now explore the object graph. We will get a callback for each
		 * unique object (or <object, type> pair, eventually) that we visit. */
		/* __uniqtype_node_rec *list_head = NULL; */
		/* __uniqtype_process_bfs_queue(&q_head, &q_tail,  */
		/* 	__uniqtype_default_follow_ptr, NULL, */
		/* 	list_add, &list_head); */
		/* Now we have a list of objects constituting what we think the 
		 * footprint is. Output that to fd 7. */
		/* for (__uniqtype_node_rec *n = list_head; n; n = n->next) */
		/* { */
		/* 	write_footprint(n->obj, n->t->pos_maxoff); */
		/* } */
	}
	else
	{
		debug_printf(1, "Syscall %s(%d) has no uniqtype, so unknown footprint\n",
			syscall_names[gsp->syscall_number], gsp->syscall_number);
	}
}

void __attribute__((visibility("protected")))
systrap_post_handling(struct generic_syscall *gsp, long int ret)
{
	void *calling_addr = (void*) gsp->saved_context->uc.uc_mcontext.MC_REG(rip);
	struct link_map *calling_object = get_link_map(calling_addr);
	print_post(gsp, calling_addr, calling_object, (void *)ret);
}

static void __attribute__((constructor(102))) init_footprints(void)
{
	char *footprint_fd_str = getenv("TRAP_SYSCALLS_FOOTPRINT_FD");
	footprints_spec_filename = getenv("TRAP_SYSCALLS_FOOTPRINT_SPEC_FILENAME");
	struct timespec one_second = { /* seconds */ 1, /* nanoseconds */ 0 };
	if (footprint_fd_str) footprint_fd = atoi(footprint_fd_str);

	/* Is fd open? If so, it's the input fd for our sanity check info
	 * from systemtap. */
	debug_printf(0, "TRAP_SYSCALLS_FOOTPRINT_FD is %s, ", footprint_fd_str);
	if (footprint_fd > 2)
	{
		struct stat buf;
		int stat_ret = raw_fstat(footprint_fd, &buf);
		if (stat_ret == 0) 
		{
			debug_printf(0, "fd %d is open; outputting systemtap cross-check info.\n", footprint_fd);
			/* PROBLEM: ideally we'd read in the stap script's output ourselves, and process
			 * it at every system call. But by reading in stuff from stap, we're doing more
			 * copying to/from userspace, so creating a feedback loop which would blow up.
			 *
			 * Instead we write out what we think we touched, and do a diff outside the process.
			 * This also adds noise to stap's output, but without the feedback cycle: we ourselves
			 * won't read the extra output, hence won't write() more stuff in response.
			 */
			__write_footprints = 1;
			footprints_out = fdopen(footprint_fd, "a");
			if (!footprints_out)
			{
				debug_printf(0, "Could not open footprints output stream for writing!\n");
			}

			if (footprints_spec_filename)
			{
				footprints = parse_footprints_from_file(footprints_spec_filename, &footprints_env);
			}
			else debug_printf(0, "no footprints spec filename provided\n", footprints_spec_filename);
		}
		else debug_printf(0, "fd %d is closed; skipping systemtap cross-check info.\n", footprint_fd);
	} 
	else debug_printf(0, "skipping systemtap cross-check info\n");
}
