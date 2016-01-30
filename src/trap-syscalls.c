#define _GNU_SOURCE
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
// #include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "systrap.h"
#include "systrap_private.h"
#include <footprints.h>

_Bool __write_footprints;
_Bool __write_traces;
void *footprints_out __attribute__((visibility("hidden"))) /* really FILE* */;
void *traces_out __attribute__((visibility("hidden"))) /* really FILE* */;
int footprint_fd __attribute__((visibility("hidden")));
int trace_fd __attribute__((visibility("hidden")));
char *footprints_spec_filename __attribute__((visibility("hidden")));
struct env_node *footprints_env __attribute__((visibility("hidden"))) = NULL;
struct footprint_node *footprints __attribute__((visibility("hidden"))) = NULL;

#ifndef EXECUTABLE
#define RETURN_VALUE
static void __attribute__((constructor)) startup(void)
{
#else
#define RETURN_VALUE 0
extern void *__libsystrap_ignore_ud2_addr;
// scratch test code
int main(void)
{
#endif

	char *footprint_fd_str = getenv("TRAP_SYSCALLS_FOOTPRINT_FD");
	char *trace_fd_str = getenv("TRAP_SYSCALLS_TRACE_FD");
	footprints_spec_filename = getenv("TRAP_SYSCALLS_FOOTPRINT_SPEC_FILENAME");
	struct timespec one_second = { /* seconds */ 1, /* nanoseconds */ 0 };
	if (trace_fd_str) trace_fd = atoi(trace_fd_str);
	if (footprint_fd_str) footprint_fd = atoi(footprint_fd_str);

	/* Is fd open? If so, it's the input fd for our sanity check info
	 * from systemtap. */
	debug_printf(0, "TRAP_SYSCALLS_FOOTPRINT_FD is %s, ", footprint_fd_str);
	if (footprint_fd > 2)
	{
		struct stat buf;
		int stat_ret = raw_fstat(footprint_fd, &buf);
		if (stat_ret == 0) {
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

			if (footprints_spec_filename) {

				 footprints = parse_footprints_from_file(footprints_spec_filename, &footprints_env);
				 
			} else {
				 debug_printf(0, "no footprints spec filename provided\n", footprints_spec_filename);
			}

			
		} else {
			debug_printf(0, "fd %d is closed; skipping systemtap cross-check info.\n", footprint_fd);
		}

	}
	else
	{
		debug_printf(0, "skipping systemtap cross-check info\n");
	}

	debug_printf(0, "TRAP_SYSCALLS_TRACE_FD is %s, ", trace_fd_str);
	if (!trace_fd_str || trace_fd == 2) {
		debug_printf(0, "dup'ing stderr, ");
		trace_fd = dup(2);
	}
	
	if (trace_fd >= 0) {
		struct stat buf;
		int stat_ret = raw_fstat(trace_fd, &buf);
		if (stat_ret == 0) {
			debug_printf(0, "fd %d is open; outputting traces there.\n", trace_fd);
			__write_traces = 1;
			traces_out = fdopen(trace_fd, "a");
			if (!traces_out)
				{
					debug_printf(0, "Could not open traces output stream for writing!\n");
				}
		} else {
			debug_printf(0, "fd %d is closed; not outputting traces.\n", trace_fd);
		}
	} else {
		debug_printf(0, "not outputting traces.\n");
	}
	
	trap_all_mappings();
	install_sigill_handler();
	
#ifdef EXECUTABLE
	// HACK for testing: do a ud2 right now!
	ignore_ud2_addr = &&ud2_addr;
ud2_addr:
	__asm__ ("ud2\n");

	// we must also exit without running any libdl exit handlers,
	// because we're an executable so our csu/startfiles include some cleanup
	// that will now cause traps (this isn't necessary in the shared library case)
	raw_exit(0);
#endif
	return RETURN_VALUE;
}
