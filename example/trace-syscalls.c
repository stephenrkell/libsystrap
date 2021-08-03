#define _GNU_SOURCE
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <link.h>
#include <alloca.h>
#ifndef assert
// HACK to avoid including assert.h
#if 0 /* musl already gives us this... ho hum */
extern void
__assert_fail (const char *assertion, const char *file,
        unsigned int line, const char *function) __attribute__((__noreturn__));
#endif
#define stringify(cond) #cond
#define assert(cond) \
        do { ((cond) ? ((void) 0) : (__assert_fail("Assertion failed: \"" stringify((cond)) "\"", __FILE__, __LINE__, __func__ ))); }  while (0)
#endif
#include <librunt.h> /* from librunt */
#include <dso-meta.h> /* from librunt */
#include <vas.h> /* from librunt */
#include <maps.h> /* from librunt */
#include <relf.h> /* from librunt */
#include "systrap.h"
#include "syscall-names.h"
#include "raw-syscalls-defs.h"
#include "trace-syscalls.h"

int raw_open(const char *pathname, int flags, int mode);
int raw_close(int fd);
extern int etext;

/* We are a preloaded library whose constructor
 * calls libsystrap to divert all syscalls
 * into the generic syscall emulation path; we provide
 * pre_handler and post_handler to print stuff. */

void *traces_out __attribute__((visibility("hidden"))) /* really FILE* */;
int trace_fd __attribute__((visibility("hidden")));
int debug_level __attribute__((visibility("hidden")));
FILE **p_err_stream __attribute__((visibility("hidden")));
FILE *our_fake_stderr __attribute__((visibility("hidden"))); // will fdopen stderr if necessary

/* FIXME: use a librunt API for doing this. */
static int process_mapping_cb(struct maps_entry *ent, char *linebuf, void *arg)
{
	/* Skip ourselves, but remember our load address. */
	void *expected_mapping_end = ROUND_UP_PTR_TO_PAGE((uintptr_t) &etext);
	if ((const unsigned char *) ent->second >= (const unsigned char *) expected_mapping_end
		 && (const unsigned char *) ent->first < (const unsigned char *) expected_mapping_end)
	{
		// it's our own mapping; skip and keep going
		return 0;
	}

	if (ent->x == 'x')
	{
		trap_one_executable_region((unsigned char *) ent->first, (unsigned char *) ent->second,
			 ent->rest[0] ? ent->rest : NULL,
			ent->w == 'w', ent->r == 'r');
	}
	
	return 0; // keep going
}

void trap_all_mappings(void)
{
	/* When we process mappings, we do mprotect()s, which can change the memory map, 
	 * including removing/adding lines. So there's a race condition unless we eagerly
	 * snapshot the map. Do that here. */
	int fd = raw_open("/proc/self/maps", O_RDONLY, 0);
	if (fd >= 0)
	{
		/* We run during startup, so the number of distinct /proc lines should be small. */
	#define MAX_LINES 1024
	#define MAX_ALLBUF 81920 // 80kB
		static char *lines[MAX_LINES];
		static char allbuf[MAX_ALLBUF];
		char *p_allbuf = &allbuf[0];
		int n = 0;
		ssize_t linesz;
		char linebuf[8192];
		while (-1 != (linesz = get_a_line_from_maps_fd(linebuf, sizeof linebuf, fd)))
		{
			/* I have seen alloca blow the stack here on 32-bit, so use a static buffer.
			 * We simply fill the buffer with all the data we get from get_a_line...(),
			 * and point lines[i] into it at the start-of-line positions. */
			//char *a = alloca(linesz + 1);
			char *a = p_allbuf;
			// if the combined offset exceeds the size of allbuf, we give up
			if ((p_allbuf - &allbuf[0]) + linesz + 1 > sizeof allbuf) abort();
			p_allbuf += (linesz + 1);
			lines[n] = a;
			assert(lines[n]);
			// copy info allbuf from linebuf
			strncpy(lines[n], linebuf, linesz);
			lines[n][linesz] = '\0';
			++n;
		}
		
		/* Now we have an array containing the lines. */
		struct maps_entry entry;
		for (int i = 0; i < n; ++i)
		{
			int ret = process_one_maps_entry(lines[i], &entry, process_mapping_cb, NULL);
			if (ret) break;
		}

		raw_close(fd);
	} else debug_printf(0, "Could not open /proc/self/maps");
}

void init_fds(void)
{
	if (getenv("TRACE_SYSCALLS_DELAY_STARTUP"))
	{
		sleep(atoi(getenv("TRACE_SYSCALLS_DELAY_STARTUP")));
	}
	
	char *trace_fd_str = getenv("TRACE_SYSCALLS_TRACE_FD");
	if (trace_fd_str) trace_fd = atoi(trace_fd_str);
	debug_printf(0, "TRACE_SYSCALLS_TRACE_FD is %s, ", trace_fd_str ?: "(none)");
	if (!trace_fd_str || trace_fd == 2)
	{
		debug_printf(0, "dup'ing stderr, ");
		trace_fd = dup(2);
	}
	/* The user is allowed to ask for traces on a particular fd, which must
	 * be open at process start. We fdopen it to get a FILE object. */
	if (trace_fd >= 0)
	{
		if (fcntl(trace_fd, F_GETFD) != -1)
		{
			debug_printf(0, "fd %d is open; outputting traces there.\n", trace_fd);
			traces_out = fdopen(trace_fd, "a");
			if (!traces_out)
			{
				debug_printf(0, "Could not open traces output stream for writing!\n");
			}
		}
		else
		{
			debug_printf(0, "fd %d is closed; not outputting traces.\n", trace_fd);
		}
	}
	else debug_printf(0, "not outputting traces.\n");
}

void __init_libc(char **envp, char *pn); // musl-internal API

static void startup(void) __attribute__((constructor(101)));
static void startup(void)
{
	/* We use musl as our libc. That means there are (up to) two libc instances
	 * in the process! Before we do any libc calls, make sure musl's state
	 * is initialized. We use librunt to get the env/arg values. */
	const char **p_argv_0 = NULL, **p_argv_end = NULL;
	const char **p_envv_0 = NULL, **p_envv_end = NULL;
	__runt_auxv_init();
	__runt_auxv_get_argv(&p_argv_0, &p_argv_end);
	__runt_auxv_get_env(&p_envv_0, &p_envv_end);
	__init_libc((char**) p_envv_0, (char*) *p_argv_0);
	init_fds();
	trap_all_mappings();
	install_sigill_handler();
}


void print_pre_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret)
			__attribute__((visibility("protected")));
void print_pre_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret) {
	char namebuf[5];
	snprintf(namebuf, sizeof namebuf, "%d", gsp->syscall_number);
	fprintf(stream, "== %d == > %p (%s+0x%x) %s(%p, %p, %p, %p, %p, %p)\n",
			 getpid(), 
			 calling_addr,
			 calling_object ? calling_object->l_name : "(unknown)",
			 calling_object ? (char*) calling_addr - (char*) calling_object->l_addr : (ptrdiff_t) 0,
			 syscall_names[gsp->syscall_number]?:namebuf,
			 gsp->args[0],
			 gsp->args[1],
			 gsp->args[2],
			 gsp->args[3],
			 gsp->args[4],
			 gsp->args[5]
		);
	fflush(stream);
}

void print_post_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret)
			__attribute__((visibility("protected")));
void print_post_syscall(void *stream, struct generic_syscall *gsp, void *calling_addr, struct link_map *calling_object, void *ret) {
	fprintf(stream, "== %d == < %p (%s+0x%x) %s(%p, %p, %p, %p, %p, %p) = %p\n",
		getpid(),
		calling_addr,
		calling_object ? calling_object->l_name : "(unknown)",
		calling_object ? (char*) calling_addr - (char*) calling_object->l_addr : (ptrdiff_t) 0,
		syscall_names[gsp->syscall_number],
			gsp->args[0],
			gsp->args[1],
			gsp->args[2],
			gsp->args[3],
			gsp->args[4],
			gsp->args[5],
		ret
	);
	fflush(stream);
}

void __attribute__((visibility("protected")))
systrap_pre_handling(struct generic_syscall *gsp)
{
	void *calling_addr = generic_syscall_get_ip(gsp);
	struct link_map *calling_object = get_highest_loaded_object_below(calling_addr);
	print_pre_syscall(traces_out, gsp, calling_addr, calling_object, NULL);
}

void __attribute__((visibility("protected")))
systrap_post_handling(struct generic_syscall *gsp, long ret, _Bool do_fixup)
{
	void *calling_addr = generic_syscall_get_ip(gsp);
	struct link_map *calling_object = get_highest_loaded_object_below(calling_addr);
	print_post_syscall(traces_out, gsp, calling_addr, calling_object, NULL);
	__libsystrap_noop_post_handling(gsp, ret, do_fixup);
}
