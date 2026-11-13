#ifndef TRACE_SYSCALLS_H_
#define TRACE_SYSCALLS_H_

#include <stdio.h>
#include <elf.h>

void init_fds(void) __attribute__((visibility("hidden")));
void trap_all_mappings(void) __attribute__((visibility("hidden")));
void start_tracing(ElfW(auxv_t) *p_auxv, _Bool apply_asm_replacements, void *arg) __attribute__((visibility("hidden")));
extern int debug_level __attribute__((visibility("hidden")));
extern FILE **p_err_stream __attribute__((visibility("hidden")));
extern FILE *our_fake_stderr  __attribute__((visibility("hidden"))); // will fdopen stderr if necessary

/* We may or may not be using donald.h, so be conditional... */
#ifndef debug_printf
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= debug_level) { \
      if (!p_err_stream || !*p_err_stream) { \
          p_err_stream = &our_fake_stderr; \
          *p_err_stream = fdopen(2, "w"); if (!*p_err_stream) abort(); \
      } \
      fprintf(*p_err_stream, fmt, ## __VA_ARGS__ ); \
      fflush(*p_err_stream); \
    } \
  } while (0)
#endif

#endif
