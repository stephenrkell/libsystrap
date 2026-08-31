#ifndef SYSTRAP_PRIVATE_H_
#define SYSTRAP_PRIVATE_H_

extern int systrap_debug_level __attribute__((visibility("hidden")));
extern _Bool is_ud2(const unsigned char *ins) __attribute__((visibility("hidden")));

#include <stdint.h>
/* Trap-site registry: the set of addresses where WE replaced an instruction
 * with ud2. Used to distinguish our syscall traps from foreign ud2s (e.g.
 * Alaska's safepoint poll points). See trap.c and sigill.c. */
void __systrap_record_trap_site(uintptr_t addr) __attribute__((visibility("hidden")));
_Bool __systrap_is_trap_site(uintptr_t addr) __attribute__((visibility("hidden")));
/* The client SIGILL handler to chain to for non-trap-site SIGILLs (or NULL). */
extern void (*__systrap_chained_sigill_handler)(int, void *, void *)
	__attribute__((visibility("hidden")));

#ifdef SYSTRAP_DEFINE_FILE
struct _IO_FILE;
typedef struct _IO_FILE FILE;
#endif
/* Don't declare stderr ourselves; e.g. in FreeBSD it's really called __stderrp. */
/* extern FILE *stderr; */

extern char *getenv (const char *__name);
extern int atoi (const char *__nptr);
/* avoid stdlib and stdio for sigset_t conflict reasons */
void *calloc(size_t, size_t);
void free(void*);
/* avoid stdio because of sigset_t conflict */
FILE *fdopen(int fd, const char *mode);
int fprintf(FILE *stream, const char *format, ...);
int vfprintf(FILE *stream, const char *format, va_list args);
int fflush(FILE *stream);

#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= systrap_debug_level) { \
      fprintf(stderr, fmt, ## __VA_ARGS__ ); \
      fflush(stderr); \
    } \
  } while (0)

#endif
