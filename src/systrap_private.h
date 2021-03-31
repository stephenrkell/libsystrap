#ifndef SYSTRAP_PRIVATE_H_
#define SYSTRAP_PRIVATE_H_

extern int systrap_debug_level __attribute__((visibility("hidden")));

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
