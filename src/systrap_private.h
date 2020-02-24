#ifndef SYSTRAP_PRIVATE_H_
#define SYSTRAP_PRIVATE_H_

extern int debug_level __attribute__((visibility("hidden")));

#ifdef SYSTRAP_DEFINE_FILE
struct _IO_FILE;
typedef struct _IO_FILE FILE;
#endif
/* Don't declare stderr ourselves; e.g. in FreeBSD it's really called __stderrp. */
/* extern FILE *stderr; */
extern FILE **p_err_stream;
extern FILE *our_fake_stderr;

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
    if ((lvl) <= debug_level) { \
      if (!p_err_stream || !*p_err_stream) { \
          p_err_stream = &our_fake_stderr; \
          *p_err_stream = fdopen(2, "w"); \
      } \
      fprintf(*p_err_stream, fmt, ## __VA_ARGS__ ); \
      fflush(*p_err_stream); \
    } \
  } while (0)

#endif
