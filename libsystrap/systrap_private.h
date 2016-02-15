#ifndef SYSTRAP_PRIVATE_H_
#define SYSTRAP_PRIVATE_H_

extern void *stderr;
extern int debug_level __attribute__((visibility("hidden")));
extern int sleep_for_seconds __attribute__((visibility("hidden")));
extern int stop_self __attribute__((visibility("hidden")));
extern int self_pid __attribute__((visibility("hidden")));
extern void *stderr;
extern void **p_err_stream;

extern char *getenv (const char *__name) __THROW __nonnull ((1)) __wur;
extern int atoi (const char *__nptr)
     __THROW __attribute_pure__ __nonnull ((1)) __wur;
/* avoid stdlib and stdio for sigset_t conflict reasons */
void *calloc(size_t, size_t);
void free(void*);
/* avoid stdio because of sigset_t conflict */
void *fdopen(int fd, const char *mode);
int fprintf(void *stream, const char *format, ...);
int vfprintf(void *stream, const char *format, va_list args);
int fflush(void *stream);

#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= debug_level) { \
      fprintf(*p_err_stream, fmt, ## __VA_ARGS__ ); \
      fflush(*p_err_stream); \
    } \
  } while (0)

#endif
