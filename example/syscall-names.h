#ifndef SYSCALL_NAMES_H_
#define SYSCALL_NAMES_H_

#ifndef SYSCALL_MAX
#define SYSCALL_MAX 1024 /* safe overestimate for now? */
#endif

#define SYSCALL_NAME_LEN 32

extern const char *syscall_names[SYSCALL_MAX + 2];

#endif
