#ifndef SYSCALL_NAMES_H_
#define SYSCALL_NAMES_H_

#define SYSCALL_MAX 543 /* FIXME: where does this come from? */
#define SYSCALL_NAME_LEN 32

extern const char *syscall_names[SYSCALL_MAX + 1];

#endif
