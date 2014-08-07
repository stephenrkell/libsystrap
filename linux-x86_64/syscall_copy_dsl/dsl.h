switch(syscall_arg[0]) {
case SYS_time:
/*
 *         time_t __user * tloc;
 */
copy_buf(syscall_arg[1], sizeof(time_t)); // tloc
break;
case SYS_stime:
/*
 *         time_t __user * tptr;
 */
copy_buf(syscall_arg[1], sizeof(time_t)); // tptr
break;
case SYS_gettimeofday:
/*
 *         struct timeval __user * tv;
 *         struct timezone __user * tz;
 */
copy_buf(syscall_arg[1], sizeof(struct timeval)); // tv
copy_buf(syscall_arg[2], sizeof(struct timezone)); // tz
break;
case SYS_settimeofday:
/*
 *         struct timeval __user * tv;
 *         struct timezone __user * tz;
 */
copy_buf(syscall_arg[1], sizeof(struct timeval)); // tv
copy_buf(syscall_arg[2], sizeof(struct timezone)); // tz
break;
case SYS_adjtimex:
/*
 *         struct timex __user * txc_p;
 */
copy_buf(syscall_arg[1], sizeof(struct timex)); // txc_p
break;
case SYS_times:
/*
 *         struct tms __user * tbuf;
 */
copy_buf(syscall_arg[1], sizeof(struct tms)); // tbuf
break;
case SYS_gettid:
break;
case SYS_nanosleep:
/*
 *         struct timespec __user * rqtp;
 *         struct timespec __user * rmtp;
 */
copy_buf(syscall_arg[1], sizeof(struct timespec)); // rqtp
copy_buf(syscall_arg[2], sizeof(struct timespec)); // rmtp
break;
case SYS_alarm:
/*
 *         unsigned int seconds;
 */
break;
case SYS_getpid:
break;
case SYS_getppid:
break;
case SYS_getuid:
break;
case SYS_geteuid:
break;
case SYS_getgid:
break;
case SYS_getegid:
break;
case SYS_getresuid:
/*
 *         uid_t __user * ruid;
 *         uid_t __user * euid;
 *         uid_t __user * suid;
 */
copy_buf(syscall_arg[1], sizeof(uid_t)); // ruid
copy_buf(syscall_arg[2], sizeof(uid_t)); // euid
copy_buf(syscall_arg[3], sizeof(uid_t)); // suid
break;
case SYS_getresgid:
/*
 *         gid_t __user * rgid;
 *         gid_t __user * egid;
 *         gid_t __user * sgid;
 */
copy_buf(syscall_arg[1], sizeof(gid_t)); // rgid
copy_buf(syscall_arg[2], sizeof(gid_t)); // egid
copy_buf(syscall_arg[3], sizeof(gid_t)); // sgid
break;
case SYS_getpgid:
/*
 *         pid_t pid;
 */
break;
case SYS_getpgrp:
break;
case SYS_getsid:
/*
 *         pid_t pid;
 */
break;
case SYS_getgroups:
/*
 *         int gidsetsize;
 *         gid_t __user * grouplist;
 */
copy_buf(syscall_arg[2], sizeof(gid_t)); // grouplist
break;
case SYS_setregid:
/*
 *         gid_t rgid;
 *         gid_t egid;
 */
break;
case SYS_setgid:
/*
 *         gid_t gid;
 */
break;
case SYS_setreuid:
/*
 *         uid_t ruid;
 *         uid_t euid;
 */
break;
case SYS_setuid:
/*
 *         uid_t uid;
 */
break;
case SYS_setresuid:
/*
 *         uid_t ruid;
 *         uid_t euid;
 *         uid_t suid;
 */
break;
case SYS_setresgid:
/*
 *         gid_t rgid;
 *         gid_t egid;
 *         gid_t sgid;
 */
break;
case SYS_setfsuid:
/*
 *         uid_t uid;
 */
break;
case SYS_setfsgid:
/*
 *         gid_t gid;
 */
break;
case SYS_setpgid:
/*
 *         pid_t pid;
 *         pid_t pgid;
 */
break;
case SYS_setsid:
break;
case SYS_setgroups:
/*
 *         int gidsetsize;
 *         gid_t __user * grouplist;
 */
copy_buf(syscall_arg[2], sizeof(gid_t)); // grouplist
break;
case SYS_acct:
/*
 *         const char __user * name;
 */
unsafe_copy_zts(name);
break;
case SYS_capget:
/*
 *         cap_user_header_t header;
 *         cap_user_data_t dataptr;
 */
break;
case SYS_capset:
/*
 *         cap_user_header_t header;
 *         const cap_user_data_t data;
 */
break;
case SYS_personality:
/*
 *         unsigned int personality;
 */
break;
case SYS_sigpending:
/*
 *         old_sigset_t __user * set;
 */
copy_buf(syscall_arg[1], sizeof(old_sigset_t)); // set
break;
case SYS_sigprocmask:
/*
 *         int how;
 *         old_sigset_t __user * set;
 *         old_sigset_t __user * oset;
 */
copy_buf(syscall_arg[2], sizeof(old_sigset_t)); // set
copy_buf(syscall_arg[3], sizeof(old_sigset_t)); // oset
break;
case SYS_getitimer:
/*
 *         int which;
 *         struct itimerval __user * value;
 */
copy_buf(syscall_arg[2], sizeof(struct itimerval)); // value
break;
case SYS_setitimer:
/*
 *         int which;
 *         struct itimerval __user * value;
 *         struct itimerval __user * ovalue;
 */
copy_buf(syscall_arg[2], sizeof(struct itimerval)); // value
copy_buf(syscall_arg[3], sizeof(struct itimerval)); // ovalue
break;
case SYS_timer_create:
/*
 *         clockid_t which_clock;
 *         struct sigevent __user * timer_event_spec;
 *         timer_t __user * created_timer_id;
 */
copy_buf(syscall_arg[2], sizeof(struct sigevent)); // timer_event_spec
rec_copy_struct(timer_event_spec);
copy_buf(syscall_arg[3], sizeof(timer_t)); // created_timer_id
break;
case SYS_timer_gettime:
/*
 *         timer_t timer_id;
 *         struct itimerspec __user * setting;
 */
copy_buf(syscall_arg[2], sizeof(struct itimerspec)); // setting
break;
case SYS_timer_getoverrun:
/*
 *         timer_t timer_id;
 */
break;
case SYS_timer_settime:
/*
 *         timer_t timer_id;
 *         int flags;
 *         const struct itimerspec __user * new_setting;
 *         struct itimerspec __user * old_setting;
 */
copy_buf(syscall_arg[3], sizeof(struct itimerspec)); // new_setting
copy_buf(syscall_arg[4], sizeof(struct itimerspec)); // old_setting
break;
case SYS_timer_delete:
/*
 *         timer_t timer_id;
 */
break;
case SYS_clock_settime:
/*
 *         clockid_t which_clock;
 *         const struct timespec __user * tp;
 */
copy_buf(syscall_arg[2], sizeof(struct timespec)); // tp
break;
case SYS_clock_gettime:
/*
 *         clockid_t which_clock;
 *         struct timespec __user * tp;
 */
copy_buf(syscall_arg[2], sizeof(struct timespec)); // tp
break;
case SYS_clock_adjtime:
/*
 *         clockid_t which_clock;
 *         struct timex __user * tx;
 */
copy_buf(syscall_arg[2], sizeof(struct timex)); // tx
break;
case SYS_clock_getres:
/*
 *         clockid_t which_clock;
 *         struct timespec __user * tp;
 */
copy_buf(syscall_arg[2], sizeof(struct timespec)); // tp
break;
case SYS_clock_nanosleep:
/*
 *         clockid_t which_clock;
 *         int flags;
 *         const struct timespec __user * rqtp;
 *         struct timespec __user * rmtp;
 */
copy_buf(syscall_arg[3], sizeof(struct timespec)); // rqtp
copy_buf(syscall_arg[4], sizeof(struct timespec)); // rmtp
break;
case SYS_nice:
/*
 *         int increment;
 */
break;
case SYS_sched_setscheduler:
/*
 *         pid_t pid;
 *         int policy;
 *         struct sched_param __user * param;
 */
copy_buf(syscall_arg[3], sizeof(struct sched_param)); // param
undefined semantics for struct param
break;
case SYS_sched_setparam:
/*
 *         pid_t pid;
 *         struct sched_param __user * param;
 */
copy_buf(syscall_arg[2], sizeof(struct sched_param)); // param
undefined semantics for struct param
break;
case SYS_sched_getscheduler:
/*
 *         pid_t pid;
 */
break;
case SYS_sched_getparam:
/*
 *         pid_t pid;
 *         struct sched_param __user * param;
 */
copy_buf(syscall_arg[2], sizeof(struct sched_param)); // param
undefined semantics for struct param
break;
case SYS_sched_setaffinity:
/*
 *         pid_t pid;
 *         unsigned int len;
 *         unsigned long __user * user_mask_ptr;
 */
copy_buf(syscall_arg[3], sizeof(long)); // user_mask_ptr
break;
case SYS_sched_getaffinity:
/*
 *         pid_t pid;
 *         unsigned int len;
 *         unsigned long __user * user_mask_ptr;
 */
copy_buf(syscall_arg[3], sizeof(long)); // user_mask_ptr
break;
case SYS_sched_yield:
break;
case SYS_sched_get_priority_max:
/*
 *         int policy;
 */
break;
case SYS_sched_get_priority_min:
/*
 *         int policy;
 */
break;
case SYS_sched_rr_get_interval:
/*
 *         pid_t pid;
 *         struct timespec __user * interval;
 */
copy_buf(syscall_arg[2], sizeof(struct timespec)); // interval
break;
case SYS_setpriority:
/*
 *         int which;
 *         int who;
 *         int niceval;
 */
break;
case SYS_getpriority:
/*
 *         int which;
 *         int who;
 */
break;
case SYS_shutdown:
/*
 *         int ;
 *         int ;
 */
break;
case SYS_reboot:
/*
 *         int magic1;
 *         int magic2;
 *         unsigned int cmd;
 *         void __user * arg;
 */
copy_buf(syscall_arg[4], sizeof(void)); // arg
break;
case SYS_restart_syscall:
break;
case SYS_kexec_load:
/*
 *         unsigned long entry;
 *         unsigned long nr_segments;
 *         struct kexec_segment __user * segments;
 *         unsigned long flags;
 */
copy_buf(syscall_arg[3], sizeof(struct kexec_segment)); // segments
rec_copy_struct(segments);
break;
case SYS_exit:
/*
 *         int error_code;
 */
break;
case SYS_exit_group:
/*
 *         int error_code;
 */
break;
case SYS_wait4:
/*
 *         pid_t pid;
 *         int __user * stat_addr;
 *         int options;
 *         struct rusage __user * ru;
 */
copy_buf(syscall_arg[2], sizeof(int)); // stat_addr
copy_buf(syscall_arg[4], sizeof(struct rusage)); // ru
break;
case SYS_waitid:
/*
 *         int which;
 *         pid_t pid;
 *         struct siginfo __user * infop;
 *         int options;
 *         struct rusage __user * ru;
 */
copy_buf(syscall_arg[3], sizeof(struct siginfo)); // infop
undefined semantics for struct infop
copy_buf(syscall_arg[5], sizeof(struct rusage)); // ru
break;
case SYS_waitpid:
/*
 *         pid_t pid;
 *         int __user * stat_addr;
 *         int options;
 */
copy_buf(syscall_arg[2], sizeof(int)); // stat_addr
break;
case SYS_set_tid_address:
/*
 *         int __user * tidptr;
 */
copy_buf(syscall_arg[1], sizeof(int)); // tidptr
break;
case SYS_futex:
/*
 *         u32 __user * uaddr;
 *         int op;
 *         u32 val;
 *         struct timespec __user * utime;
 *         u32 __user * uaddr2;
 *         u32 val3;
 */
copy_buf(syscall_arg[1], sizeof(u32)); // uaddr
copy_buf(syscall_arg[4], sizeof(struct timespec)); // utime
copy_buf(syscall_arg[5], sizeof(u32)); // uaddr2
break;
case SYS_init_module:
/*
 *         void __user * umod;
 *         unsigned long len;
 *         const char __user * uargs;
 */
copy_buf(syscall_arg[1], sizeof(void)); // umod
unsafe_copy_zts(uargs);
break;
case SYS_delete_module:
/*
 *         const char __user * name_user;
 *         unsigned int flags;
 */
unsafe_copy_zts(name_user);
break;
case SYS_rt_sigprocmask:
/*
 *         int how;
 *         sigset_t __user * set;
 *         sigset_t __user * oset;
 *         size_t sigsetsize;
 */
copy_buf(syscall_arg[2], sizeof(sigset_t)); // set
copy_buf(syscall_arg[3], sizeof(sigset_t)); // oset
break;
case SYS_rt_sigpending:
/*
 *         sigset_t __user * set;
 *         size_t sigsetsize;
 */
copy_buf(syscall_arg[1], sizeof(sigset_t)); // set
break;
case SYS_rt_sigtimedwait:
/*
 *         const sigset_t __user * uthese;
 *         siginfo_t __user * uinfo;
 *         const struct timespec __user * uts;
 *         size_t sigsetsize;
 */
copy_buf(syscall_arg[1], sizeof(sigset_t)); // uthese
copy_buf(syscall_arg[2], sizeof(siginfo_t)); // uinfo
copy_buf(syscall_arg[3], sizeof(struct timespec)); // uts
break;
case SYS_rt_tgsigqueueinfo:
/*
 *         pid_t tgid;
 *         pid_t pid;
 *         int sig;
 *         siginfo_t __user * uinfo;
 */
copy_buf(syscall_arg[4], sizeof(siginfo_t)); // uinfo
break;
case SYS_kill:
/*
 *         int pid;
 *         int sig;
 */
break;
case SYS_tgkill:
/*
 *         int tgid;
 *         int pid;
 *         int sig;
 */
break;
case SYS_tkill:
/*
 *         int pid;
 *         int sig;
 */
break;
case SYS_rt_sigqueueinfo:
/*
 *         int pid;
 *         int sig;
 *         siginfo_t __user * uinfo;
 */
copy_buf(syscall_arg[3], sizeof(siginfo_t)); // uinfo
break;
case SYS_sgetmask:
break;
case SYS_ssetmask:
/*
 *         int newmask;
 */
break;
case SYS_signal:
/*
 *         int sig;
 *         __sighandler_t handler;
 */
break;
case SYS_pause:
break;
case SYS_sync:
break;
case SYS_fsync:
/*
 *         unsigned int fd;
 */
break;
case SYS_fdatasync:
/*
 *         unsigned int fd;
 */
break;
case SYS_bdflush:
/*
 *         int func;
 *         long data;
 */
break;
case SYS_mount:
/*
 *         char __user * dev_name;
 *         char __user * dir_name;
 *         char __user * type;
 *         unsigned long flags;
 *         void __user * data;
 */
unsafe_copy_zts(dev_name);
unsafe_copy_zts(dir_name);
unsafe_copy_zts(type);
copy_buf(syscall_arg[5], sizeof(void)); // data
break;
case SYS_umount:
/*
 *         char __user * name;
 *         int flags;
 */
unsafe_copy_zts(name);
break;
case SYS_oldumount:
/*
 *         char __user * name;
 */
unsafe_copy_zts(name);
break;
case SYS_truncate:
/*
 *         const char __user * path;
 *         long length;
 */
unsafe_copy_zts(path);
break;
case SYS_ftruncate:
/*
 *         unsigned int fd;
 *         unsigned long length;
 */
break;
case SYS_stat:
/*
 *         const char __user * filename;
 *         struct __old_kernel_stat __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct __old_kernel_stat)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_statfs:
/*
 *         const char __user * path;
 *         struct statfs __user * buf;
 */
unsafe_copy_zts(path);
copy_buf(syscall_arg[2], sizeof(struct statfs)); // buf
break;
case SYS_statfs64:
/*
 *         const char __user * path;
 *         size_t sz;
 *         struct statfs64 __user * buf;
 */
unsafe_copy_zts(path);
copy_buf(syscall_arg[3], sizeof(struct statfs64)); // buf
undefined semantics for struct buf
break;
case SYS_fstatfs:
/*
 *         unsigned int fd;
 *         struct statfs __user * buf;
 */
copy_buf(syscall_arg[2], sizeof(struct statfs)); // buf
break;
case SYS_fstatfs64:
/*
 *         unsigned int fd;
 *         size_t sz;
 *         struct statfs64 __user * buf;
 */
copy_buf(syscall_arg[3], sizeof(struct statfs64)); // buf
undefined semantics for struct buf
break;
case SYS_lstat:
/*
 *         const char __user * filename;
 *         struct __old_kernel_stat __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct __old_kernel_stat)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_fstat:
/*
 *         unsigned int fd;
 *         struct __old_kernel_stat __user * statbuf;
 */
copy_buf(syscall_arg[2], sizeof(struct __old_kernel_stat)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_newstat:
/*
 *         const char __user * filename;
 *         struct stat __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct stat)); // statbuf
break;
case SYS_newlstat:
/*
 *         const char __user * filename;
 *         struct stat __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct stat)); // statbuf
break;
case SYS_newfstat:
/*
 *         unsigned int fd;
 *         struct stat __user * statbuf;
 */
copy_buf(syscall_arg[2], sizeof(struct stat)); // statbuf
break;
case SYS_ustat:
/*
 *         unsigned dev ;
 *         struct ustat __user * ubuf;
 */
copy_buf(syscall_arg[2], sizeof(struct ustat)); // ubuf
undefined semantics for struct ubuf
break;
case SYS_stat64:
/*
 *         const char __user * filename;
 *         struct stat64 __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct stat64)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_fstat64:
/*
 *         unsigned long fd;
 *         struct stat64 __user * statbuf;
 */
copy_buf(syscall_arg[2], sizeof(struct stat64)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_lstat64:
/*
 *         const char __user * filename;
 *         struct stat64 __user * statbuf;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct stat64)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_truncate64:
/*
 *         const char __user * path;
 *         loff_t length;
 */
unsafe_copy_zts(path);
break;
case SYS_ftruncate64:
/*
 *         unsigned int fd;
 *         loff_t length;
 */
break;
case SYS_setxattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 *         const void __user * value;
 *         size_t size;
 *         int flags;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_lsetxattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 *         const void __user * value;
 *         size_t size;
 *         int flags;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_fsetxattr:
/*
 *         int fd;
 *         const char __user * name;
 *         const void __user * value;
 *         size_t size;
 *         int flags;
 */
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_getxattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 *         void __user * value;
 *         size_t size;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_lgetxattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 *         void __user * value;
 *         size_t size;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_fgetxattr:
/*
 *         int fd;
 *         const char __user * name;
 *         void __user * value;
 *         size_t size;
 */
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(void)); // value
break;
case SYS_listxattr:
/*
 *         const char __user * path;
 *         char __user * list;
 *         size_t size;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(list);
break;
case SYS_llistxattr:
/*
 *         const char __user * path;
 *         char __user * list;
 *         size_t size;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(list);
break;
case SYS_flistxattr:
/*
 *         int fd;
 *         char __user * list;
 *         size_t size;
 */
unsafe_copy_zts(list);
break;
case SYS_removexattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
break;
case SYS_lremovexattr:
/*
 *         const char __user * path;
 *         const char __user * name;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(name);
break;
case SYS_fremovexattr:
/*
 *         int fd;
 *         const char __user * name;
 */
unsafe_copy_zts(name);
break;
case SYS_brk:
/*
 *         unsigned long brk;
 */
break;
case SYS_mprotect:
/*
 *         unsigned long start;
 *         size_t len;
 *         unsigned long prot;
 */
break;
case SYS_mremap:
/*
 *         unsigned long addr;
 *         unsigned long old_len;
 *         unsigned long new_len;
 *         unsigned long flags;
 *         unsigned long new_addr;
 */
break;
case SYS_remap_file_pages:
/*
 *         unsigned long start;
 *         unsigned long size;
 *         unsigned long prot;
 *         unsigned long pgoff;
 *         unsigned long flags;
 */
break;
case SYS_msync:
/*
 *         unsigned long start;
 *         size_t len;
 *         int flags;
 */
break;
case SYS_fadvise64:
/*
 *         int fd;
 *         loff_t offset;
 *         size_t len;
 *         int advice;
 */
break;
case SYS_fadvise64_64:
/*
 *         int fd;
 *         loff_t offset;
 *         loff_t len;
 *         int advice;
 */
break;
case SYS_munmap:
/*
 *         unsigned long addr;
 *         size_t len;
 */
break;
case SYS_mlock:
/*
 *         unsigned long start;
 *         size_t len;
 */
break;
case SYS_munlock:
/*
 *         unsigned long start;
 *         size_t len;
 */
break;
case SYS_mlockall:
/*
 *         int flags;
 */
break;
case SYS_munlockall:
break;
case SYS_madvise:
/*
 *         unsigned long start;
 *         size_t len;
 *         int behavior;
 */
break;
case SYS_mincore:
/*
 *         unsigned long start;
 *         size_t len;
 *         unsigned char __user * vec;
 */
unsafe_copy_zts(vec);
break;
case SYS_pivot_root:
/*
 *         const char __user * new_root;
 *         const char __user * put_old;
 */
unsafe_copy_zts(new_root);
unsafe_copy_zts(put_old);
break;
case SYS_chroot:
/*
 *         const char __user * filename;
 */
unsafe_copy_zts(filename);
break;
case SYS_mknod:
/*
 *         const char __user * filename;
 *         int mode;
 *         unsigned dev ;
 */
unsafe_copy_zts(filename);
break;
case SYS_link:
/*
 *         const char __user * oldname;
 *         const char __user * newname;
 */
unsafe_copy_zts(oldname);
unsafe_copy_zts(newname);
break;
case SYS_symlink:
/*
 *         const char __user * old;
 *         const char __user * new;
 */
unsafe_copy_zts(old);
unsafe_copy_zts(new);
break;
case SYS_unlink:
/*
 *         const char __user * pathname;
 */
unsafe_copy_zts(pathname);
break;
case SYS_rename:
/*
 *         const char __user * oldname;
 *         const char __user * newname;
 */
unsafe_copy_zts(oldname);
unsafe_copy_zts(newname);
break;
case SYS_chmod:
/*
 *         const char __user * filename;
 *         mode_t mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchmod:
/*
 *         unsigned int fd;
 *         mode_t mode;
 */
break;
case SYS_fcntl:
/*
 *         unsigned int fd;
 *         unsigned int cmd;
 *         unsigned long arg;
 */
break;
case SYS_fcntl64:
/*
 *         unsigned int fd;
 *         unsigned int cmd;
 *         unsigned long arg;
 */
break;
case SYS_pipe:
/*
 *         int __user * fildes;
 */
copy_buf(syscall_arg[1], sizeof(int)); // fildes
break;
case SYS_pipe2:
/*
 *         int __user * fildes;
 *         int flags;
 */
copy_buf(syscall_arg[1], sizeof(int)); // fildes
break;
case SYS_dup:
/*
 *         unsigned int fildes;
 */
break;
case SYS_dup2:
/*
 *         unsigned int oldfd;
 *         unsigned int newfd;
 */
break;
case SYS_dup3:
/*
 *         unsigned int oldfd;
 *         unsigned int newfd;
 *         int flags;
 */
break;
case SYS_ioperm:
/*
 *         unsigned long from;
 *         unsigned long num;
 *         int on;
 */
break;
case SYS_ioctl:
/*
 *         unsigned int fd;
 *         unsigned int cmd;
 *         unsigned long arg;
 */
break;
case SYS_flock:
/*
 *         unsigned int fd;
 *         unsigned int cmd;
 */
break;
case SYS_io_setup:
/*
 *         unsigned nr_reqs ;
 *         aio_context_t __user * ctx;
 */
copy_buf(syscall_arg[2], sizeof(aio_context_t)); // ctx
break;
case SYS_io_destroy:
/*
 *         aio_context_t ctx;
 */
break;
case SYS_io_getevents:
/*
 *         aio_context_t ctx_id;
 *         long min_nr;
 *         long nr;
 *         struct io_event __user * events;
 *         struct timespec __user * timeout;
 */
copy_buf(syscall_arg[4], sizeof(struct io_event)); // events
undefined semantics for struct events
copy_buf(syscall_arg[5], sizeof(struct timespec)); // timeout
break;
case SYS_io_submit:
/*
 *         aio_context_t ;
 *         long ;
 *         struct iocb __user * __user * ;
 */
copy_buf(syscall_arg[3], sizeof(struct iocb)); //
undefined semantics for struct
break;
case SYS_io_cancel:
/*
 *         aio_context_t ctx_id;
 *         struct iocb __user * iocb;
 *         struct io_event __user * result;
 */
copy_buf(syscall_arg[2], sizeof(struct iocb)); // iocb
undefined semantics for struct iocb
copy_buf(syscall_arg[3], sizeof(struct io_event)); // result
undefined semantics for struct result
break;
case SYS_sendfile:
/*
 *         int out_fd;
 *         int in_fd;
 *         off_t __user * offset;
 *         size_t count;
 */
copy_buf(syscall_arg[3], sizeof(off_t)); // offset
break;
case SYS_sendfile64:
/*
 *         int out_fd;
 *         int in_fd;
 *         loff_t __user * offset;
 *         size_t count;
 */
copy_buf(syscall_arg[3], sizeof(loff_t)); // offset
break;
case SYS_readlink:
/*
 *         const char __user * path;
 *         char __user * buf;
 *         int bufsiz;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(buf);
break;
case SYS_creat:
/*
 *         const char __user * pathname;
 *         int mode;
 */
unsafe_copy_zts(pathname);
break;
case SYS_open:
/*
 *         const char __user * filename;
 *         int flags;
 *         int mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_close:
/*
 *         unsigned int fd;
 */
break;
case SYS_access:
/*
 *         const char __user * filename;
 *         int mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_vhangup:
break;
case SYS_chown:
/*
 *         const char __user * filename;
 *         uid_t user;
 *         gid_t group;
 */
unsafe_copy_zts(filename);
break;
case SYS_lchown:
/*
 *         const char __user * filename;
 *         uid_t user;
 *         gid_t group;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchown:
/*
 *         unsigned int fd;
 *         uid_t user;
 *         gid_t group;
 */
break;
case SYS_chown16:
/*
 *         const char __user * filename;
 *         old_uid_t user;
 *         old_gid_t group;
 */
unsafe_copy_zts(filename);
break;
case SYS_lchown16:
/*
 *         const char __user * filename;
 *         old_uid_t user;
 *         old_gid_t group;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchown16:
/*
 *         unsigned int fd;
 *         old_uid_t user;
 *         old_gid_t group;
 */
break;
case SYS_setregid16:
/*
 *         old_gid_t rgid;
 *         old_gid_t egid;
 */
break;
case SYS_setgid16:
/*
 *         old_gid_t gid;
 */
break;
case SYS_setreuid16:
/*
 *         old_uid_t ruid;
 *         old_uid_t euid;
 */
break;
case SYS_setuid16:
/*
 *         old_uid_t uid;
 */
break;
case SYS_setresuid16:
/*
 *         old_uid_t ruid;
 *         old_uid_t euid;
 *         old_uid_t suid;
 */
break;
case SYS_getresuid16:
/*
 *         old_uid_t __user * ruid;
 *         old_uid_t __user * euid;
 *         old_uid_t __user * suid;
 */
copy_buf(syscall_arg[1], sizeof(old_uid_t)); // ruid
copy_buf(syscall_arg[2], sizeof(old_uid_t)); // euid
copy_buf(syscall_arg[3], sizeof(old_uid_t)); // suid
break;
case SYS_setresgid16:
/*
 *         old_gid_t rgid;
 *         old_gid_t egid;
 *         old_gid_t sgid;
 */
break;
case SYS_getresgid16:
/*
 *         old_gid_t __user * rgid;
 *         old_gid_t __user * egid;
 *         old_gid_t __user * sgid;
 */
copy_buf(syscall_arg[1], sizeof(old_gid_t)); // rgid
copy_buf(syscall_arg[2], sizeof(old_gid_t)); // egid
copy_buf(syscall_arg[3], sizeof(old_gid_t)); // sgid
break;
case SYS_setfsuid16:
/*
 *         old_uid_t uid;
 */
break;
case SYS_setfsgid16:
/*
 *         old_gid_t gid;
 */
break;
case SYS_getgroups16:
/*
 *         int gidsetsize;
 *         old_gid_t __user * grouplist;
 */
copy_buf(syscall_arg[2], sizeof(old_gid_t)); // grouplist
break;
case SYS_setgroups16:
/*
 *         int gidsetsize;
 *         old_gid_t __user * grouplist;
 */
copy_buf(syscall_arg[2], sizeof(old_gid_t)); // grouplist
break;
case SYS_getuid16:
break;
case SYS_geteuid16:
break;
case SYS_getgid16:
break;
case SYS_getegid16:
break;
case SYS_utime:
/*
 *         char __user * filename;
 *         struct utimbuf __user * times;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct utimbuf)); // times
break;
case SYS_utimes:
/*
 *         char __user * filename;
 *         struct timeval __user * utimes;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[2], sizeof(struct timeval)); // utimes
break;
case SYS_lseek:
/*
 *         unsigned int fd;
 *         off_t offset;
 *         unsigned int origin;
 */
break;
case SYS_llseek:
/*
 *         unsigned int fd;
 *         unsigned long offset_high;
 *         unsigned long offset_low;
 *         loff_t __user * result;
 *         unsigned int origin;
 */
copy_buf(syscall_arg[4], sizeof(loff_t)); // result
break;
case SYS_read:
/*
 *         unsigned int fd;
 *         char __user * buf;
 *         size_t count;
 */
unsafe_copy_zts(buf);
break;
case SYS_readahead:
/*
 *         int fd;
 *         loff_t offset;
 *         size_t count;
 */
break;
case SYS_readv:
/*
 *         unsigned long fd;
 *         const struct iovec __user * vec;
 *         unsigned long vlen;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // vec
rec_copy_struct(vec);
break;
case SYS_write:
/*
 *         unsigned int fd;
 *         const char __user * buf;
 *         size_t count;
 */
unsafe_copy_zts(buf);
break;
case SYS_writev:
/*
 *         unsigned long fd;
 *         const struct iovec __user * vec;
 *         unsigned long vlen;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // vec
rec_copy_struct(vec);
break;
case SYS_pread64:
/*
 *         unsigned int fd;
 *         char __user * buf;
 *         size_t count;
 *         loff_t pos;
 */
unsafe_copy_zts(buf);
break;
case SYS_pwrite64:
/*
 *         unsigned int fd;
 *         const char __user * buf;
 *         size_t count;
 *         loff_t pos;
 */
unsafe_copy_zts(buf);
break;
case SYS_preadv:
/*
 *         unsigned long fd;
 *         const struct iovec __user * vec;
 *         unsigned long vlen;
 *         unsigned long pos_l;
 *         unsigned long pos_h;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // vec
rec_copy_struct(vec);
break;
case SYS_pwritev:
/*
 *         unsigned long fd;
 *         const struct iovec __user * vec;
 *         unsigned long vlen;
 *         unsigned long pos_l;
 *         unsigned long pos_h;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // vec
rec_copy_struct(vec);
break;
case SYS_getcwd:
/*
 *         char __user * buf;
 *         unsigned long size;
 */
unsafe_copy_zts(buf);
break;
case SYS_mkdir:
/*
 *         const char __user * pathname;
 *         int mode;
 */
unsafe_copy_zts(pathname);
break;
case SYS_chdir:
/*
 *         const char __user * filename;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchdir:
/*
 *         unsigned int fd;
 */
break;
case SYS_rmdir:
/*
 *         const char __user * pathname;
 */
unsafe_copy_zts(pathname);
break;
case SYS_lookup_dcookie:
/*
 *         u64 cookie64;
 *         char __user * buf;
 *         size_t len;
 */
unsafe_copy_zts(buf);
break;
case SYS_quotactl:
/*
 *         unsigned int cmd;
 *         const char __user * special;
 *         qid_t id;
 *         void __user * addr;
 */
unsafe_copy_zts(special);
copy_buf(syscall_arg[4], sizeof(void)); // addr
break;
case SYS_getdents:
/*
 *         unsigned int fd;
 *         struct linux_dirent __user * dirent;
 *         unsigned int count;
 */
copy_buf(syscall_arg[2], sizeof(struct linux_dirent)); // dirent
rec_copy_struct(dirent);
break;
case SYS_getdents64:
/*
 *         unsigned int fd;
 *         struct linux_dirent64 __user * dirent;
 *         unsigned int count;
 */
copy_buf(syscall_arg[2], sizeof(struct linux_dirent64)); // dirent
undefined semantics for struct dirent
break;
case SYS_setsockopt:
/*
 *         int fd;
 *         int level;
 *         int optname;
 *         char __user * optval;
 *         int optlen;
 */
unsafe_copy_zts(optval);
break;
case SYS_getsockopt:
/*
 *         int fd;
 *         int level;
 *         int optname;
 *         char __user * optval;
 *         int __user * optlen;
 */
unsafe_copy_zts(optval);
copy_buf(syscall_arg[5], sizeof(int)); // optlen
break;
case SYS_bind:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
break;
case SYS_connect:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
break;
case SYS_accept:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int __user * ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
copy_buf(syscall_arg[3], sizeof(int)); //
break;
case SYS_accept4:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int __user * ;
 *         int ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
copy_buf(syscall_arg[3], sizeof(int)); //
break;
case SYS_getsockname:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int __user * ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
copy_buf(syscall_arg[3], sizeof(int)); //
break;
case SYS_getpeername:
/*
 *         int ;
 *         struct sockaddr __user * ;
 *         int __user * ;
 */
copy_buf(syscall_arg[2], sizeof(struct sockaddr)); //
copy_buf(syscall_arg[3], sizeof(int)); //
break;
case SYS_sendmsg:
/*
 *         int fd;
 *         struct msghdr __user * msg;
 *         unsigned flags ;
 */
copy_buf(syscall_arg[2], sizeof(struct msghdr)); // msg
rec_copy_struct(msg);
break;
case SYS_sendmmsg:
/*
 *         int fd;
 *         struct mmsghdr __user * msg;
 *         unsigned int vlen;
 *         unsigned flags ;
 */
copy_buf(syscall_arg[2], sizeof(struct mmsghdr)); // msg
rec_copy_struct(msg);
break;
case SYS_recvmsg:
/*
 *         int fd;
 *         struct msghdr __user * msg;
 *         unsigned flags ;
 */
copy_buf(syscall_arg[2], sizeof(struct msghdr)); // msg
rec_copy_struct(msg);
break;
case SYS_recvmmsg:
/*
 *         int fd;
 *         struct mmsghdr __user * msg;
 *         unsigned int vlen;
 *         unsigned flags ;
 *         struct timespec __user * timeout;
 */
copy_buf(syscall_arg[2], sizeof(struct mmsghdr)); // msg
rec_copy_struct(msg);
copy_buf(syscall_arg[5], sizeof(struct timespec)); // timeout
break;
case SYS_socket:
/*
 *         int ;
 *         int ;
 *         int ;
 */
break;
case SYS_socketpair:
/*
 *         int ;
 *         int ;
 *         int ;
 *         int __user * ;
 */
copy_buf(syscall_arg[4], sizeof(int)); //
break;
case SYS_socketcall:
/*
 *         int call;
 *         unsigned long __user * args;
 */
copy_buf(syscall_arg[2], sizeof(long)); // args
break;
case SYS_listen:
/*
 *         int ;
 *         int ;
 */
break;
case SYS_poll:
/*
 *         struct pollfd __user * ufds;
 *         unsigned int nfds;
 *         long timeout;
 */
copy_buf(syscall_arg[1], sizeof(struct pollfd)); // ufds
break;
case SYS_select:
/*
 *         int n;
 *         fd_set __user * inp;
 *         fd_set __user * outp;
 *         fd_set __user * exp;
 *         struct timeval __user * tvp;
 */
copy_buf(syscall_arg[2], sizeof(fd_set)); // inp
copy_buf(syscall_arg[3], sizeof(fd_set)); // outp
copy_buf(syscall_arg[4], sizeof(fd_set)); // exp
copy_buf(syscall_arg[5], sizeof(struct timeval)); // tvp
break;
case SYS_old_select:
/*
 *         struct sel_arg_struct __user * arg;
 */
copy_buf(syscall_arg[1], sizeof(struct sel_arg_struct)); // arg
undefined semantics for struct arg
break;
case SYS_epoll_create:
/*
 *         int size;
 */
break;
case SYS_epoll_create1:
/*
 *         int flags;
 */
break;
case SYS_epoll_ctl:
/*
 *         int epfd;
 *         int op;
 *         int fd;
 *         struct epoll_event __user * event;
 */
copy_buf(syscall_arg[4], sizeof(struct epoll_event)); // event
rec_copy_struct(event);
break;
case SYS_epoll_wait:
/*
 *         int epfd;
 *         struct epoll_event __user * events;
 *         int maxevents;
 *         int timeout;
 */
copy_buf(syscall_arg[2], sizeof(struct epoll_event)); // events
rec_copy_struct(events);
break;
case SYS_epoll_pwait:
/*
 *         int epfd;
 *         struct epoll_event __user * events;
 *         int maxevents;
 *         int timeout;
 *         const sigset_t __user * sigmask;
 *         size_t sigsetsize;
 */
copy_buf(syscall_arg[2], sizeof(struct epoll_event)); // events
rec_copy_struct(events);
copy_buf(syscall_arg[5], sizeof(sigset_t)); // sigmask
break;
case SYS_gethostname:
/*
 *         char __user * name;
 *         int len;
 */
unsafe_copy_zts(name);
break;
case SYS_sethostname:
/*
 *         char __user * name;
 *         int len;
 */
unsafe_copy_zts(name);
break;
case SYS_setdomainname:
/*
 *         char __user * name;
 *         int len;
 */
unsafe_copy_zts(name);
break;
case SYS_newuname:
/*
 *         struct new_utsname __user * name;
 */
copy_buf(syscall_arg[1], sizeof(struct new_utsname)); // name
undefined semantics for struct name
break;
case SYS_uname:
/*
 *         struct old_utsname __user * ;
 */
copy_buf(syscall_arg[1], sizeof(struct old_utsname)); //
undefined semantics for struct
break;
case SYS_olduname:
/*
 *         struct oldold_utsname __user * ;
 */
copy_buf(syscall_arg[1], sizeof(struct oldold_utsname)); //
undefined semantics for struct
break;
case SYS_getrlimit:
/*
 *         unsigned int resource;
 *         struct rlimit __user * rlim;
 */
copy_buf(syscall_arg[2], sizeof(struct rlimit)); // rlim
break;
case SYS_old_getrlimit:
/*
 *         unsigned int resource;
 *         struct rlimit __user * rlim;
 */
copy_buf(syscall_arg[2], sizeof(struct rlimit)); // rlim
break;
case SYS_setrlimit:
/*
 *         unsigned int resource;
 *         struct rlimit __user * rlim;
 */
copy_buf(syscall_arg[2], sizeof(struct rlimit)); // rlim
break;
case SYS_prlimit64:
/*
 *         pid_t pid;
 *         unsigned int resource;
 *         const struct rlimit64 __user * new_rlim;
 *         struct rlimit64 __user * old_rlim;
 */
copy_buf(syscall_arg[3], sizeof(struct rlimit64)); // new_rlim
undefined semantics for struct new_rlim
copy_buf(syscall_arg[4], sizeof(struct rlimit64)); // old_rlim
undefined semantics for struct old_rlim
break;
case SYS_getrusage:
/*
 *         int who;
 *         struct rusage __user * ru;
 */
copy_buf(syscall_arg[2], sizeof(struct rusage)); // ru
break;
case SYS_umask:
/*
 *         int mask;
 */
break;
case SYS_msgget:
/*
 *         key_t key;
 *         int msgflg;
 */
break;
case SYS_msgsnd:
/*
 *         int msqid;
 *         struct msgbuf __user * msgp;
 *         size_t msgsz;
 *         int msgflg;
 */
copy_buf(syscall_arg[2], sizeof(struct msgbuf)); // msgp
rec_copy_struct(msgp);
break;
case SYS_msgrcv:
/*
 *         int msqid;
 *         struct msgbuf __user * msgp;
 *         size_t msgsz;
 *         long msgtyp;
 *         int msgflg;
 */
copy_buf(syscall_arg[2], sizeof(struct msgbuf)); // msgp
rec_copy_struct(msgp);
break;
case SYS_msgctl:
/*
 *         int msqid;
 *         int cmd;
 *         struct msqid_ds __user * buf;
 */
copy_buf(syscall_arg[3], sizeof(struct msqid_ds)); // buf
break;
case SYS_semget:
/*
 *         key_t key;
 *         int nsems;
 *         int semflg;
 */
break;
case SYS_semop:
/*
 *         int semid;
 *         struct sembuf __user * sops;
 *         unsigned nsops ;
 */
copy_buf(syscall_arg[2], sizeof(struct sembuf)); // sops
undefined semantics for struct sops
break;
case SYS_semtimedop:
/*
 *         int semid;
 *         struct sembuf __user * sops;
 *         unsigned nsops ;
 *         const struct timespec __user * timeout;
 */
copy_buf(syscall_arg[2], sizeof(struct sembuf)); // sops
undefined semantics for struct sops
copy_buf(syscall_arg[4], sizeof(struct timespec)); // timeout
break;
case SYS_shmat:
/*
 *         int shmid;
 *         char __user * shmaddr;
 *         int shmflg;
 */
unsafe_copy_zts(shmaddr);
break;
case SYS_shmget:
/*
 *         key_t key;
 *         size_t size;
 *         int flag;
 */
break;
case SYS_shmdt:
/*
 *         char __user * shmaddr;
 */
unsafe_copy_zts(shmaddr);
break;
case SYS_shmctl:
/*
 *         int shmid;
 *         int cmd;
 *         struct shmid_ds __user * buf;
 */
copy_buf(syscall_arg[3], sizeof(struct shmid_ds)); // buf
undefined semantics for struct buf
break;
case SYS_ipc:
/*
 *         unsigned int call;
 *         int first;
 *         unsigned long second;
 *         unsigned long third;
 *         void __user * ptr;
 *         long fifth;
 */
copy_buf(syscall_arg[5], sizeof(void)); // ptr
break;
case SYS_mq_open:
/*
 *         const char __user * name;
 *         int oflag;
 *         mode_t mode;
 *         struct mq_attr __user * attr;
 */
unsafe_copy_zts(name);
copy_buf(syscall_arg[4], sizeof(struct mq_attr)); // attr
undefined semantics for struct attr
break;
case SYS_mq_unlink:
/*
 *         const char __user * name;
 */
unsafe_copy_zts(name);
break;
case SYS_mq_timedsend:
/*
 *         mqd_t mqdes;
 *         const char __user * msg_ptr;
 *         size_t msg_len;
 *         unsigned int msg_prio;
 *         const struct timespec __user * abs_timeout;
 */
unsafe_copy_zts(msg_ptr);
copy_buf(syscall_arg[5], sizeof(struct timespec)); // abs_timeout
break;
case SYS_mq_timedreceive:
/*
 *         mqd_t mqdes;
 *         char __user * msg_ptr;
 *         size_t msg_len;
 *         unsigned int __user * msg_prio;
 *         const struct timespec __user * abs_timeout;
 */
unsafe_copy_zts(msg_ptr);
copy_buf(syscall_arg[4], sizeof(int)); // msg_prio
copy_buf(syscall_arg[5], sizeof(struct timespec)); // abs_timeout
break;
case SYS_mq_notify:
/*
 *         mqd_t mqdes;
 *         const struct sigevent __user * notification;
 */
copy_buf(syscall_arg[2], sizeof(struct sigevent)); // notification
rec_copy_struct(notification);
break;
case SYS_mq_getsetattr:
/*
 *         mqd_t mqdes;
 *         const struct mq_attr __user * mqstat;
 *         struct mq_attr __user * omqstat;
 */
copy_buf(syscall_arg[2], sizeof(struct mq_attr)); // mqstat
undefined semantics for struct mqstat
copy_buf(syscall_arg[3], sizeof(struct mq_attr)); // omqstat
undefined semantics for struct omqstat
break;
case SYS_pciconfig_iobase:
/*
 *         long which;
 *         unsigned long bus;
 *         unsigned long devfn;
 */
break;
case SYS_pciconfig_read:
/*
 *         unsigned long bus;
 *         unsigned long dfn;
 *         unsigned long off;
 *         unsigned long len;
 *         void __user * buf;
 */
copy_buf(syscall_arg[5], sizeof(void)); // buf
break;
case SYS_pciconfig_write:
/*
 *         unsigned long bus;
 *         unsigned long dfn;
 *         unsigned long off;
 *         unsigned long len;
 *         void __user * buf;
 */
copy_buf(syscall_arg[5], sizeof(void)); // buf
break;
case SYS_prctl:
/*
 *         int option;
 *         unsigned long arg2;
 *         unsigned long arg3;
 *         unsigned long arg4;
 *         unsigned long arg5;
 */
break;
case SYS_swapon:
/*
 *         const char __user * specialfile;
 *         int swap_flags;
 */
unsafe_copy_zts(specialfile);
break;
case SYS_swapoff:
/*
 *         const char __user * specialfile;
 */
unsafe_copy_zts(specialfile);
break;
case SYS_sysctl:
/*
 *         struct __sysctl_args __user * args;
 */
copy_buf(syscall_arg[1], sizeof(struct __sysctl_args)); // args
rec_copy_struct(args);
break;
case SYS_sysinfo:
/*
 *         struct sysinfo __user * info;
 */
copy_buf(syscall_arg[1], sizeof(struct sysinfo)); // info
break;
case SYS_sysfs:
/*
 *         int option;
 *         unsigned long arg1;
 *         unsigned long arg2;
 */
break;
case SYS_syslog:
/*
 *         int type;
 *         char __user * buf;
 *         int len;
 */
unsafe_copy_zts(buf);
break;
case SYS_uselib:
/*
 *         const char __user * library;
 */
unsafe_copy_zts(library);
break;
case SYS_ni_syscall:
break;
case SYS_ptrace:
/*
 *         long request;
 *         long pid;
 *         unsigned long addr;
 *         unsigned long data;
 */
break;
case SYS_add_key:
/*
 *         const char __user * _type;
 *         const char __user * _description;
 *         const void __user * _payload;
 *         size_t plen;
 *         key_serial_t destringid;
 */
unsafe_copy_zts(_type);
unsafe_copy_zts(_description);
copy_buf(syscall_arg[3], sizeof(void)); // _payload
break;
case SYS_request_key:
/*
 *         const char __user * _type;
 *         const char __user * _description;
 *         const char __user * _callout_info;
 *         key_serial_t destringid;
 */
unsafe_copy_zts(_type);
unsafe_copy_zts(_description);
unsafe_copy_zts(_callout_info);
break;
case SYS_keyctl:
/*
 *         int cmd;
 *         unsigned long arg2;
 *         unsigned long arg3;
 *         unsigned long arg4;
 *         unsigned long arg5;
 */
break;
case SYS_ioprio_set:
/*
 *         int which;
 *         int who;
 *         int ioprio;
 */
break;
case SYS_ioprio_get:
/*
 *         int which;
 *         int who;
 */
break;
case SYS_set_mempolicy:
/*
 *         int mode;
 *         unsigned long __user * nmask;
 *         unsigned long maxnode;
 */
copy_buf(syscall_arg[2], sizeof(long)); // nmask
break;
case SYS_migrate_pages:
/*
 *         pid_t pid;
 *         unsigned long maxnode;
 *         const unsigned long __user * from;
 *         const unsigned long __user * to;
 */
copy_buf(syscall_arg[3], sizeof(long)); // from
copy_buf(syscall_arg[4], sizeof(long)); // to
break;
case SYS_move_pages:
/*
 *         pid_t pid;
 *         unsigned long nr_pages;
 *         const void __user * __user * pages;
 *         const int __user * nodes;
 *         int __user * status;
 *         int flags;
 */
copy_buf(syscall_arg[3], sizeof(void)); // pages
copy_buf(syscall_arg[4], sizeof(int)); // nodes
copy_buf(syscall_arg[5], sizeof(int)); // status
break;
case SYS_mbind:
/*
 *         unsigned long start;
 *         unsigned long len;
 *         unsigned long mode;
 *         unsigned long __user * nmask;
 *         unsigned long maxnode;
 *         unsigned flags ;
 */
copy_buf(syscall_arg[4], sizeof(long)); // nmask
break;
case SYS_get_mempolicy:
/*
 *         int __user * policy;
 *         unsigned long __user * nmask;
 *         unsigned long maxnode;
 *         unsigned long addr;
 *         unsigned long flags;
 */
copy_buf(syscall_arg[1], sizeof(int)); // policy
copy_buf(syscall_arg[2], sizeof(long)); // nmask
break;
case SYS_inotify_init:
break;
case SYS_inotify_init1:
/*
 *         int flags;
 */
break;
case SYS_inotify_add_watch:
/*
 *         int fd;
 *         const char __user * path;
 *         u32 mask;
 */
unsafe_copy_zts(path);
break;
case SYS_inotify_rm_watch:
/*
 *         int fd;
 *         __s32 wd;
 */
break;
case SYS_spu_run:
/*
 *         int fd;
 *         __u32 __user * unpc;
 *         __u32 __user * ustatus;
 */
copy_buf(syscall_arg[2], sizeof(__u32)); // unpc
copy_buf(syscall_arg[3], sizeof(__u32)); // ustatus
break;
case SYS_spu_create:
/*
 *         const char __user * name;
 *         unsigned int flags;
 *         mode_t mode;
 *         int fd;
 */
unsafe_copy_zts(name);
break;
case SYS_mknodat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         int mode;
 *         unsigned dev ;
 */
unsafe_copy_zts(filename);
break;
case SYS_mkdirat:
/*
 *         int dfd;
 *         const char __user * pathname;
 *         int mode;
 */
unsafe_copy_zts(pathname);
break;
case SYS_unlinkat:
/*
 *         int dfd;
 *         const char __user * pathname;
 *         int flag;
 */
unsafe_copy_zts(pathname);
break;
case SYS_symlinkat:
/*
 *         const char __user * oldname;
 *         int newdfd;
 *         const char __user * newname;
 */
unsafe_copy_zts(oldname);
unsafe_copy_zts(newname);
break;
case SYS_linkat:
/*
 *         int olddfd;
 *         const char __user * oldname;
 *         int newdfd;
 *         const char __user * newname;
 *         int flags;
 */
unsafe_copy_zts(oldname);
unsafe_copy_zts(newname);
break;
case SYS_renameat:
/*
 *         int olddfd;
 *         const char __user * oldname;
 *         int newdfd;
 *         const char __user * newname;
 */
unsafe_copy_zts(oldname);
unsafe_copy_zts(newname);
break;
case SYS_futimesat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         struct timeval __user * utimes;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[3], sizeof(struct timeval)); // utimes
break;
case SYS_faccessat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         int mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchmodat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         mode_t mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_fchownat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         uid_t user;
 *         gid_t group;
 *         int flag;
 */
unsafe_copy_zts(filename);
break;
case SYS_openat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         int flags;
 *         int mode;
 */
unsafe_copy_zts(filename);
break;
case SYS_newfstatat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         struct stat __user * statbuf;
 *         int flag;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[3], sizeof(struct stat)); // statbuf
break;
case SYS_fstatat64:
/*
 *         int dfd;
 *         const char __user * filename;
 *         struct stat64 __user * statbuf;
 *         int flag;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[3], sizeof(struct stat64)); // statbuf
undefined semantics for struct statbuf
break;
case SYS_readlinkat:
/*
 *         int dfd;
 *         const char __user * path;
 *         char __user * buf;
 *         int bufsiz;
 */
unsafe_copy_zts(path);
unsafe_copy_zts(buf);
break;
case SYS_utimensat:
/*
 *         int dfd;
 *         const char __user * filename;
 *         struct timespec __user * utimes;
 *         int flags;
 */
unsafe_copy_zts(filename);
copy_buf(syscall_arg[3], sizeof(struct timespec)); // utimes
break;
case SYS_unshare:
/*
 *         unsigned long unshare_flags;
 */
break;
case SYS_splice:
/*
 *         int fd_in;
 *         loff_t __user * off_in;
 *         int fd_out;
 *         loff_t __user * off_out;
 *         size_t len;
 *         unsigned int flags;
 */
copy_buf(syscall_arg[2], sizeof(loff_t)); // off_in
copy_buf(syscall_arg[4], sizeof(loff_t)); // off_out
break;
case SYS_vmsplice:
/*
 *         int fd;
 *         const struct iovec __user * iov;
 *         unsigned long nr_segs;
 *         unsigned int flags;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // iov
rec_copy_struct(iov);
break;
case SYS_tee:
/*
 *         int fdin;
 *         int fdout;
 *         size_t len;
 *         unsigned int flags;
 */
break;
case SYS_sync_file_range:
/*
 *         int fd;
 *         loff_t offset;
 *         loff_t nbytes;
 *         unsigned int flags;
 */
break;
case SYS_sync_file_range2:
/*
 *         int fd;
 *         unsigned int flags;
 *         loff_t offset;
 *         loff_t nbytes;
 */
break;
case SYS_get_robust_list:
/*
 *         int pid;
 *         struct robust_list_head __user * __user * head_ptr;
 *         size_t __user * len_ptr;
 */
copy_buf(syscall_arg[2], sizeof(struct robust_list_head)); // head_ptr
undefined semantics for struct head_ptr
copy_buf(syscall_arg[3], sizeof(size_t)); // len_ptr
break;
case SYS_set_robust_list:
/*
 *         struct robust_list_head __user * head;
 *         size_t len;
 */
copy_buf(syscall_arg[1], sizeof(struct robust_list_head)); // head
undefined semantics for struct head
break;
case SYS_getcpu:
/*
 *         unsigned __user * cpu;
 *         unsigned __user * node;
 *         struct getcpu_cache __user * cache;
 */
copy_buf(syscall_arg[1], sizeof()); // cpu
copy_buf(syscall_arg[2], sizeof()); // node
copy_buf(syscall_arg[3], sizeof(struct getcpu_cache)); // cache
undefined semantics for struct cache
break;
case SYS_signalfd:
/*
 *         int ufd;
 *         sigset_t __user * user_mask;
 *         size_t sizemask;
 */
copy_buf(syscall_arg[2], sizeof(sigset_t)); // user_mask
break;
case SYS_signalfd4:
/*
 *         int ufd;
 *         sigset_t __user * user_mask;
 *         size_t sizemask;
 *         int flags;
 */
copy_buf(syscall_arg[2], sizeof(sigset_t)); // user_mask
break;
case SYS_timerfd_create:
/*
 *         int clockid;
 *         int flags;
 */
break;
case SYS_timerfd_settime:
/*
 *         int ufd;
 *         int flags;
 *         const struct itimerspec __user * utmr;
 *         struct itimerspec __user * otmr;
 */
copy_buf(syscall_arg[3], sizeof(struct itimerspec)); // utmr
copy_buf(syscall_arg[4], sizeof(struct itimerspec)); // otmr
break;
case SYS_timerfd_gettime:
/*
 *         int ufd;
 *         struct itimerspec __user * otmr;
 */
copy_buf(syscall_arg[2], sizeof(struct itimerspec)); // otmr
break;
case SYS_eventfd:
/*
 *         unsigned int count;
 */
break;
case SYS_eventfd2:
/*
 *         unsigned int count;
 *         int flags;
 */
break;
case SYS_fallocate:
/*
 *         int fd;
 *         int mode;
 *         loff_t offset;
 *         loff_t len;
 */
break;
case SYS_old_readdir:
/*
 *         unsigned int ;
 *         struct old_linux_dirent __user * ;
 *         unsigned int ;
 */
copy_buf(syscall_arg[2], sizeof(struct old_linux_dirent)); //
undefined semantics for struct
break;
case SYS_pselect6:
/*
 *         int ;
 *         fd_set __user * ;
 *         fd_set __user * ;
 *         fd_set __user * ;
 *         struct timespec __user * ;
 *         void __user * ;
 */
copy_buf(syscall_arg[2], sizeof(fd_set)); //
copy_buf(syscall_arg[3], sizeof(fd_set)); //
copy_buf(syscall_arg[4], sizeof(fd_set)); //
copy_buf(syscall_arg[5], sizeof(struct timespec)); //
copy_buf(syscall_arg[6], sizeof(void)); //
break;
case SYS_ppoll:
/*
 *         struct pollfd __user * ;
 *         unsigned int ;
 *         struct timespec __user * ;
 *         const sigset_t __user * ;
 *         size_t ;
 */
copy_buf(syscall_arg[1], sizeof(struct pollfd)); //
copy_buf(syscall_arg[3], sizeof(struct timespec)); //
copy_buf(syscall_arg[4], sizeof(sigset_t)); //
break;
case SYS_fanotify_init:
/*
 *         unsigned int flags;
 *         unsigned int event_f_flags;
 */
break;
case SYS_fanotify_mark:
/*
 *         int fanotify_fd;
 *         unsigned int flags;
 *         u64 mask;
 *         int fd;
 *         const char __user * pathname;
 */
unsafe_copy_zts(pathname);
break;
case SYS_syncfs:
/*
 *         int fd;
 */
break;
case SYS_perf_event_open:
/*
 *         struct perf_event_attr __user * attr_uptr;
 *         pid_t pid;
 *         int cpu;
 *         int group_fd;
 *         unsigned long flags;
 */
copy_buf(syscall_arg[1], sizeof(struct perf_event_attr)); // attr_uptr
undefined semantics for struct attr_uptr
break;
case SYS_mmap_pgoff:
/*
 *         unsigned long addr;
 *         unsigned long len;
 *         unsigned long prot;
 *         unsigned long flags;
 *         unsigned long fd;
 *         unsigned long pgoff;
 */
break;
case SYS_old_mmap:
/*
 *         struct mmap_arg_struct __user * arg;
 */
copy_buf(syscall_arg[1], sizeof(struct mmap_arg_struct)); // arg
undefined semantics for struct arg
break;
case SYS_name_to_handle_at:
/*
 *         int dfd;
 *         const char __user * name;
 *         struct file_handle __user * handle;
 *         int __user * mnt_id;
 *         int flag;
 */
unsafe_copy_zts(name);
copy_buf(syscall_arg[3], sizeof(struct file_handle)); // handle
undefined semantics for struct handle
copy_buf(syscall_arg[4], sizeof(int)); // mnt_id
break;
case SYS_open_by_handle_at:
/*
 *         int mountdirfd;
 *         struct file_handle __user * handle;
 *         int flags;
 */
copy_buf(syscall_arg[2], sizeof(struct file_handle)); // handle
undefined semantics for struct handle
break;
case SYS_setns:
/*
 *         int fd;
 *         int nstype;
 */
break;
case SYS_process_vm_readv:
/*
 *         pid_t pid;
 *         const struct iovec __user * lvec;
 *         unsigned long liovcnt;
 *         const struct iovec __user * rvec;
 *         unsigned long riovcnt;
 *         unsigned long flags;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // lvec
rec_copy_struct(lvec);
copy_buf(syscall_arg[4], sizeof(struct iovec)); // rvec
rec_copy_struct(rvec);
break;
case SYS_process_vm_writev:
/*
 *         pid_t pid;
 *         const struct iovec __user * lvec;
 *         unsigned long liovcnt;
 *         const struct iovec __user * rvec;
 *         unsigned long riovcnt;
 *         unsigned long flags;
 */
copy_buf(syscall_arg[2], sizeof(struct iovec)); // lvec
rec_copy_struct(lvec);
copy_buf(syscall_arg[4], sizeof(struct iovec)); // rvec
rec_copy_struct(rvec);
break;
}
