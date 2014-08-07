do_syscalls.h:
struct sys_time_args {
        PADDED(time_t __user * tloc)
};
struct sys_stime_args {
        PADDED(time_t __user * tptr)
};
struct sys_gettimeofday_args {
        PADDED(struct timeval __user * tv)
        PADDED(struct timezone __user * tz)
};
struct sys_settimeofday_args {
        PADDED(struct timeval __user * tv)
        PADDED(struct timezone __user * tz)
};
struct sys_adjtimex_args {
        PADDED(struct timex __user * txc_p)
};
struct sys_times_args {
        PADDED(struct tms __user * tbuf)
};
struct sys_gettid_args {

};
struct sys_nanosleep_args {
        PADDED(struct timespec __user * rqtp)
        PADDED(struct timespec __user * rmtp)
};
struct sys_alarm_args {
        PADDED(unsigned int seconds)
};
struct sys_getpid_args {

};
struct sys_getppid_args {

};
struct sys_getuid_args {

};
struct sys_geteuid_args {

};
struct sys_getgid_args {

};
struct sys_getegid_args {

};
struct sys_getresuid_args {
        PADDED(uid_t __user * ruid)
        PADDED(uid_t __user * euid)
        PADDED(uid_t __user * suid)
};
struct sys_getresgid_args {
        PADDED(gid_t __user * rgid)
        PADDED(gid_t __user * egid)
        PADDED(gid_t __user * sgid)
};
struct sys_getpgid_args {
        PADDED(pid_t pid)
};
struct sys_getpgrp_args {

};
struct sys_getsid_args {
        PADDED(pid_t pid)
};
struct sys_getgroups_args {
        PADDED(int gidsetsize)
        PADDED(gid_t __user * grouplist)
};
struct sys_setregid_args {
        PADDED(gid_t rgid)
        PADDED(gid_t egid)
};
struct sys_setgid_args {
        PADDED(gid_t gid)
};
struct sys_setreuid_args {
        PADDED(uid_t ruid)
        PADDED(uid_t euid)
};
struct sys_setuid_args {
        PADDED(uid_t uid)
};
struct sys_setresuid_args {
        PADDED(uid_t ruid)
        PADDED(uid_t euid)
        PADDED(uid_t suid)
};
struct sys_setresgid_args {
        PADDED(gid_t rgid)
        PADDED(gid_t egid)
        PADDED(gid_t sgid)
};
struct sys_setfsuid_args {
        PADDED(uid_t uid)
};
struct sys_setfsgid_args {
        PADDED(gid_t gid)
};
struct sys_setpgid_args {
        PADDED(pid_t pid)
        PADDED(pid_t pgid)
};
struct sys_setsid_args {

};
struct sys_setgroups_args {
        PADDED(int gidsetsize)
        PADDED(gid_t __user * grouplist)
};
struct sys_acct_args {
        PADDED(const char __user * name)
};
struct sys_capget_args {
        PADDED(cap_user_header_t header)
        PADDED(cap_user_data_t dataptr)
};
struct sys_capset_args {
        PADDED(cap_user_header_t header)
        PADDED(const cap_user_data_t data)
};
struct sys_personality_args {
        PADDED(unsigned int personality)
};
struct sys_sigpending_args {
        PADDED(old_sigset_t __user * set)
};
struct sys_sigprocmask_args {
        PADDED(int how)
        PADDED(old_sigset_t __user * set)
        PADDED(old_sigset_t __user * oset)
};
struct sys_sigaltstack_args {
        PADDED(const struct sigaltstack __user * uss)
        PADDED(struct sigaltstack __user * uoss)
};
struct sys_getitimer_args {
        PADDED(int which)
        PADDED(struct itimerval __user * value)
};
struct sys_setitimer_args {
        PADDED(int which)
        PADDED(struct itimerval __user * value)
        PADDED(struct itimerval __user * ovalue)
};
struct sys_timer_create_args {
        PADDED(clockid_t which_clock)
        PADDED(struct sigevent __user * timer_event_spec)
        PADDED(timer_t __user * created_timer_id)
};
struct sys_timer_gettime_args {
        PADDED(timer_t timer_id)
        PADDED(struct itimerspec __user * setting)
};
struct sys_timer_getoverrun_args {
        PADDED(timer_t timer_id)
};
struct sys_timer_settime_args {
        PADDED(timer_t timer_id)
        PADDED(int flags)
        PADDED(const struct itimerspec __user * new_setting)
        PADDED(struct itimerspec __user * old_setting)
};
struct sys_timer_delete_args {
        PADDED(timer_t timer_id)
};
struct sys_clock_settime_args {
        PADDED(clockid_t which_clock)
        PADDED(const struct timespec __user * tp)
};
struct sys_clock_gettime_args {
        PADDED(clockid_t which_clock)
        PADDED(struct timespec __user * tp)
};
struct sys_clock_adjtime_args {
        PADDED(clockid_t which_clock)
        PADDED(struct timex __user * tx)
};
struct sys_clock_getres_args {
        PADDED(clockid_t which_clock)
        PADDED(struct timespec __user * tp)
};
struct sys_clock_nanosleep_args {
        PADDED(clockid_t which_clock)
        PADDED(int flags)
        PADDED(const struct timespec __user * rqtp)
        PADDED(struct timespec __user * rmtp)
};
struct sys_nice_args {
        PADDED(int increment)
};
struct sys_sched_setscheduler_args {
        PADDED(pid_t pid)
        PADDED(int policy)
        PADDED(struct sched_param __user * param)
};
struct sys_sched_setparam_args {
        PADDED(pid_t pid)
        PADDED(struct sched_param __user * param)
};
struct sys_sched_setattr_args {
        PADDED(pid_t pid)
        PADDED(struct sched_attr __user * attr)
        PADDED(unsigned int flags)
};
struct sys_sched_getscheduler_args {
        PADDED(pid_t pid)
};
struct sys_sched_getparam_args {
        PADDED(pid_t pid)
        PADDED(struct sched_param __user * param)
};
struct sys_sched_getattr_args {
        PADDED(pid_t pid)
        PADDED(struct sched_attr __user * attr)
        PADDED(unsigned int size)
        PADDED(unsigned int flags)
};
struct sys_sched_setaffinity_args {
        PADDED(pid_t pid)
        PADDED(unsigned int len)
        PADDED(unsigned long __user * user_mask_ptr)
};
struct sys_sched_getaffinity_args {
        PADDED(pid_t pid)
        PADDED(unsigned int len)
        PADDED(unsigned long __user * user_mask_ptr)
};
struct sys_sched_yield_args {

};
struct sys_sched_get_priority_max_args {
        PADDED(int policy)
};
struct sys_sched_get_priority_min_args {
        PADDED(int policy)
};
struct sys_sched_rr_get_interval_args {
        PADDED(pid_t pid)
        PADDED(struct timespec __user * interval)
};
struct sys_setpriority_args {
        PADDED(int which)
        PADDED(int who)
        PADDED(int niceval)
};
struct sys_getpriority_args {
        PADDED(int which)
        PADDED(int who)
};
struct sys_shutdown_args {
        PADDED(int )
        PADDED(int )
};
struct sys_reboot_args {
        PADDED(int magic1)
        PADDED(int magic2)
        PADDED(unsigned int cmd)
        PADDED(void __user * arg)
};
struct sys_restart_syscall_args {

};
struct sys_kexec_load_args {
        PADDED(unsigned long entry)
        PADDED(unsigned long nr_segments)
        PADDED(struct kexec_segment __user * segments)
        PADDED(unsigned long flags)
};
struct sys_exit_args {
        PADDED(int error_code)
};
struct sys_exit_group_args {
        PADDED(int error_code)
};
struct sys_wait4_args {
        PADDED(pid_t pid)
        PADDED(int __user * stat_addr)
        PADDED(int options)
        PADDED(struct rusage __user * ru)
};
struct sys_waitid_args {
        PADDED(int which)
        PADDED(pid_t pid)
        PADDED(struct siginfo __user * infop)
        PADDED(int options)
        PADDED(struct rusage __user * ru)
};
struct sys_waitpid_args {
        PADDED(pid_t pid)
        PADDED(int __user * stat_addr)
        PADDED(int options)
};
struct sys_set_tid_address_args {
        PADDED(int __user * tidptr)
};
struct sys_futex_args {
        PADDED(u32 __user * uaddr)
        PADDED(int op)
        PADDED(u32 val)
        PADDED(struct timespec __user * utime)
        PADDED(u32 __user * uaddr2)
        PADDED(u32 val3)
};
struct sys_init_module_args {
        PADDED(void __user * umod)
        PADDED(unsigned long len)
        PADDED(const char __user * uargs)
};
struct sys_delete_module_args {
        PADDED(const char __user * name_user)
        PADDED(unsigned int flags)
};
struct sys_sigsuspend_args {
        PADDED(old_sigset_t mask)
};
struct sys_sigsuspend_args {
        PADDED(int unused1)
        PADDED(int unused2)
        PADDED(old_sigset_t mask)
};
struct sys_rt_sigsuspend_args {
        PADDED(sigset_t __user * unewset)
        PADDED(size_t sigsetsize)
};
struct sys_sigaction_args {
        PADDED(int )
        PADDED(const struct old_sigaction __user * )
        PADDED(struct old_sigaction __user * )
};
struct sys_rt_sigaction_args {
        PADDED(int )
        PADDED(const struct sigaction __user * )
        PADDED(struct sigaction __user * )
        PADDED(size_t )
};
struct sys_rt_sigprocmask_args {
        PADDED(int how)
        PADDED(sigset_t __user * set)
        PADDED(sigset_t __user * oset)
        PADDED(size_t sigsetsize)
};
struct sys_rt_sigpending_args {
        PADDED(sigset_t __user * set)
        PADDED(size_t sigsetsize)
};
struct sys_rt_sigtimedwait_args {
        PADDED(const sigset_t __user * uthese)
        PADDED(siginfo_t __user * uinfo)
        PADDED(const struct timespec __user * uts)
        PADDED(size_t sigsetsize)
};
struct sys_rt_tgsigqueueinfo_args {
        PADDED(pid_t tgid)
        PADDED(pid_t pid)
        PADDED(int sig)
        PADDED(siginfo_t __user * uinfo)
};
struct sys_kill_args {
        PADDED(int pid)
        PADDED(int sig)
};
struct sys_tgkill_args {
        PADDED(int tgid)
        PADDED(int pid)
        PADDED(int sig)
};
struct sys_tkill_args {
        PADDED(int pid)
        PADDED(int sig)
};
struct sys_rt_sigqueueinfo_args {
        PADDED(int pid)
        PADDED(int sig)
        PADDED(siginfo_t __user * uinfo)
};
struct sys_sgetmask_args {

};
struct sys_ssetmask_args {
        PADDED(int newmask)
};
struct sys_signal_args {
        PADDED(int sig)
        PADDED(__sighandler_t handler)
};
struct sys_pause_args {

};
struct sys_sync_args {

};
struct sys_fsync_args {
        PADDED(unsigned int fd)
};
struct sys_fdatasync_args {
        PADDED(unsigned int fd)
};
struct sys_bdflush_args {
        PADDED(int func)
        PADDED(long data)
};
struct sys_mount_args {
        PADDED(char __user * dev_name)
        PADDED(char __user * dir_name)
        PADDED(char __user * type)
        PADDED(unsigned long flags)
        PADDED(void __user * data)
};
struct sys_umount_args {
        PADDED(char __user * name)
        PADDED(int flags)
};
struct sys_oldumount_args {
        PADDED(char __user * name)
};
struct sys_truncate_args {
        PADDED(const char __user * path)
        PADDED(long length)
};
struct sys_ftruncate_args {
        PADDED(unsigned int fd)
        PADDED(unsigned long length)
};
struct sys_stat_args {
        PADDED(const char __user * filename)
        PADDED(struct __old_kernel_stat __user * statbuf)
};
struct sys_statfs_args {
        PADDED(const char __user * path)
        PADDED(struct statfs __user * buf)
};
struct sys_statfs64_args {
        PADDED(const char __user * path)
        PADDED(size_t sz)
        PADDED(struct statfs64 __user * buf)
};
struct sys_fstatfs_args {
        PADDED(unsigned int fd)
        PADDED(struct statfs __user * buf)
};
struct sys_fstatfs64_args {
        PADDED(unsigned int fd)
        PADDED(size_t sz)
        PADDED(struct statfs64 __user * buf)
};
struct sys_lstat_args {
        PADDED(const char __user * filename)
        PADDED(struct __old_kernel_stat __user * statbuf)
};
struct sys_fstat_args {
        PADDED(unsigned int fd)
        PADDED(struct __old_kernel_stat __user * statbuf)
};
struct sys_newstat_args {
        PADDED(const char __user * filename)
        PADDED(struct stat __user * statbuf)
};
struct sys_newlstat_args {
        PADDED(const char __user * filename)
        PADDED(struct stat __user * statbuf)
};
struct sys_newfstat_args {
        PADDED(unsigned int fd)
        PADDED(struct stat __user * statbuf)
};
struct sys_ustat_args {
        PADDED(unsigned dev )
        PADDED(struct ustat __user * ubuf)
};
struct sys_stat64_args {
        PADDED(const char __user * filename)
        PADDED(struct stat64 __user * statbuf)
};
struct sys_fstat64_args {
        PADDED(unsigned long fd)
        PADDED(struct stat64 __user * statbuf)
};
struct sys_lstat64_args {
        PADDED(const char __user * filename)
        PADDED(struct stat64 __user * statbuf)
};
struct sys_truncate64_args {
        PADDED(const char __user * path)
        PADDED(loff_t length)
};
struct sys_ftruncate64_args {
        PADDED(unsigned int fd)
        PADDED(loff_t length)
};
struct sys_setxattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
        PADDED(const void __user * value)
        PADDED(size_t size)
        PADDED(int flags)
};
struct sys_lsetxattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
        PADDED(const void __user * value)
        PADDED(size_t size)
        PADDED(int flags)
};
struct sys_fsetxattr_args {
        PADDED(int fd)
        PADDED(const char __user * name)
        PADDED(const void __user * value)
        PADDED(size_t size)
        PADDED(int flags)
};
struct sys_getxattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
        PADDED(void __user * value)
        PADDED(size_t size)
};
struct sys_lgetxattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
        PADDED(void __user * value)
        PADDED(size_t size)
};
struct sys_fgetxattr_args {
        PADDED(int fd)
        PADDED(const char __user * name)
        PADDED(void __user * value)
        PADDED(size_t size)
};
struct sys_listxattr_args {
        PADDED(const char __user * path)
        PADDED(char __user * list)
        PADDED(size_t size)
};
struct sys_llistxattr_args {
        PADDED(const char __user * path)
        PADDED(char __user * list)
        PADDED(size_t size)
};
struct sys_flistxattr_args {
        PADDED(int fd)
        PADDED(char __user * list)
        PADDED(size_t size)
};
struct sys_removexattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
};
struct sys_lremovexattr_args {
        PADDED(const char __user * path)
        PADDED(const char __user * name)
};
struct sys_fremovexattr_args {
        PADDED(int fd)
        PADDED(const char __user * name)
};
struct sys_brk_args {
        PADDED(unsigned long brk)
};
struct sys_mprotect_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
        PADDED(unsigned long prot)
};
struct sys_mremap_args {
        PADDED(unsigned long addr)
        PADDED(unsigned long old_len)
        PADDED(unsigned long new_len)
        PADDED(unsigned long flags)
        PADDED(unsigned long new_addr)
};
struct sys_remap_file_pages_args {
        PADDED(unsigned long start)
        PADDED(unsigned long size)
        PADDED(unsigned long prot)
        PADDED(unsigned long pgoff)
        PADDED(unsigned long flags)
};
struct sys_msync_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
        PADDED(int flags)
};
struct sys_fadvise64_args {
        PADDED(int fd)
        PADDED(loff_t offset)
        PADDED(size_t len)
        PADDED(int advice)
};
struct sys_fadvise64_64_args {
        PADDED(int fd)
        PADDED(loff_t offset)
        PADDED(loff_t len)
        PADDED(int advice)
};
struct sys_munmap_args {
        PADDED(unsigned long addr)
        PADDED(size_t len)
};
struct sys_mlock_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
};
struct sys_munlock_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
};
struct sys_mlockall_args {
        PADDED(int flags)
};
struct sys_munlockall_args {

};
struct sys_madvise_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
        PADDED(int behavior)
};
struct sys_mincore_args {
        PADDED(unsigned long start)
        PADDED(size_t len)
        PADDED(unsigned char __user * vec)
};
struct sys_pivot_root_args {
        PADDED(const char __user * new_root)
        PADDED(const char __user * put_old)
};
struct sys_chroot_args {
        PADDED(const char __user * filename)
};
struct sys_mknod_args {
        PADDED(const char __user * filename)
        PADDED(umode_t mode)
        PADDED(unsigned dev )
};
struct sys_link_args {
        PADDED(const char __user * oldname)
        PADDED(const char __user * newname)
};
struct sys_symlink_args {
        PADDED(const char __user * old)
        PADDED(const char __user * new)
};
struct sys_unlink_args {
        PADDED(const char __user * pathname)
};
struct sys_rename_args {
        PADDED(const char __user * oldname)
        PADDED(const char __user * newname)
};
struct sys_chmod_args {
        PADDED(const char __user * filename)
        PADDED(umode_t mode)
};
struct sys_fchmod_args {
        PADDED(unsigned int fd)
        PADDED(umode_t mode)
};
struct sys_fcntl_args {
        PADDED(unsigned int fd)
        PADDED(unsigned int cmd)
        PADDED(unsigned long arg)
};
struct sys_fcntl64_args {
        PADDED(unsigned int fd)
        PADDED(unsigned int cmd)
        PADDED(unsigned long arg)
};
struct sys_pipe_args {
        PADDED(int __user * fildes)
};
struct sys_pipe2_args {
        PADDED(int __user * fildes)
        PADDED(int flags)
};
struct sys_dup_args {
        PADDED(unsigned int fildes)
};
struct sys_dup2_args {
        PADDED(unsigned int oldfd)
        PADDED(unsigned int newfd)
};
struct sys_dup3_args {
        PADDED(unsigned int oldfd)
        PADDED(unsigned int newfd)
        PADDED(int flags)
};
struct sys_ioperm_args {
        PADDED(unsigned long from)
        PADDED(unsigned long num)
        PADDED(int on)
};
struct sys_ioctl_args {
        PADDED(unsigned int fd)
        PADDED(unsigned int cmd)
        PADDED(unsigned long arg)
};
struct sys_flock_args {
        PADDED(unsigned int fd)
        PADDED(unsigned int cmd)
};
struct sys_io_setup_args {
        PADDED(unsigned nr_reqs )
        PADDED(aio_context_t __user * ctx)
};
struct sys_io_destroy_args {
        PADDED(aio_context_t ctx)
};
struct sys_io_getevents_args {
        PADDED(aio_context_t ctx_id)
        PADDED(long min_nr)
        PADDED(long nr)
        PADDED(struct io_event __user * events)
        PADDED(struct timespec __user * timeout)
};
struct sys_io_submit_args {
        PADDED(aio_context_t )
        PADDED(long )
        PADDED(struct iocb __user * __user * )
};
struct sys_io_cancel_args {
        PADDED(aio_context_t ctx_id)
        PADDED(struct iocb __user * iocb)
        PADDED(struct io_event __user * result)
};
struct sys_sendfile_args {
        PADDED(int out_fd)
        PADDED(int in_fd)
        PADDED(off_t __user * offset)
        PADDED(size_t count)
};
struct sys_sendfile64_args {
        PADDED(int out_fd)
        PADDED(int in_fd)
        PADDED(loff_t __user * offset)
        PADDED(size_t count)
};
struct sys_readlink_args {
        PADDED(const char __user * path)
        PADDED(char __user * buf)
        PADDED(int bufsiz)
};
struct sys_creat_args {
        PADDED(const char __user * pathname)
        PADDED(umode_t mode)
};
struct sys_open_args {
        PADDED(const char __user * filename)
        PADDED(int flags)
        PADDED(umode_t mode)
};
struct sys_close_args {
        PADDED(unsigned int fd)
};
struct sys_access_args {
        PADDED(const char __user * filename)
        PADDED(int mode)
};
struct sys_vhangup_args {

};
struct sys_chown_args {
        PADDED(const char __user * filename)
        PADDED(uid_t user)
        PADDED(gid_t group)
};
struct sys_lchown_args {
        PADDED(const char __user * filename)
        PADDED(uid_t user)
        PADDED(gid_t group)
};
struct sys_fchown_args {
        PADDED(unsigned int fd)
        PADDED(uid_t user)
        PADDED(gid_t group)
};
struct sys_chown16_args {
        PADDED(const char __user * filename)
        PADDED(old_uid_t user)
        PADDED(old_gid_t group)
};
struct sys_lchown16_args {
        PADDED(const char __user * filename)
        PADDED(old_uid_t user)
        PADDED(old_gid_t group)
};
struct sys_fchown16_args {
        PADDED(unsigned int fd)
        PADDED(old_uid_t user)
        PADDED(old_gid_t group)
};
struct sys_setregid16_args {
        PADDED(old_gid_t rgid)
        PADDED(old_gid_t egid)
};
struct sys_setgid16_args {
        PADDED(old_gid_t gid)
};
struct sys_setreuid16_args {
        PADDED(old_uid_t ruid)
        PADDED(old_uid_t euid)
};
struct sys_setuid16_args {
        PADDED(old_uid_t uid)
};
struct sys_setresuid16_args {
        PADDED(old_uid_t ruid)
        PADDED(old_uid_t euid)
        PADDED(old_uid_t suid)
};
struct sys_getresuid16_args {
        PADDED(old_uid_t __user * ruid)
        PADDED(old_uid_t __user * euid)
        PADDED(old_uid_t __user * suid)
};
struct sys_setresgid16_args {
        PADDED(old_gid_t rgid)
        PADDED(old_gid_t egid)
        PADDED(old_gid_t sgid)
};
struct sys_getresgid16_args {
        PADDED(old_gid_t __user * rgid)
        PADDED(old_gid_t __user * egid)
        PADDED(old_gid_t __user * sgid)
};
struct sys_setfsuid16_args {
        PADDED(old_uid_t uid)
};
struct sys_setfsgid16_args {
        PADDED(old_gid_t gid)
};
struct sys_getgroups16_args {
        PADDED(int gidsetsize)
        PADDED(old_gid_t __user * grouplist)
};
struct sys_setgroups16_args {
        PADDED(int gidsetsize)
        PADDED(old_gid_t __user * grouplist)
};
struct sys_getuid16_args {

};
struct sys_geteuid16_args {

};
struct sys_getgid16_args {

};
struct sys_getegid16_args {

};
struct sys_utime_args {
        PADDED(char __user * filename)
        PADDED(struct utimbuf __user * times)
};
struct sys_utimes_args {
        PADDED(char __user * filename)
        PADDED(struct timeval __user * utimes)
};
struct sys_lseek_args {
        PADDED(unsigned int fd)
        PADDED(off_t offset)
        PADDED(unsigned int whence)
};
struct sys_llseek_args {
        PADDED(unsigned int fd)
        PADDED(unsigned long offset_high)
        PADDED(unsigned long offset_low)
        PADDED(loff_t __user * result)
        PADDED(unsigned int whence)
};
struct sys_read_args {
        PADDED(unsigned int fd)
        PADDED(char __user * buf)
        PADDED(size_t count)
};
struct sys_readahead_args {
        PADDED(int fd)
        PADDED(loff_t offset)
        PADDED(size_t count)
};
struct sys_readv_args {
        PADDED(unsigned long fd)
        PADDED(const struct iovec __user * vec)
        PADDED(unsigned long vlen)
};
struct sys_write_args {
        PADDED(unsigned int fd)
        PADDED(const char __user * buf)
        PADDED(size_t count)
};
struct sys_writev_args {
        PADDED(unsigned long fd)
        PADDED(const struct iovec __user * vec)
        PADDED(unsigned long vlen)
};
struct sys_pread64_args {
        PADDED(unsigned int fd)
        PADDED(char __user * buf)
        PADDED(size_t count)
        PADDED(loff_t pos)
};
struct sys_pwrite64_args {
        PADDED(unsigned int fd)
        PADDED(const char __user * buf)
        PADDED(size_t count)
        PADDED(loff_t pos)
};
struct sys_preadv_args {
        PADDED(unsigned long fd)
        PADDED(const struct iovec __user * vec)
        PADDED(unsigned long vlen)
        PADDED(unsigned long pos_l)
        PADDED(unsigned long pos_h)
};
struct sys_pwritev_args {
        PADDED(unsigned long fd)
        PADDED(const struct iovec __user * vec)
        PADDED(unsigned long vlen)
        PADDED(unsigned long pos_l)
        PADDED(unsigned long pos_h)
};
struct sys_getcwd_args {
        PADDED(char __user * buf)
        PADDED(unsigned long size)
};
struct sys_mkdir_args {
        PADDED(const char __user * pathname)
        PADDED(umode_t mode)
};
struct sys_chdir_args {
        PADDED(const char __user * filename)
};
struct sys_fchdir_args {
        PADDED(unsigned int fd)
};
struct sys_rmdir_args {
        PADDED(const char __user * pathname)
};
struct sys_lookup_dcookie_args {
        PADDED(u64 cookie64)
        PADDED(char __user * buf)
        PADDED(size_t len)
};
struct sys_quotactl_args {
        PADDED(unsigned int cmd)
        PADDED(const char __user * special)
        PADDED(qid_t id)
        PADDED(void __user * addr)
};
struct sys_getdents_args {
        PADDED(unsigned int fd)
        PADDED(struct linux_dirent __user * dirent)
        PADDED(unsigned int count)
};
struct sys_getdents64_args {
        PADDED(unsigned int fd)
        PADDED(struct linux_dirent64 __user * dirent)
        PADDED(unsigned int count)
};
struct sys_setsockopt_args {
        PADDED(int fd)
        PADDED(int level)
        PADDED(int optname)
        PADDED(char __user * optval)
        PADDED(int optlen)
};
struct sys_getsockopt_args {
        PADDED(int fd)
        PADDED(int level)
        PADDED(int optname)
        PADDED(char __user * optval)
        PADDED(int __user * optlen)
};
struct sys_bind_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int )
};
struct sys_connect_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int )
};
struct sys_accept_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int __user * )
};
struct sys_accept4_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int __user * )
        PADDED(int )
};
struct sys_getsockname_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int __user * )
};
struct sys_getpeername_args {
        PADDED(int )
        PADDED(struct sockaddr __user * )
        PADDED(int __user * )
};
struct sys_sendmsg_args {
        PADDED(int fd)
        PADDED(struct msghdr __user * msg)
        PADDED(unsigned flags )
};
struct sys_sendmmsg_args {
        PADDED(int fd)
        PADDED(struct mmsghdr __user * msg)
        PADDED(unsigned int vlen)
        PADDED(unsigned flags )
};
struct sys_recvmsg_args {
        PADDED(int fd)
        PADDED(struct msghdr __user * msg)
        PADDED(unsigned flags )
};
struct sys_recvmmsg_args {
        PADDED(int fd)
        PADDED(struct mmsghdr __user * msg)
        PADDED(unsigned int vlen)
        PADDED(unsigned flags )
        PADDED(struct timespec __user * timeout)
};
struct sys_socket_args {
        PADDED(int )
        PADDED(int )
        PADDED(int )
};
struct sys_socketpair_args {
        PADDED(int )
        PADDED(int )
        PADDED(int )
        PADDED(int __user * )
};
struct sys_socketcall_args {
        PADDED(int call)
        PADDED(unsigned long __user * args)
};
struct sys_listen_args {
        PADDED(int )
        PADDED(int )
};
struct sys_poll_args {
        PADDED(struct pollfd __user * ufds)
        PADDED(unsigned int nfds)
        PADDED(int timeout)
};
struct sys_select_args {
        PADDED(int n)
        PADDED(fd_set __user * inp)
        PADDED(fd_set __user * outp)
        PADDED(fd_set __user * exp)
        PADDED(struct timeval __user * tvp)
};
struct sys_old_select_args {
        PADDED(struct sel_arg_struct __user * arg)
};
struct sys_epoll_create_args {
        PADDED(int size)
};
struct sys_epoll_create1_args {
        PADDED(int flags)
};
struct sys_epoll_ctl_args {
        PADDED(int epfd)
        PADDED(int op)
        PADDED(int fd)
        PADDED(struct epoll_event __user * event)
};
struct sys_epoll_wait_args {
        PADDED(int epfd)
        PADDED(struct epoll_event __user * events)
        PADDED(int maxevents)
        PADDED(int timeout)
};
struct sys_epoll_pwait_args {
        PADDED(int epfd)
        PADDED(struct epoll_event __user * events)
        PADDED(int maxevents)
        PADDED(int timeout)
        PADDED(const sigset_t __user * sigmask)
        PADDED(size_t sigsetsize)
};
struct sys_gethostname_args {
        PADDED(char __user * name)
        PADDED(int len)
};
struct sys_sethostname_args {
        PADDED(char __user * name)
        PADDED(int len)
};
struct sys_setdomainname_args {
        PADDED(char __user * name)
        PADDED(int len)
};
struct sys_newuname_args {
        PADDED(struct new_utsname __user * name)
};
struct sys_uname_args {
        PADDED(struct old_utsname __user * )
};
struct sys_olduname_args {
        PADDED(struct oldold_utsname __user * )
};
struct sys_getrlimit_args {
        PADDED(unsigned int resource)
        PADDED(struct rlimit __user * rlim)
};
struct sys_old_getrlimit_args {
        PADDED(unsigned int resource)
        PADDED(struct rlimit __user * rlim)
};
struct sys_setrlimit_args {
        PADDED(unsigned int resource)
        PADDED(struct rlimit __user * rlim)
};
struct sys_prlimit64_args {
        PADDED(pid_t pid)
        PADDED(unsigned int resource)
        PADDED(const struct rlimit64 __user * new_rlim)
        PADDED(struct rlimit64 __user * old_rlim)
};
struct sys_getrusage_args {
        PADDED(int who)
        PADDED(struct rusage __user * ru)
};
struct sys_umask_args {
        PADDED(int mask)
};
struct sys_msgget_args {
        PADDED(key_t key)
        PADDED(int msgflg)
};
struct sys_msgsnd_args {
        PADDED(int msqid)
        PADDED(struct msgbuf __user * msgp)
        PADDED(size_t msgsz)
        PADDED(int msgflg)
};
struct sys_msgrcv_args {
        PADDED(int msqid)
        PADDED(struct msgbuf __user * msgp)
        PADDED(size_t msgsz)
        PADDED(long msgtyp)
        PADDED(int msgflg)
};
struct sys_msgctl_args {
        PADDED(int msqid)
        PADDED(int cmd)
        PADDED(struct msqid_ds __user * buf)
};
struct sys_semget_args {
        PADDED(key_t key)
        PADDED(int nsems)
        PADDED(int semflg)
};
struct sys_semop_args {
        PADDED(int semid)
        PADDED(struct sembuf __user * sops)
        PADDED(unsigned nsops )
};
struct sys_semctl_args {
        PADDED(int semid)
        PADDED(int semnum)
        PADDED(int cmd)
        PADDED(unsigned long arg)
};
struct sys_semtimedop_args {
        PADDED(int semid)
        PADDED(struct sembuf __user * sops)
        PADDED(unsigned nsops )
        PADDED(const struct timespec __user * timeout)
};
struct sys_shmat_args {
        PADDED(int shmid)
        PADDED(char __user * shmaddr)
        PADDED(int shmflg)
};
struct sys_shmget_args {
        PADDED(key_t key)
        PADDED(size_t size)
        PADDED(int flag)
};
struct sys_shmdt_args {
        PADDED(char __user * shmaddr)
};
struct sys_shmctl_args {
        PADDED(int shmid)
        PADDED(int cmd)
        PADDED(struct shmid_ds __user * buf)
};
struct sys_ipc_args {
        PADDED(unsigned int call)
        PADDED(int first)
        PADDED(unsigned long second)
        PADDED(unsigned long third)
        PADDED(void __user * ptr)
        PADDED(long fifth)
};
struct sys_mq_open_args {
        PADDED(const char __user * name)
        PADDED(int oflag)
        PADDED(umode_t mode)
        PADDED(struct mq_attr __user * attr)
};
struct sys_mq_unlink_args {
        PADDED(const char __user * name)
};
struct sys_mq_timedsend_args {
        PADDED(mqd_t mqdes)
        PADDED(const char __user * msg_ptr)
        PADDED(size_t msg_len)
        PADDED(unsigned int msg_prio)
        PADDED(const struct timespec __user * abs_timeout)
};
struct sys_mq_timedreceive_args {
        PADDED(mqd_t mqdes)
        PADDED(char __user * msg_ptr)
        PADDED(size_t msg_len)
        PADDED(unsigned int __user * msg_prio)
        PADDED(const struct timespec __user * abs_timeout)
};
struct sys_mq_notify_args {
        PADDED(mqd_t mqdes)
        PADDED(const struct sigevent __user * notification)
};
struct sys_mq_getsetattr_args {
        PADDED(mqd_t mqdes)
        PADDED(const struct mq_attr __user * mqstat)
        PADDED(struct mq_attr __user * omqstat)
};
struct sys_pciconfig_iobase_args {
        PADDED(long which)
        PADDED(unsigned long bus)
        PADDED(unsigned long devfn)
};
struct sys_pciconfig_read_args {
        PADDED(unsigned long bus)
        PADDED(unsigned long dfn)
        PADDED(unsigned long off)
        PADDED(unsigned long len)
        PADDED(void __user * buf)
};
struct sys_pciconfig_write_args {
        PADDED(unsigned long bus)
        PADDED(unsigned long dfn)
        PADDED(unsigned long off)
        PADDED(unsigned long len)
        PADDED(void __user * buf)
};
struct sys_prctl_args {
        PADDED(int option)
        PADDED(unsigned long arg2)
        PADDED(unsigned long arg3)
        PADDED(unsigned long arg4)
        PADDED(unsigned long arg5)
};
struct sys_swapon_args {
        PADDED(const char __user * specialfile)
        PADDED(int swap_flags)
};
struct sys_swapoff_args {
        PADDED(const char __user * specialfile)
};
struct sys_sysctl_args {
        PADDED(struct __sysctl_args __user * args)
};
struct sys_sysinfo_args {
        PADDED(struct sysinfo __user * info)
};
struct sys_sysfs_args {
        PADDED(int option)
        PADDED(unsigned long arg1)
        PADDED(unsigned long arg2)
};
struct sys_syslog_args {
        PADDED(int type)
        PADDED(char __user * buf)
        PADDED(int len)
};
struct sys_uselib_args {
        PADDED(const char __user * library)
};
struct sys_ni_syscall_args {

};
struct sys_ptrace_args {
        PADDED(long request)
        PADDED(long pid)
        PADDED(unsigned long addr)
        PADDED(unsigned long data)
};
struct sys_add_key_args {
        PADDED(const char __user * _type)
        PADDED(const char __user * _description)
        PADDED(const void __user * _payload)
        PADDED(size_t plen)
        PADDED(key_serial_t destringid)
};
struct sys_request_key_args {
        PADDED(const char __user * _type)
        PADDED(const char __user * _description)
        PADDED(const char __user * _callout_info)
        PADDED(key_serial_t destringid)
};
struct sys_keyctl_args {
        PADDED(int cmd)
        PADDED(unsigned long arg2)
        PADDED(unsigned long arg3)
        PADDED(unsigned long arg4)
        PADDED(unsigned long arg5)
};
struct sys_ioprio_set_args {
        PADDED(int which)
        PADDED(int who)
        PADDED(int ioprio)
};
struct sys_ioprio_get_args {
        PADDED(int which)
        PADDED(int who)
};
struct sys_set_mempolicy_args {
        PADDED(int mode)
        PADDED(unsigned long __user * nmask)
        PADDED(unsigned long maxnode)
};
struct sys_migrate_pages_args {
        PADDED(pid_t pid)
        PADDED(unsigned long maxnode)
        PADDED(const unsigned long __user * from)
        PADDED(const unsigned long __user * to)
};
struct sys_move_pages_args {
        PADDED(pid_t pid)
        PADDED(unsigned long nr_pages)
        PADDED(const void __user * __user * pages)
        PADDED(const int __user * nodes)
        PADDED(int __user * status)
        PADDED(int flags)
};
struct sys_mbind_args {
        PADDED(unsigned long start)
        PADDED(unsigned long len)
        PADDED(unsigned long mode)
        PADDED(unsigned long __user * nmask)
        PADDED(unsigned long maxnode)
        PADDED(unsigned flags )
};
struct sys_get_mempolicy_args {
        PADDED(int __user * policy)
        PADDED(unsigned long __user * nmask)
        PADDED(unsigned long maxnode)
        PADDED(unsigned long addr)
        PADDED(unsigned long flags)
};
struct sys_inotify_init_args {

};
struct sys_inotify_init1_args {
        PADDED(int flags)
};
struct sys_inotify_add_watch_args {
        PADDED(int fd)
        PADDED(const char __user * path)
        PADDED(u32 mask)
};
struct sys_inotify_rm_watch_args {
        PADDED(int fd)
        PADDED(__s32 wd)
};
struct sys_spu_run_args {
        PADDED(int fd)
        PADDED(__u32 __user * unpc)
        PADDED(__u32 __user * ustatus)
};
struct sys_spu_create_args {
        PADDED(const char __user * name)
        PADDED(unsigned int flags)
        PADDED(umode_t mode)
        PADDED(int fd)
};
struct sys_mknodat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(umode_t mode)
        PADDED(unsigned dev )
};
struct sys_mkdirat_args {
        PADDED(int dfd)
        PADDED(const char __user * pathname)
        PADDED(umode_t mode)
};
struct sys_unlinkat_args {
        PADDED(int dfd)
        PADDED(const char __user * pathname)
        PADDED(int flag)
};
struct sys_symlinkat_args {
        PADDED(const char __user * oldname)
        PADDED(int newdfd)
        PADDED(const char __user * newname)
};
struct sys_linkat_args {
        PADDED(int olddfd)
        PADDED(const char __user * oldname)
        PADDED(int newdfd)
        PADDED(const char __user * newname)
        PADDED(int flags)
};
struct sys_renameat_args {
        PADDED(int olddfd)
        PADDED(const char __user * oldname)
        PADDED(int newdfd)
        PADDED(const char __user * newname)
};
struct sys_renameat2_args {
        PADDED(int olddfd)
        PADDED(const char __user * oldname)
        PADDED(int newdfd)
        PADDED(const char __user * newname)
        PADDED(unsigned int flags)
};
struct sys_futimesat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(struct timeval __user * utimes)
};
struct sys_faccessat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(int mode)
};
struct sys_fchmodat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(umode_t mode)
};
struct sys_fchownat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(uid_t user)
        PADDED(gid_t group)
        PADDED(int flag)
};
struct sys_openat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(int flags)
        PADDED(umode_t mode)
};
struct sys_newfstatat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(struct stat __user * statbuf)
        PADDED(int flag)
};
struct sys_fstatat64_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(struct stat64 __user * statbuf)
        PADDED(int flag)
};
struct sys_readlinkat_args {
        PADDED(int dfd)
        PADDED(const char __user * path)
        PADDED(char __user * buf)
        PADDED(int bufsiz)
};
struct sys_utimensat_args {
        PADDED(int dfd)
        PADDED(const char __user * filename)
        PADDED(struct timespec __user * utimes)
        PADDED(int flags)
};
struct sys_unshare_args {
        PADDED(unsigned long unshare_flags)
};
struct sys_splice_args {
        PADDED(int fd_in)
        PADDED(loff_t __user * off_in)
        PADDED(int fd_out)
        PADDED(loff_t __user * off_out)
        PADDED(size_t len)
        PADDED(unsigned int flags)
};
struct sys_vmsplice_args {
        PADDED(int fd)
        PADDED(const struct iovec __user * iov)
        PADDED(unsigned long nr_segs)
        PADDED(unsigned int flags)
};
struct sys_tee_args {
        PADDED(int fdin)
        PADDED(int fdout)
        PADDED(size_t len)
        PADDED(unsigned int flags)
};
struct sys_sync_file_range_args {
        PADDED(int fd)
        PADDED(loff_t offset)
        PADDED(loff_t nbytes)
        PADDED(unsigned int flags)
};
struct sys_sync_file_range2_args {
        PADDED(int fd)
        PADDED(unsigned int flags)
        PADDED(loff_t offset)
        PADDED(loff_t nbytes)
};
struct sys_get_robust_list_args {
        PADDED(int pid)
        PADDED(struct robust_list_head __user * __user * head_ptr)
        PADDED(size_t __user * len_ptr)
};
struct sys_set_robust_list_args {
        PADDED(struct robust_list_head __user * head)
        PADDED(size_t len)
};
struct sys_getcpu_args {
        PADDED(unsigned __user * cpu)
        PADDED(unsigned __user * node)
        PADDED(struct getcpu_cache __user * cache)
};
struct sys_signalfd_args {
        PADDED(int ufd)
        PADDED(sigset_t __user * user_mask)
        PADDED(size_t sizemask)
};
struct sys_signalfd4_args {
        PADDED(int ufd)
        PADDED(sigset_t __user * user_mask)
        PADDED(size_t sizemask)
        PADDED(int flags)
};
struct sys_timerfd_create_args {
        PADDED(int clockid)
        PADDED(int flags)
};
struct sys_timerfd_settime_args {
        PADDED(int ufd)
        PADDED(int flags)
        PADDED(const struct itimerspec __user * utmr)
        PADDED(struct itimerspec __user * otmr)
};
struct sys_timerfd_gettime_args {
        PADDED(int ufd)
        PADDED(struct itimerspec __user * otmr)
};
struct sys_eventfd_args {
        PADDED(unsigned int count)
};
struct sys_eventfd2_args {
        PADDED(unsigned int count)
        PADDED(int flags)
};
struct sys_fallocate_args {
        PADDED(int fd)
        PADDED(int mode)
        PADDED(loff_t offset)
        PADDED(loff_t len)
};
struct sys_old_readdir_args {
        PADDED(unsigned int )
        PADDED(struct old_linux_dirent __user * )
        PADDED(unsigned int )
};
struct sys_pselect6_args {
        PADDED(int )
        PADDED(fd_set __user * )
        PADDED(fd_set __user * )
        PADDED(fd_set __user * )
        PADDED(struct timespec __user * )
        PADDED(void __user * )
};
struct sys_ppoll_args {
        PADDED(struct pollfd __user * )
        PADDED(unsigned int )
        PADDED(struct timespec __user * )
        PADDED(const sigset_t __user * )
        PADDED(size_t )
};
struct sys_fanotify_init_args {
        PADDED(unsigned int flags)
        PADDED(unsigned int event_f_flags)
};
struct sys_fanotify_mark_args {
        PADDED(int fanotify_fd)
        PADDED(unsigned int flags)
        PADDED(u64 mask)
        PADDED(int fd)
        PADDED(const char __user * pathname)
};
struct sys_syncfs_args {
        PADDED(int fd)
};
struct sys_fork_args {

};
struct sys_vfork_args {

};
struct sys_clone_args {
        PADDED(unsigned long )
        PADDED(unsigned long )
        PADDED(int __user * )
        PADDED(int )
        PADDED(int __user * )
};
struct sys_clone_args {
        PADDED(unsigned long )
        PADDED(unsigned long )
        PADDED(int )
        PADDED(int __user * )
        PADDED(int __user * )
        PADDED(int )
};
struct sys_clone_args {
        PADDED(unsigned long )
        PADDED(unsigned long )
        PADDED(int __user * )
        PADDED(int __user * )
        PADDED(int )
};
struct sys_execve_args {
        PADDED(const char __user * filename)
        PADDED(const char __user * const __user * argv)
        PADDED(const char __user * const __user * envp)
};
struct sys_perf_event_open_args {
        PADDED(struct perf_event_attr __user * attr_uptr)
        PADDED(pid_t pid)
        PADDED(int cpu)
        PADDED(int group_fd)
        PADDED(unsigned long flags)
};
struct sys_mmap_pgoff_args {
        PADDED(unsigned long addr)
        PADDED(unsigned long len)
        PADDED(unsigned long prot)
        PADDED(unsigned long flags)
        PADDED(unsigned long fd)
        PADDED(unsigned long pgoff)
};
struct sys_old_mmap_args {
        PADDED(struct mmap_arg_struct __user * arg)
};
struct sys_name_to_handle_at_args {
        PADDED(int dfd)
        PADDED(const char __user * name)
        PADDED(struct file_handle __user * handle)
        PADDED(int __user * mnt_id)
        PADDED(int flag)
};
struct sys_open_by_handle_at_args {
        PADDED(int mountdirfd)
        PADDED(struct file_handle __user * handle)
        PADDED(int flags)
};
struct sys_setns_args {
        PADDED(int fd)
        PADDED(int nstype)
};
struct sys_process_vm_readv_args {
        PADDED(pid_t pid)
        PADDED(const struct iovec __user * lvec)
        PADDED(unsigned long liovcnt)
        PADDED(const struct iovec __user * rvec)
        PADDED(unsigned long riovcnt)
        PADDED(unsigned long flags)
};
struct sys_process_vm_writev_args {
        PADDED(pid_t pid)
        PADDED(const struct iovec __user * lvec)
        PADDED(unsigned long liovcnt)
        PADDED(const struct iovec __user * rvec)
        PADDED(unsigned long riovcnt)
        PADDED(unsigned long flags)
};
struct sys_kcmp_args {
        PADDED(pid_t pid1)
        PADDED(pid_t pid2)
        PADDED(int type)
        PADDED(unsigned long idx1)
        PADDED(unsigned long idx2)
};
struct sys_finit_module_args {
        PADDED(int fd)
        PADDED(const char __user * uargs)
        PADDED(int flags)
};

struct syscall {
        PADDED(int syscall_number)
        union {
                struct sys_time_args sys_timeargs;
                struct sys_stime_args sys_stimeargs;
                struct sys_gettimeofday_args sys_gettimeofdayargs;
                struct sys_settimeofday_args sys_settimeofdayargs;
                struct sys_adjtimex_args sys_adjtimexargs;
                struct sys_times_args sys_timesargs;
                struct sys_gettid_args sys_gettidargs;
                struct sys_nanosleep_args sys_nanosleepargs;
                struct sys_alarm_args sys_alarmargs;
                struct sys_getpid_args sys_getpidargs;
                struct sys_getppid_args sys_getppidargs;
                struct sys_getuid_args sys_getuidargs;
                struct sys_geteuid_args sys_geteuidargs;
                struct sys_getgid_args sys_getgidargs;
                struct sys_getegid_args sys_getegidargs;
                struct sys_getresuid_args sys_getresuidargs;
                struct sys_getresgid_args sys_getresgidargs;
                struct sys_getpgid_args sys_getpgidargs;
                struct sys_getpgrp_args sys_getpgrpargs;
                struct sys_getsid_args sys_getsidargs;
                struct sys_getgroups_args sys_getgroupsargs;
                struct sys_setregid_args sys_setregidargs;
                struct sys_setgid_args sys_setgidargs;
                struct sys_setreuid_args sys_setreuidargs;
                struct sys_setuid_args sys_setuidargs;
                struct sys_setresuid_args sys_setresuidargs;
                struct sys_setresgid_args sys_setresgidargs;
                struct sys_setfsuid_args sys_setfsuidargs;
                struct sys_setfsgid_args sys_setfsgidargs;
                struct sys_setpgid_args sys_setpgidargs;
                struct sys_setsid_args sys_setsidargs;
                struct sys_setgroups_args sys_setgroupsargs;
                struct sys_acct_args sys_acctargs;
                struct sys_capget_args sys_capgetargs;
                struct sys_capset_args sys_capsetargs;
                struct sys_personality_args sys_personalityargs;
                struct sys_sigpending_args sys_sigpendingargs;
                struct sys_sigprocmask_args sys_sigprocmaskargs;
                struct sys_sigaltstack_args sys_sigaltstackargs;
                struct sys_getitimer_args sys_getitimerargs;
                struct sys_setitimer_args sys_setitimerargs;
                struct sys_timer_create_args sys_timer_createargs;
                struct sys_timer_gettime_args sys_timer_gettimeargs;
                struct sys_timer_getoverrun_args sys_timer_getoverrunargs;
                struct sys_timer_settime_args sys_timer_settimeargs;
                struct sys_timer_delete_args sys_timer_deleteargs;
                struct sys_clock_settime_args sys_clock_settimeargs;
                struct sys_clock_gettime_args sys_clock_gettimeargs;
                struct sys_clock_adjtime_args sys_clock_adjtimeargs;
                struct sys_clock_getres_args sys_clock_getresargs;
                struct sys_clock_nanosleep_args sys_clock_nanosleepargs;
                struct sys_nice_args sys_niceargs;
                struct sys_sched_setscheduler_args sys_sched_setschedulerargs;
                struct sys_sched_setparam_args sys_sched_setparamargs;
                struct sys_sched_setattr_args sys_sched_setattrargs;
                struct sys_sched_getscheduler_args sys_sched_getschedulerargs;
                struct sys_sched_getparam_args sys_sched_getparamargs;
                struct sys_sched_getattr_args sys_sched_getattrargs;
                struct sys_sched_setaffinity_args sys_sched_setaffinityargs;
                struct sys_sched_getaffinity_args sys_sched_getaffinityargs;
                struct sys_sched_yield_args sys_sched_yieldargs;
                struct sys_sched_get_priority_max_args sys_sched_get_priority_maxargs;
                struct sys_sched_get_priority_min_args sys_sched_get_priority_minargs;
                struct sys_sched_rr_get_interval_args sys_sched_rr_get_intervalargs;
                struct sys_setpriority_args sys_setpriorityargs;
                struct sys_getpriority_args sys_getpriorityargs;
                struct sys_shutdown_args sys_shutdownargs;
                struct sys_reboot_args sys_rebootargs;
                struct sys_restart_syscall_args sys_restart_syscallargs;
                struct sys_kexec_load_args sys_kexec_loadargs;
                struct sys_exit_args sys_exitargs;
                struct sys_exit_group_args sys_exit_groupargs;
                struct sys_wait4_args sys_wait4args;
                struct sys_waitid_args sys_waitidargs;
                struct sys_waitpid_args sys_waitpidargs;
                struct sys_set_tid_address_args sys_set_tid_addressargs;
                struct sys_futex_args sys_futexargs;
                struct sys_init_module_args sys_init_moduleargs;
                struct sys_delete_module_args sys_delete_moduleargs;
                struct sys_sigsuspend_args sys_sigsuspendargs;
                struct sys_sigsuspend_args sys_sigsuspendargs;
                struct sys_rt_sigsuspend_args sys_rt_sigsuspendargs;
                struct sys_sigaction_args sys_sigactionargs;
                struct sys_rt_sigaction_args sys_rt_sigactionargs;
                struct sys_rt_sigprocmask_args sys_rt_sigprocmaskargs;
                struct sys_rt_sigpending_args sys_rt_sigpendingargs;
                struct sys_rt_sigtimedwait_args sys_rt_sigtimedwaitargs;
                struct sys_rt_tgsigqueueinfo_args sys_rt_tgsigqueueinfoargs;
                struct sys_kill_args sys_killargs;
                struct sys_tgkill_args sys_tgkillargs;
                struct sys_tkill_args sys_tkillargs;
                struct sys_rt_sigqueueinfo_args sys_rt_sigqueueinfoargs;
                struct sys_sgetmask_args sys_sgetmaskargs;
                struct sys_ssetmask_args sys_ssetmaskargs;
                struct sys_signal_args sys_signalargs;
                struct sys_pause_args sys_pauseargs;
                struct sys_sync_args sys_syncargs;
                struct sys_fsync_args sys_fsyncargs;
                struct sys_fdatasync_args sys_fdatasyncargs;
                struct sys_bdflush_args sys_bdflushargs;
                struct sys_mount_args sys_mountargs;
                struct sys_umount_args sys_umountargs;
                struct sys_oldumount_args sys_oldumountargs;
                struct sys_truncate_args sys_truncateargs;
                struct sys_ftruncate_args sys_ftruncateargs;
                struct sys_stat_args sys_statargs;
                struct sys_statfs_args sys_statfsargs;
                struct sys_statfs64_args sys_statfs64args;
                struct sys_fstatfs_args sys_fstatfsargs;
                struct sys_fstatfs64_args sys_fstatfs64args;
                struct sys_lstat_args sys_lstatargs;
                struct sys_fstat_args sys_fstatargs;
                struct sys_newstat_args sys_newstatargs;
                struct sys_newlstat_args sys_newlstatargs;
                struct sys_newfstat_args sys_newfstatargs;
                struct sys_ustat_args sys_ustatargs;
                struct sys_stat64_args sys_stat64args;
                struct sys_fstat64_args sys_fstat64args;
                struct sys_lstat64_args sys_lstat64args;
                struct sys_truncate64_args sys_truncate64args;
                struct sys_ftruncate64_args sys_ftruncate64args;
                struct sys_setxattr_args sys_setxattrargs;
                struct sys_lsetxattr_args sys_lsetxattrargs;
                struct sys_fsetxattr_args sys_fsetxattrargs;
                struct sys_getxattr_args sys_getxattrargs;
                struct sys_lgetxattr_args sys_lgetxattrargs;
                struct sys_fgetxattr_args sys_fgetxattrargs;
                struct sys_listxattr_args sys_listxattrargs;
                struct sys_llistxattr_args sys_llistxattrargs;
                struct sys_flistxattr_args sys_flistxattrargs;
                struct sys_removexattr_args sys_removexattrargs;
                struct sys_lremovexattr_args sys_lremovexattrargs;
                struct sys_fremovexattr_args sys_fremovexattrargs;
                struct sys_brk_args sys_brkargs;
                struct sys_mprotect_args sys_mprotectargs;
                struct sys_mremap_args sys_mremapargs;
                struct sys_remap_file_pages_args sys_remap_file_pagesargs;
                struct sys_msync_args sys_msyncargs;
                struct sys_fadvise64_args sys_fadvise64args;
                struct sys_fadvise64_64_args sys_fadvise64_64args;
                struct sys_munmap_args sys_munmapargs;
                struct sys_mlock_args sys_mlockargs;
                struct sys_munlock_args sys_munlockargs;
                struct sys_mlockall_args sys_mlockallargs;
                struct sys_munlockall_args sys_munlockallargs;
                struct sys_madvise_args sys_madviseargs;
                struct sys_mincore_args sys_mincoreargs;
                struct sys_pivot_root_args sys_pivot_rootargs;
                struct sys_chroot_args sys_chrootargs;
                struct sys_mknod_args sys_mknodargs;
                struct sys_link_args sys_linkargs;
                struct sys_symlink_args sys_symlinkargs;
                struct sys_unlink_args sys_unlinkargs;
                struct sys_rename_args sys_renameargs;
                struct sys_chmod_args sys_chmodargs;
                struct sys_fchmod_args sys_fchmodargs;
                struct sys_fcntl_args sys_fcntlargs;
                struct sys_fcntl64_args sys_fcntl64args;
                struct sys_pipe_args sys_pipeargs;
                struct sys_pipe2_args sys_pipe2args;
                struct sys_dup_args sys_dupargs;
                struct sys_dup2_args sys_dup2args;
                struct sys_dup3_args sys_dup3args;
                struct sys_ioperm_args sys_iopermargs;
                struct sys_ioctl_args sys_ioctlargs;
                struct sys_flock_args sys_flockargs;
                struct sys_io_setup_args sys_io_setupargs;
                struct sys_io_destroy_args sys_io_destroyargs;
                struct sys_io_getevents_args sys_io_geteventsargs;
                struct sys_io_submit_args sys_io_submitargs;
                struct sys_io_cancel_args sys_io_cancelargs;
                struct sys_sendfile_args sys_sendfileargs;
                struct sys_sendfile64_args sys_sendfile64args;
                struct sys_readlink_args sys_readlinkargs;
                struct sys_creat_args sys_creatargs;
                struct sys_open_args sys_openargs;
                struct sys_close_args sys_closeargs;
                struct sys_access_args sys_accessargs;
                struct sys_vhangup_args sys_vhangupargs;
                struct sys_chown_args sys_chownargs;
                struct sys_lchown_args sys_lchownargs;
                struct sys_fchown_args sys_fchownargs;
                struct sys_chown16_args sys_chown16args;
                struct sys_lchown16_args sys_lchown16args;
                struct sys_fchown16_args sys_fchown16args;
                struct sys_setregid16_args sys_setregid16args;
                struct sys_setgid16_args sys_setgid16args;
                struct sys_setreuid16_args sys_setreuid16args;
                struct sys_setuid16_args sys_setuid16args;
                struct sys_setresuid16_args sys_setresuid16args;
                struct sys_getresuid16_args sys_getresuid16args;
                struct sys_setresgid16_args sys_setresgid16args;
                struct sys_getresgid16_args sys_getresgid16args;
                struct sys_setfsuid16_args sys_setfsuid16args;
                struct sys_setfsgid16_args sys_setfsgid16args;
                struct sys_getgroups16_args sys_getgroups16args;
                struct sys_setgroups16_args sys_setgroups16args;
                struct sys_getuid16_args sys_getuid16args;
                struct sys_geteuid16_args sys_geteuid16args;
                struct sys_getgid16_args sys_getgid16args;
                struct sys_getegid16_args sys_getegid16args;
                struct sys_utime_args sys_utimeargs;
                struct sys_utimes_args sys_utimesargs;
                struct sys_lseek_args sys_lseekargs;
                struct sys_llseek_args sys_llseekargs;
                struct sys_read_args sys_readargs;
                struct sys_readahead_args sys_readaheadargs;
                struct sys_readv_args sys_readvargs;
                struct sys_write_args sys_writeargs;
                struct sys_writev_args sys_writevargs;
                struct sys_pread64_args sys_pread64args;
                struct sys_pwrite64_args sys_pwrite64args;
                struct sys_preadv_args sys_preadvargs;
                struct sys_pwritev_args sys_pwritevargs;
                struct sys_getcwd_args sys_getcwdargs;
                struct sys_mkdir_args sys_mkdirargs;
                struct sys_chdir_args sys_chdirargs;
                struct sys_fchdir_args sys_fchdirargs;
                struct sys_rmdir_args sys_rmdirargs;
                struct sys_lookup_dcookie_args sys_lookup_dcookieargs;
                struct sys_quotactl_args sys_quotactlargs;
                struct sys_getdents_args sys_getdentsargs;
                struct sys_getdents64_args sys_getdents64args;
                struct sys_setsockopt_args sys_setsockoptargs;
                struct sys_getsockopt_args sys_getsockoptargs;
                struct sys_bind_args sys_bindargs;
                struct sys_connect_args sys_connectargs;
                struct sys_accept_args sys_acceptargs;
                struct sys_accept4_args sys_accept4args;
                struct sys_getsockname_args sys_getsocknameargs;
                struct sys_getpeername_args sys_getpeernameargs;
                struct sys_sendmsg_args sys_sendmsgargs;
                struct sys_sendmmsg_args sys_sendmmsgargs;
                struct sys_recvmsg_args sys_recvmsgargs;
                struct sys_recvmmsg_args sys_recvmmsgargs;
                struct sys_socket_args sys_socketargs;
                struct sys_socketpair_args sys_socketpairargs;
                struct sys_socketcall_args sys_socketcallargs;
                struct sys_listen_args sys_listenargs;
                struct sys_poll_args sys_pollargs;
                struct sys_select_args sys_selectargs;
                struct sys_old_select_args sys_old_selectargs;
                struct sys_epoll_create_args sys_epoll_createargs;
                struct sys_epoll_create1_args sys_epoll_create1args;
                struct sys_epoll_ctl_args sys_epoll_ctlargs;
                struct sys_epoll_wait_args sys_epoll_waitargs;
                struct sys_epoll_pwait_args sys_epoll_pwaitargs;
                struct sys_gethostname_args sys_gethostnameargs;
                struct sys_sethostname_args sys_sethostnameargs;
                struct sys_setdomainname_args sys_setdomainnameargs;
                struct sys_newuname_args sys_newunameargs;
                struct sys_uname_args sys_unameargs;
                struct sys_olduname_args sys_oldunameargs;
                struct sys_getrlimit_args sys_getrlimitargs;
                struct sys_old_getrlimit_args sys_old_getrlimitargs;
                struct sys_setrlimit_args sys_setrlimitargs;
                struct sys_prlimit64_args sys_prlimit64args;
                struct sys_getrusage_args sys_getrusageargs;
                struct sys_umask_args sys_umaskargs;
                struct sys_msgget_args sys_msggetargs;
                struct sys_msgsnd_args sys_msgsndargs;
                struct sys_msgrcv_args sys_msgrcvargs;
                struct sys_msgctl_args sys_msgctlargs;
                struct sys_semget_args sys_semgetargs;
                struct sys_semop_args sys_semopargs;
                struct sys_semctl_args sys_semctlargs;
                struct sys_semtimedop_args sys_semtimedopargs;
                struct sys_shmat_args sys_shmatargs;
                struct sys_shmget_args sys_shmgetargs;
                struct sys_shmdt_args sys_shmdtargs;
                struct sys_shmctl_args sys_shmctlargs;
                struct sys_ipc_args sys_ipcargs;
                struct sys_mq_open_args sys_mq_openargs;
                struct sys_mq_unlink_args sys_mq_unlinkargs;
                struct sys_mq_timedsend_args sys_mq_timedsendargs;
                struct sys_mq_timedreceive_args sys_mq_timedreceiveargs;
                struct sys_mq_notify_args sys_mq_notifyargs;
                struct sys_mq_getsetattr_args sys_mq_getsetattrargs;
                struct sys_pciconfig_iobase_args sys_pciconfig_iobaseargs;
                struct sys_pciconfig_read_args sys_pciconfig_readargs;
                struct sys_pciconfig_write_args sys_pciconfig_writeargs;
                struct sys_prctl_args sys_prctlargs;
                struct sys_swapon_args sys_swaponargs;
                struct sys_swapoff_args sys_swapoffargs;
                struct sys_sysctl_args sys_sysctlargs;
                struct sys_sysinfo_args sys_sysinfoargs;
                struct sys_sysfs_args sys_sysfsargs;
                struct sys_syslog_args sys_syslogargs;
                struct sys_uselib_args sys_uselibargs;
                struct sys_ni_syscall_args sys_ni_syscallargs;
                struct sys_ptrace_args sys_ptraceargs;
                struct sys_add_key_args sys_add_keyargs;
                struct sys_request_key_args sys_request_keyargs;
                struct sys_keyctl_args sys_keyctlargs;
                struct sys_ioprio_set_args sys_ioprio_setargs;
                struct sys_ioprio_get_args sys_ioprio_getargs;
                struct sys_set_mempolicy_args sys_set_mempolicyargs;
                struct sys_migrate_pages_args sys_migrate_pagesargs;
                struct sys_move_pages_args sys_move_pagesargs;
                struct sys_mbind_args sys_mbindargs;
                struct sys_get_mempolicy_args sys_get_mempolicyargs;
                struct sys_inotify_init_args sys_inotify_initargs;
                struct sys_inotify_init1_args sys_inotify_init1args;
                struct sys_inotify_add_watch_args sys_inotify_add_watchargs;
                struct sys_inotify_rm_watch_args sys_inotify_rm_watchargs;
                struct sys_spu_run_args sys_spu_runargs;
                struct sys_spu_create_args sys_spu_createargs;
                struct sys_mknodat_args sys_mknodatargs;
                struct sys_mkdirat_args sys_mkdiratargs;
                struct sys_unlinkat_args sys_unlinkatargs;
                struct sys_symlinkat_args sys_symlinkatargs;
                struct sys_linkat_args sys_linkatargs;
                struct sys_renameat_args sys_renameatargs;
                struct sys_renameat2_args sys_renameat2args;
                struct sys_futimesat_args sys_futimesatargs;
                struct sys_faccessat_args sys_faccessatargs;
                struct sys_fchmodat_args sys_fchmodatargs;
                struct sys_fchownat_args sys_fchownatargs;
                struct sys_openat_args sys_openatargs;
                struct sys_newfstatat_args sys_newfstatatargs;
                struct sys_fstatat64_args sys_fstatat64args;
                struct sys_readlinkat_args sys_readlinkatargs;
                struct sys_utimensat_args sys_utimensatargs;
                struct sys_unshare_args sys_unshareargs;
                struct sys_splice_args sys_spliceargs;
                struct sys_vmsplice_args sys_vmspliceargs;
                struct sys_tee_args sys_teeargs;
                struct sys_sync_file_range_args sys_sync_file_rangeargs;
                struct sys_sync_file_range2_args sys_sync_file_range2args;
                struct sys_get_robust_list_args sys_get_robust_listargs;
                struct sys_set_robust_list_args sys_set_robust_listargs;
                struct sys_getcpu_args sys_getcpuargs;
                struct sys_signalfd_args sys_signalfdargs;
                struct sys_signalfd4_args sys_signalfd4args;
                struct sys_timerfd_create_args sys_timerfd_createargs;
                struct sys_timerfd_settime_args sys_timerfd_settimeargs;
                struct sys_timerfd_gettime_args sys_timerfd_gettimeargs;
                struct sys_eventfd_args sys_eventfdargs;
                struct sys_eventfd2_args sys_eventfd2args;
                struct sys_fallocate_args sys_fallocateargs;
                struct sys_old_readdir_args sys_old_readdirargs;
                struct sys_pselect6_args sys_pselect6args;
                struct sys_ppoll_args sys_ppollargs;
                struct sys_fanotify_init_args sys_fanotify_initargs;
                struct sys_fanotify_mark_args sys_fanotify_markargs;
                struct sys_syncfs_args sys_syncfsargs;
                struct sys_fork_args sys_forkargs;
                struct sys_vfork_args sys_vforkargs;
                struct sys_clone_args sys_cloneargs;
                struct sys_clone_args sys_cloneargs;
                struct sys_clone_args sys_cloneargs;
                struct sys_execve_args sys_execveargs;
                struct sys_perf_event_open_args sys_perf_event_openargs;
                struct sys_mmap_pgoff_args sys_mmap_pgoffargs;
                struct sys_old_mmap_args sys_old_mmapargs;
                struct sys_name_to_handle_at_args sys_name_to_handle_atargs;
                struct sys_open_by_handle_at_args sys_open_by_handle_atargs;
                struct sys_setns_args sys_setnsargs;
                struct sys_process_vm_readv_args sys_process_vm_readvargs;
                struct sys_process_vm_writev_args sys_process_vm_writevargs;
                struct sys_kcmp_args sys_kcmpargs;
                struct sys_finit_module_args sys_finit_moduleargs;
        } syscall_args;
};
