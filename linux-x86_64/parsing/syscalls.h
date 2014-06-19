asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long sys_write(unsigned int fd, const char __user *buf,
			  size_t count);
asmlinkage long sys_open(const char __user *filename,
				int flags, umode_t mode);
asmlinkage long sys_getpid(void);
asmlinkage long sys_exit(int error_code);
asmlinkage long sys_time(time_t __user *tloc);
