STUB sys_read(unsigned int fd, mut char __user *buf, size_t count);
AUTO sys_write(unsigned int fd, const char __user *buf,
			  size_t count);
AUTO sys_open(const char __user *filename,
				int flags, umode_t mode);
AUTO sys_getpid(void);
AUTO sys_exit(int error_code);
AUTO sys_time(mut time_t __user *tloc);
