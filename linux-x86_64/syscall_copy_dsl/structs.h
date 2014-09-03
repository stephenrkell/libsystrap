struct __sysctl_args {
  int    *name;
  int     nlen;
  void   *oldval;
  size_t *oldlenp;

  void   *newval;
  size_t  newlen;
};
struct epoll_event {
  uint32_t     events;
  epoll_data_t data;
};
struct iovec {
  void  *iov_base;
  size_t iov_len;
};
struct ipc_perm {
  key_t          __key;
  uid_t          uid;
  gid_t          gid;
  uid_t          cuid;
  gid_t          cgid;
  unsigned short mode;
  unsigned short __seq;
};
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};
struct itimerval {
  struct timeval it_interval;
  struct timeval it_value;
};
struct kexec_segment {
  void   *buf;
  size_t  bufsz;
  void   *mem;
  size_t  memsz;
};
struct linux_dirent {
  unsigned long  d_ino;
  unsigned long  d_off;
  unsigned short d_reclen;
  char           d_name[];
};
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int  msg_len;
};
struct msgbuf {
  long mtype;
  char mtext[1];
};
struct msghdr {
  void         *msg_name;
  socklen_t     msg_namelen;
  struct iovec *msg_iov;
  size_t        msg_iovlen;
  void         *msg_control;
  size_t        msg_controllen;
  int           msg_flags;
};
struct msqid_ds {
  struct ipc_perm msg_perm;
  time_t          msg_stime;
  time_t          msg_rtime;
  time_t          msg_ctime;
  unsigned long   __msg_cbytes;
  msgqnum_t       msg_qnum;
  msglen_t        msg_qbytes;
  pid_t           msg_lspid;
  pid_t           msg_lrpid;
};
struct pollfd {
  int   fd;
  short events;
  short revents;
};
struct rlimit {
  rlim_t rlim_cur;
  rlim_t rlim_max;
};
struct rusage {
  struct timeval ru_utime;
  struct timeval ru_stime;
  long   ru_maxrss;
  long   ru_ixrss;
  long   ru_idrss;
  long   ru_isrss;
  long   ru_minflt;
  long   ru_majflt;
  long   ru_nswap;
  long   ru_inblock;
  long   ru_oublock;
  long   ru_msgsnd;
  long   ru_msgrcv;
  long   ru_nsignals;
  long   ru_nvcsw;
  long   ru_nivcsw;
};
struct sockaddr {
  sa_family_t sa_family;
  char        sa_data[14];
}
struct stat {
  dev_t     st_dev;
  ino_t     st_ino;
  mode_t    st_mode;
  nlink_t   st_nlink;
  uid_t     st_uid;
  gid_t     st_gid;
  dev_t     st_rdev;
  off_t     st_size;
  blksize_t st_blksize;
  blkcnt_t  st_blocks;
  time_t    st_atime;
  time_t    st_mtime;
  time_t    st_ctime;
};
struct stat64
struct statfs {
  __SWORD_TYPE f_type;
  __SWORD_TYPE f_bsize;
  fsblkcnt_t   f_blocks;
  fsblkcnt_t   f_bfree;
  fsblkcnt_t   f_bavail;

  fsfilcnt_t   f_files;
  fsfilcnt_t   f_ffree;
  fsid_t       f_fsid;
  __SWORD_TYPE f_namelen;
  __SWORD_TYPE f_frsize;
  __SWORD_TYPE f_spare[5];
};
struct timespec {
  time_t tv_sec;
  long   tv_nsec;
};
struct timeval {
  time_t      tv_sec;
  suseconds_t tv_usec;
};
struct timex {
  int modes;
  long offset;
  long freq;
  long maxerror;
  long esterror;
  int status;
  long constant;
  long precision;
  long tolerance;

  struct timeval time;
  long tick;
};
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
  };
struct tms {
  clock_t tms_utime;
  clock_t tms_stime;
  clock_t tms_cutime;
  clock_t tms_cstime;
};
struct utimbuf {
  time_t actime;
  time_t modtime;
}
