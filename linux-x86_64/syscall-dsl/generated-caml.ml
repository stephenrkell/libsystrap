let sys_time = {
  name = "sys_time";
  number = SYS_time;
  arguments = [
    ("tloc", Pointer("", time_t));
  ];
  footprint =
    Basic(Argument(tloc), Pointer("", time_t));
}
let sys_stime = {
  name = "sys_stime";
  number = SYS_stime;
  arguments = [
    ("tptr", Pointer("", time_t));
  ];
  footprint =
    Basic(Argument(tptr), Pointer("", time_t));
}
let sys_gettimeofday = {
  name = "sys_gettimeofday";
  number = SYS_gettimeofday;
  arguments = [
    ("tv", Pointer("", struct_timeval));
    ("tz", Pointer("", struct_timezone));
  ];
  footprint =
    Separation_star([
      struct_timeval_footprint Argument("tv");
      struct_timezone_footprint Argument("tz");
  ]);
}
let sys_settimeofday = {
  name = "sys_settimeofday";
  number = SYS_settimeofday;
  arguments = [
    ("tv", Pointer("", struct_timeval));
    ("tz", Pointer("", struct_timezone));
    ];
    footprint =
      Separation_star([
        struct_timeval_footprint Argument("tv");
        struct_timezone_footprint Argument("tz");
  ]);
}
let sys_adjtimex = {
  name = "sys_adjtimex";
  number = SYS_adjtimex;
  arguments = [
    ("txc_p", Pointer("", struct_timex));
      ];
      footprint =
        struct_timex_footprint Argument("txc_p");
}
let sys_times = {
  name = "sys_times";
  number = SYS_times;
  arguments = [
    ("tbuf", Pointer("", struct_tms));
  ];
  footprint =
    struct_tms_footprint Argument("tbuf");
}
let sys_gettid = {
  name = "sys_gettid";
  number = SYS_gettid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_nanosleep = {
  name = "sys_nanosleep";
  number = SYS_nanosleep;
  arguments = [
    ("rqtp", Pointer("", struct_timespec));
    ("rmtp", Pointer("", struct_timespec));
  ];
  footprint =
    Separation_star([
      struct_timespec_footprint Argument("rqtp");
      struct_timespec_footprint Argument("rmtp");
  ]);
}
let sys_alarm = {
  name = "sys_alarm";
  number = SYS_alarm;
  arguments = [
    ("seconds", Basic(int));
    ];
    footprint =
      Void;
}
let sys_getpid = {
  name = "sys_getpid";
  number = SYS_getpid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getppid = {
  name = "sys_getppid";
  number = SYS_getppid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getuid = {
  name = "sys_getuid";
  number = SYS_getuid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_geteuid = {
  name = "sys_geteuid";
  number = SYS_geteuid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getgid = {
  name = "sys_getgid";
  number = SYS_getgid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getegid = {
  name = "sys_getegid";
  number = SYS_getegid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getresuid = {
  name = "sys_getresuid";
  number = SYS_getresuid;
  arguments = [
    ("ruid", Pointer("", uid_t));
    ("euid", Pointer("", uid_t));
    ("suid", Pointer("", uid_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(ruid), Pointer("", uid_t));
      Basic(Argument(euid), Pointer("", uid_t));
      Basic(Argument(suid), Pointer("", uid_t));
  ]);
}
let sys_getresgid = {
  name = "sys_getresgid";
  number = SYS_getresgid;
  arguments = [
    ("rgid", Pointer("", gid_t));
    ("egid", Pointer("", gid_t));
    ("sgid", Pointer("", gid_t));
    ];
    footprint =
      Separation_star([
        Basic(Argument(rgid), Pointer("", gid_t));
        Basic(Argument(egid), Pointer("", gid_t));
        Basic(Argument(sgid), Pointer("", gid_t));
  ]);
}
let sys_getpgid = {
  name = "sys_getpgid";
  number = SYS_getpgid;
  arguments = [
    ("pid", Basic(pid_t));
      ];
      footprint =
        Void;
}
let sys_getpgrp = {
  name = "sys_getpgrp";
  number = SYS_getpgrp;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getsid = {
  name = "sys_getsid";
  number = SYS_getsid;
  arguments = [
    ("pid", Basic(pid_t));
  ];
  footprint =
    Void;
}
let sys_getgroups = {
  name = "sys_getgroups";
  number = SYS_getgroups;
  arguments = [
    ("gidsetsize", Basic(int));
    ("grouplist", Pointer("", gid_t));
  ];
  footprint =
    Basic(Argument(grouplist), Pointer("", gid_t));
}
let sys_setregid = {
  name = "sys_setregid";
  number = SYS_setregid;
  arguments = [
    ("rgid", Basic(gid_t));
    ("egid", Basic(gid_t));
  ];
  footprint =
    Void;
}
let sys_setgid = {
  name = "sys_setgid";
  number = SYS_setgid;
  arguments = [
    ("gid", Basic(gid_t));
  ];
  footprint =
    Void;
}
let sys_setreuid = {
  name = "sys_setreuid";
  number = SYS_setreuid;
  arguments = [
    ("ruid", Basic(uid_t));
    ("euid", Basic(uid_t));
  ];
  footprint =
    Void;
}
let sys_setuid = {
  name = "sys_setuid";
  number = SYS_setuid;
  arguments = [
    ("uid", Basic(uid_t));
  ];
  footprint =
    Void;
}
let sys_setresuid = {
  name = "sys_setresuid";
  number = SYS_setresuid;
  arguments = [
    ("ruid", Basic(uid_t));
    ("euid", Basic(uid_t));
    ("suid", Basic(uid_t));
  ];
  footprint =
    Void;
}
let sys_setresgid = {
  name = "sys_setresgid";
  number = SYS_setresgid;
  arguments = [
    ("rgid", Basic(gid_t));
    ("egid", Basic(gid_t));
    ("sgid", Basic(gid_t));
  ];
  footprint =
    Void;
}
let sys_setfsuid = {
  name = "sys_setfsuid";
  number = SYS_setfsuid;
  arguments = [
    ("uid", Basic(uid_t));
  ];
  footprint =
    Void;
}
let sys_setfsgid = {
  name = "sys_setfsgid";
  number = SYS_setfsgid;
  arguments = [
    ("gid", Basic(gid_t));
  ];
  footprint =
    Void;
}
let sys_setpgid = {
  name = "sys_setpgid";
  number = SYS_setpgid;
  arguments = [
    ("pid", Basic(pid_t));
    ("pgid", Basic(pid_t));
  ];
  footprint =
    Void;
}
let sys_setsid = {
  name = "sys_setsid";
  number = SYS_setsid;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_setgroups = {
  name = "sys_setgroups";
  number = SYS_setgroups;
  arguments = [
    ("gidsetsize", Basic(int));
    ("grouplist", Pointer("", gid_t));
  ];
  footprint =
    Basic(Argument(grouplist), Pointer("", gid_t));
}
let sys_acct = {
  name = "sys_acct";
  number = SYS_acct;
  arguments = [
    ("name", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(name), Pointer(const, char));
}
let sys_capget = {
  name = "sys_capget";
  number = SYS_capget;
  arguments = [
    ("header", Basic(cap_user_header_t));
    ("dataptr", Basic(cap_user_data_t));
  ];
  footprint =
    Void;
}
let sys_capset = {
  name = "sys_capset";
  number = SYS_capset;
  arguments = [
    ("header", Basic(cap_user_header_t));
    ("data", Basic(cap_user_data_t));
  ];
  footprint =
    Void;
}
let sys_personality = {
  name = "sys_personality";
  number = SYS_personality;
  arguments = [
    ("personality", Basic(int));
  ];
  footprint =
    Void;
}
let sys_sigpending = {
  name = "sys_sigpending";
  number = SYS_sigpending;
  arguments = [
    ("set", Pointer("", old_sigset_t));
  ];
  footprint =
    Basic(Argument(set), Pointer("", old_sigset_t));
}
let sys_sigprocmask = {
  name = "sys_sigprocmask";
  number = SYS_sigprocmask;
  arguments = [
    ("how", Basic(int));
    ("set", Pointer("", old_sigset_t));
    ("oset", Pointer("", old_sigset_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(set), Pointer("", old_sigset_t));
      Basic(Argument(oset), Pointer("", old_sigset_t));
  ]);
}
let sys_getitimer = {
  name = "sys_getitimer";
  number = SYS_getitimer;
  arguments = [
    ("which", Basic(int));
    ("value", Pointer("", struct_itimerval));
    ];
    footprint =
      struct_itimerval_footprint Argument("value");
}
let sys_setitimer = {
  name = "sys_setitimer";
  number = SYS_setitimer;
  arguments = [
    ("which", Basic(int));
    ("value", Pointer("", struct_itimerval));
    ("ovalue", Pointer("", struct_itimerval));
  ];
  footprint =
    Separation_star([
      struct_itimerval_footprint Argument("value");
      struct_itimerval_footprint Argument("ovalue");
  ]);
}
let sys_timer_create = {
  name = "sys_timer_create";
  number = SYS_timer_create;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("timer_event_spec", Pointer("", struct_sigevent));
    ("created_timer_id", Pointer("", timer_t));
    ];
    footprint =
      Separation_star([
        struct_sigevent_footprint Argument("timer_event_spec");
        Basic(Argument(created_timer_id), Pointer("", timer_t));
  ]);
}
let sys_timer_gettime = {
  name = "sys_timer_gettime";
  number = SYS_timer_gettime;
  arguments = [
    ("timer_id", Basic(timer_t));
    ("setting", Pointer("", struct_itimerspec));
      ];
      footprint =
        struct_itimerspec_footprint Argument("setting");
}
let sys_timer_getoverrun = {
  name = "sys_timer_getoverrun";
  number = SYS_timer_getoverrun;
  arguments = [
    ("timer_id", Basic(timer_t));
  ];
  footprint =
    Void;
}
let sys_timer_settime = {
  name = "sys_timer_settime";
  number = SYS_timer_settime;
  arguments = [
    ("timer_id", Basic(timer_t));
    ("flags", Basic(int));
    ("new_setting", Pointer(const, struct_itimerspec));
    ("old_setting", Pointer("", struct_itimerspec));
  ];
  footprint =
    Separation_star([
      struct_itimerspec_footprint Argument("new_setting");
      struct_itimerspec_footprint Argument("old_setting");
  ]);
}
let sys_timer_delete = {
  name = "sys_timer_delete";
  number = SYS_timer_delete;
  arguments = [
    ("timer_id", Basic(timer_t));
    ];
    footprint =
      Void;
}
let sys_clock_settime = {
  name = "sys_clock_settime";
  number = SYS_clock_settime;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("tp", Pointer(const, struct_timespec));
  ];
  footprint =
    struct_timespec_footprint Argument("tp");
}
let sys_clock_gettime = {
  name = "sys_clock_gettime";
  number = SYS_clock_gettime;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("tp", Pointer("", struct_timespec));
  ];
  footprint =
    struct_timespec_footprint Argument("tp");
}
let sys_clock_adjtime = {
  name = "sys_clock_adjtime";
  number = SYS_clock_adjtime;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("tx", Pointer("", struct_timex));
  ];
  footprint =
    struct_timex_footprint Argument("tx");
}
let sys_clock_getres = {
  name = "sys_clock_getres";
  number = SYS_clock_getres;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("tp", Pointer("", struct_timespec));
  ];
  footprint =
    struct_timespec_footprint Argument("tp");
}
let sys_clock_nanosleep = {
  name = "sys_clock_nanosleep";
  number = SYS_clock_nanosleep;
  arguments = [
    ("which_clock", Basic(clockid_t));
    ("flags", Basic(int));
    ("rqtp", Pointer(const, struct_timespec));
    ("rmtp", Pointer("", struct_timespec));
  ];
  footprint =
    Separation_star([
      struct_timespec_footprint Argument("rqtp");
      struct_timespec_footprint Argument("rmtp");
  ]);
}
let sys_nice = {
  name = "sys_nice";
  number = SYS_nice;
  arguments = [
    ("increment", Basic(int));
    ];
    footprint =
      Void;
}
let sys_sched_setscheduler = {
  name = "sys_sched_setscheduler";
  number = SYS_sched_setscheduler;
  arguments = [
    ("pid", Basic(pid_t));
    ("policy", Basic(int));
    ("param", Pointer("", struct_sched_param));
  ];
  footprint =
    struct_sched_param_footprint Argument("param");
}
let sys_sched_setparam = {
  name = "sys_sched_setparam";
  number = SYS_sched_setparam;
  arguments = [
    ("pid", Basic(pid_t));
    ("param", Pointer("", struct_sched_param));
  ];
  footprint =
    struct_sched_param_footprint Argument("param");
}
let sys_sched_getscheduler = {
  name = "sys_sched_getscheduler";
  number = SYS_sched_getscheduler;
  arguments = [
    ("pid", Basic(pid_t));
  ];
  footprint =
    Void;
}
let sys_sched_getparam = {
  name = "sys_sched_getparam";
  number = SYS_sched_getparam;
  arguments = [
    ("pid", Basic(pid_t));
    ("param", Pointer("", struct_sched_param));
  ];
  footprint =
    struct_sched_param_footprint Argument("param");
}
let sys_sched_setaffinity = {
  name = "sys_sched_setaffinity";
  number = SYS_sched_setaffinity;
  arguments = [
    ("pid", Basic(pid_t));
    ("len", Basic(int));
    ("user_mask_ptr", Pointer("", long));
  ];
  footprint =
    Basic(Argument(user_mask_ptr), Pointer("", long));
}
let sys_sched_getaffinity = {
  name = "sys_sched_getaffinity";
  number = SYS_sched_getaffinity;
  arguments = [
    ("pid", Basic(pid_t));
    ("len", Basic(int));
    ("user_mask_ptr", Pointer("", long));
  ];
  footprint =
    Basic(Argument(user_mask_ptr), Pointer("", long));
}
let sys_sched_yield = {
  name = "sys_sched_yield";
  number = SYS_sched_yield;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_sched_get_priority_max = {
  name = "sys_sched_get_priority_max";
  number = SYS_sched_get_priority_max;
  arguments = [
    ("policy", Basic(int));
  ];
  footprint =
    Void;
}
let sys_sched_get_priority_min = {
  name = "sys_sched_get_priority_min";
  number = SYS_sched_get_priority_min;
  arguments = [
    ("policy", Basic(int));
  ];
  footprint =
    Void;
}
let sys_sched_rr_get_interval = {
  name = "sys_sched_rr_get_interval";
  number = SYS_sched_rr_get_interval;
  arguments = [
    ("pid", Basic(pid_t));
    ("interval", Pointer("", struct_timespec));
  ];
  footprint =
    struct_timespec_footprint Argument("interval");
}
let sys_setpriority = {
  name = "sys_setpriority";
  number = SYS_setpriority;
  arguments = [
    ("which", Basic(int));
    ("who", Basic(int));
    ("niceval", Basic(int));
  ];
  footprint =
    Void;
}
let sys_getpriority = {
  name = "sys_getpriority";
  number = SYS_getpriority;
  arguments = [
    ("which", Basic(int));
    ("who", Basic(int));
  ];
  footprint =
    Void;
}
let sys_shutdown = {
  name = "sys_shutdown";
  number = SYS_shutdown;
  arguments = [
    ("", Basic(int));
    ("", Basic(int));
  ];
  footprint =
    Void;
}
let sys_reboot = {
  name = "sys_reboot";
  number = SYS_reboot;
  arguments = [
    ("magic1", Basic(int));
    ("magic2", Basic(int));
    ("cmd", Basic(int));
    ("arg", Pointer("", void));
  ];
  footprint =
    Basic(Argument(arg), Pointer("", void));
}
let sys_restart_syscall = {
  name = "sys_restart_syscall";
  number = SYS_restart_syscall;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_kexec_load = {
  name = "sys_kexec_load";
  number = SYS_kexec_load;
  arguments = [
    ("entry", Basic(long));
    ("nr_segments", Basic(long));
    ("segments", Pointer("", struct_kexec_segment));
    ("flags", Basic(long));
  ];
  footprint =
    struct_kexec_segment_footprint Argument("segments");
}
let sys_exit = {
  name = "sys_exit";
  number = SYS_exit;
  arguments = [
    ("error_code", Basic(int));
  ];
  footprint =
    Void;
}
let sys_exit_group = {
  name = "sys_exit_group";
  number = SYS_exit_group;
  arguments = [
    ("error_code", Basic(int));
  ];
  footprint =
    Void;
}
let sys_wait4 = {
  name = "sys_wait4";
  number = SYS_wait4;
  arguments = [
    ("pid", Basic(pid_t));
    ("stat_addr", Pointer("", int));
    ("options", Basic(int));
    ("ru", Pointer("", struct_rusage));
  ];
  footprint =
    Separation_star([
      Basic(Argument(stat_addr), Pointer("", int));
      struct_rusage_footprint Argument("ru");
  ]);
}
let sys_waitid = {
  name = "sys_waitid";
  number = SYS_waitid;
  arguments = [
    ("which", Basic(int));
    ("pid", Basic(pid_t));
    ("infop", Pointer("", struct_siginfo));
    ("options", Basic(int));
    ("ru", Pointer("", struct_rusage));
    ];
    footprint =
      Separation_star([
        struct_siginfo_footprint Argument("infop");
        struct_rusage_footprint Argument("ru");
  ]);
}
let sys_waitpid = {
  name = "sys_waitpid";
  number = SYS_waitpid;
  arguments = [
    ("pid", Basic(pid_t));
    ("stat_addr", Pointer("", int));
    ("options", Basic(int));
      ];
      footprint =
        Basic(Argument(stat_addr), Pointer("", int));
}
let sys_set_tid_address = {
  name = "sys_set_tid_address";
  number = SYS_set_tid_address;
  arguments = [
    ("tidptr", Pointer("", int));
  ];
  footprint =
    Basic(Argument(tidptr), Pointer("", int));
}
let sys_futex = {
  name = "sys_futex";
  number = SYS_futex;
  arguments = [
    ("uaddr", Pointer("", u32));
    ("op", Basic(int));
    ("val", Basic(u32));
    ("utime", Pointer("", struct_timespec));
    ("uaddr2", Pointer("", u32));
    ("val3", Basic(u32));
  ];
  footprint =
    Separation_star([
      Basic(Argument(uaddr), Pointer("", u32));
      struct_timespec_footprint Argument("utime");
      Basic(Argument(uaddr2), Pointer("", u32));
  ]);
}
let sys_init_module = {
  name = "sys_init_module";
  number = SYS_init_module;
  arguments = [
    ("umod", Pointer("", void));
    ("len", Basic(long));
    ("uargs", Pointer(const, char));
    ];
    footprint =
      Separation_star([
        Basic(Argument(umod), Pointer("", void));
        Basic(Argument(uargs), Pointer(const, char));
  ]);
}
let sys_delete_module = {
  name = "sys_delete_module";
  number = SYS_delete_module;
  arguments = [
    ("name_user", Pointer(const, char));
    ("flags", Basic(int));
      ];
      footprint =
        Basic(Argument(name_user), Pointer(const, char));
}
let sys_rt_sigprocmask = {
  name = "sys_rt_sigprocmask";
  number = SYS_rt_sigprocmask;
  arguments = [
    ("how", Basic(int));
    ("set", Pointer("", sigset_t));
    ("oset", Pointer("", sigset_t));
    ("sigsetsize", Basic(size_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(set), Pointer("", sigset_t));
      Basic(Argument(oset), Pointer("", sigset_t));
  ]);
}
let sys_rt_sigpending = {
  name = "sys_rt_sigpending";
  number = SYS_rt_sigpending;
  arguments = [
    ("set", Pointer("", sigset_t));
    ("sigsetsize", Basic(size_t));
    ];
    footprint =
      Basic(Argument(set), Pointer("", sigset_t));
}
let sys_rt_sigtimedwait = {
  name = "sys_rt_sigtimedwait";
  number = SYS_rt_sigtimedwait;
  arguments = [
    ("uthese", Pointer(const, sigset_t));
    ("uinfo", Pointer("", siginfo_t));
    ("uts", Pointer(const, struct_timespec));
    ("sigsetsize", Basic(size_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(uthese), Pointer(const, sigset_t));
      Basic(Argument(uinfo), Pointer("", siginfo_t));
      struct_timespec_footprint Argument("uts");
  ]);
}
let sys_rt_tgsigqueueinfo = {
  name = "sys_rt_tgsigqueueinfo";
  number = SYS_rt_tgsigqueueinfo;
  arguments = [
    ("tgid", Basic(pid_t));
    ("pid", Basic(pid_t));
    ("sig", Basic(int));
    ("uinfo", Pointer("", siginfo_t));
    ];
    footprint =
      Basic(Argument(uinfo), Pointer("", siginfo_t));
}
let sys_kill = {
  name = "sys_kill";
  number = SYS_kill;
  arguments = [
    ("pid", Basic(int));
    ("sig", Basic(int));
  ];
  footprint =
    Void;
}
let sys_tgkill = {
  name = "sys_tgkill";
  number = SYS_tgkill;
  arguments = [
    ("tgid", Basic(int));
    ("pid", Basic(int));
    ("sig", Basic(int));
  ];
  footprint =
    Void;
}
let sys_tkill = {
  name = "sys_tkill";
  number = SYS_tkill;
  arguments = [
    ("pid", Basic(int));
    ("sig", Basic(int));
  ];
  footprint =
    Void;
}
let sys_rt_sigqueueinfo = {
  name = "sys_rt_sigqueueinfo";
  number = SYS_rt_sigqueueinfo;
  arguments = [
    ("pid", Basic(int));
    ("sig", Basic(int));
    ("uinfo", Pointer("", siginfo_t));
  ];
  footprint =
    Basic(Argument(uinfo), Pointer("", siginfo_t));
}
let sys_sgetmask = {
  name = "sys_sgetmask";
  number = SYS_sgetmask;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_ssetmask = {
  name = "sys_ssetmask";
  number = SYS_ssetmask;
  arguments = [
    ("newmask", Basic(int));
  ];
  footprint =
    Void;
}
let sys_signal = {
  name = "sys_signal";
  number = SYS_signal;
  arguments = [
    ("sig", Basic(int));
    ("handler", Basic(__sighandler_t));
  ];
  footprint =
    Void;
}
let sys_pause = {
  name = "sys_pause";
  number = SYS_pause;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_sync = {
  name = "sys_sync";
  number = SYS_sync;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_fsync = {
  name = "sys_fsync";
  number = SYS_fsync;
  arguments = [
    ("fd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_fdatasync = {
  name = "sys_fdatasync";
  number = SYS_fdatasync;
  arguments = [
    ("fd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_bdflush = {
  name = "sys_bdflush";
  number = SYS_bdflush;
  arguments = [
    ("func", Basic(int));
    ("data", Basic(long));
  ];
  footprint =
    Void;
}
let sys_mount = {
  name = "sys_mount";
  number = SYS_mount;
  arguments = [
    ("dev_name", Pointer("", char));
    ("dir_name", Pointer("", char));
    ("type", Pointer("", char));
    ("flags", Basic(long));
    ("data", Pointer("", void));
  ];
  footprint =
    Separation_star([
      Basic(Argument(dev_name), Pointer("", char));
      Basic(Argument(dir_name), Pointer("", char));
      Basic(Argument(type), Pointer("", char));
      Basic(Argument(data), Pointer("", void));
  ]);
}
let sys_umount = {
  name = "sys_umount";
  number = SYS_umount;
  arguments = [
    ("name", Pointer("", char));
    ("flags", Basic(int));
    ];
    footprint =
      Basic(Argument(name), Pointer("", char));
}
let sys_oldumount = {
  name = "sys_oldumount";
  number = SYS_oldumount;
  arguments = [
    ("name", Pointer("", char));
  ];
  footprint =
    Basic(Argument(name), Pointer("", char));
}
let sys_truncate = {
  name = "sys_truncate";
  number = SYS_truncate;
  arguments = [
    ("path", Pointer(const, char));
    ("length", Basic(long));
  ];
  footprint =
    Basic(Argument(path), Pointer(const, char));
}
let sys_ftruncate = {
  name = "sys_ftruncate";
  number = SYS_ftruncate;
  arguments = [
    ("fd", Basic(int));
    ("length", Basic(long));
  ];
  footprint =
    Void;
}
let sys_stat = {
  name = "sys_stat";
  number = SYS_stat;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct___old_kernel_stat));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct___old_kernel_stat_footprint Argument("statbuf");
  ]);
}
let sys_statfs = {
  name = "sys_statfs";
  number = SYS_statfs;
  arguments = [
    ("path", Pointer(const, char));
    ("buf", Pointer("", struct_statfs));
    ];
    footprint =
      Separation_star([
        Basic(Argument(path), Pointer(const, char));
        struct_statfs_footprint Argument("buf");
  ]);
}
let sys_statfs64 = {
  name = "sys_statfs64";
  number = SYS_statfs64;
  arguments = [
    ("path", Pointer(const, char));
    ("sz", Basic(size_t));
    ("buf", Pointer("", struct_statfs64));
      ];
      footprint =
        Separation_star([
          Basic(Argument(path), Pointer(const, char));
          struct_statfs64_footprint Argument("buf");
  ]);
}
let sys_fstatfs = {
  name = "sys_fstatfs";
  number = SYS_fstatfs;
  arguments = [
    ("fd", Basic(int));
    ("buf", Pointer("", struct_statfs));
        ];
        footprint =
          struct_statfs_footprint Argument("buf");
}
let sys_fstatfs64 = {
  name = "sys_fstatfs64";
  number = SYS_fstatfs64;
  arguments = [
    ("fd", Basic(int));
    ("sz", Basic(size_t));
    ("buf", Pointer("", struct_statfs64));
  ];
  footprint =
    struct_statfs64_footprint Argument("buf");
}
let sys_lstat = {
  name = "sys_lstat";
  number = SYS_lstat;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct___old_kernel_stat));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct___old_kernel_stat_footprint Argument("statbuf");
  ]);
}
let sys_fstat = {
  name = "sys_fstat";
  number = SYS_fstat;
  arguments = [
    ("fd", Basic(int));
    ("statbuf", Pointer("", struct___old_kernel_stat));
    ];
    footprint =
      struct___old_kernel_stat_footprint Argument("statbuf");
}
let sys_newstat = {
  name = "sys_newstat";
  number = SYS_newstat;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct_stat_footprint Argument("statbuf");
  ]);
}
let sys_newlstat = {
  name = "sys_newlstat";
  number = SYS_newlstat;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat));
    ];
    footprint =
      Separation_star([
        Basic(Argument(filename), Pointer(const, char));
        struct_stat_footprint Argument("statbuf");
  ]);
}
let sys_newfstat = {
  name = "sys_newfstat";
  number = SYS_newfstat;
  arguments = [
    ("fd", Basic(int));
    ("statbuf", Pointer("", struct_stat));
      ];
      footprint =
        struct_stat_footprint Argument("statbuf");
}
let sys_ustat = {
  name = "sys_ustat";
  number = SYS_ustat;
  arguments = [
    ("", Basic(dev));
    ("ubuf", Pointer("", struct_ustat));
  ];
  footprint =
    struct_ustat_footprint Argument("ubuf");
}
let sys_stat64 = {
  name = "sys_stat64";
  number = SYS_stat64;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat64));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct_stat64_footprint Argument("statbuf");
  ]);
}
let sys_fstat64 = {
  name = "sys_fstat64";
  number = SYS_fstat64;
  arguments = [
    ("fd", Basic(long));
    ("statbuf", Pointer("", struct_stat64));
    ];
    footprint =
      struct_stat64_footprint Argument("statbuf");
}
let sys_lstat64 = {
  name = "sys_lstat64";
  number = SYS_lstat64;
  arguments = [
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat64));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct_stat64_footprint Argument("statbuf");
  ]);
}
let sys_truncate64 = {
  name = "sys_truncate64";
  number = SYS_truncate64;
  arguments = [
    ("path", Pointer(const, char));
    ("length", Basic(loff_t));
    ];
    footprint =
      Basic(Argument(path), Pointer(const, char));
}
let sys_ftruncate64 = {
  name = "sys_ftruncate64";
  number = SYS_ftruncate64;
  arguments = [
    ("fd", Basic(int));
    ("length", Basic(loff_t));
  ];
  footprint =
    Void;
}
let sys_setxattr = {
  name = "sys_setxattr";
  number = SYS_setxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
    ("value", Pointer(const, void));
    ("size", Basic(size_t));
    ("flags", Basic(int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(path), Pointer(const, char));
      Basic(Argument(name), Pointer(const, char));
      Basic(Argument(value), Pointer(const, void));
  ]);
}
let sys_lsetxattr = {
  name = "sys_lsetxattr";
  number = SYS_lsetxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
    ("value", Pointer(const, void));
    ("size", Basic(size_t));
    ("flags", Basic(int));
    ];
    footprint =
      Separation_star([
        Basic(Argument(path), Pointer(const, char));
        Basic(Argument(name), Pointer(const, char));
        Basic(Argument(value), Pointer(const, void));
  ]);
}
let sys_fsetxattr = {
  name = "sys_fsetxattr";
  number = SYS_fsetxattr;
  arguments = [
    ("fd", Basic(int));
    ("name", Pointer(const, char));
    ("value", Pointer(const, void));
    ("size", Basic(size_t));
    ("flags", Basic(int));
      ];
      footprint =
        Separation_star([
          Basic(Argument(name), Pointer(const, char));
          Basic(Argument(value), Pointer(const, void));
  ]);
}
let sys_getxattr = {
  name = "sys_getxattr";
  number = SYS_getxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
    ("value", Pointer("", void));
    ("size", Basic(size_t));
        ];
        footprint =
          Separation_star([
            Basic(Argument(path), Pointer(const, char));
            Basic(Argument(name), Pointer(const, char));
            Basic(Argument(value), Pointer("", void));
  ]);
}
let sys_lgetxattr = {
  name = "sys_lgetxattr";
  number = SYS_lgetxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
    ("value", Pointer("", void));
    ("size", Basic(size_t));
          ];
          footprint =
            Separation_star([
              Basic(Argument(path), Pointer(const, char));
              Basic(Argument(name), Pointer(const, char));
              Basic(Argument(value), Pointer("", void));
  ]);
}
let sys_fgetxattr = {
  name = "sys_fgetxattr";
  number = SYS_fgetxattr;
  arguments = [
    ("fd", Basic(int));
    ("name", Pointer(const, char));
    ("value", Pointer("", void));
    ("size", Basic(size_t));
            ];
            footprint =
              Separation_star([
                Basic(Argument(name), Pointer(const, char));
                Basic(Argument(value), Pointer("", void));
  ]);
}
let sys_listxattr = {
  name = "sys_listxattr";
  number = SYS_listxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("list", Pointer("", char));
    ("size", Basic(size_t));
              ];
              footprint =
                Separation_star([
                  Basic(Argument(path), Pointer(const, char));
                  Basic(Argument(list), Pointer("", char));
  ]);
}
let sys_llistxattr = {
  name = "sys_llistxattr";
  number = SYS_llistxattr;
  arguments = [
    ("path", Pointer(const, char));
    ("list", Pointer("", char));
    ("size", Basic(size_t));
                ];
                footprint =
                  Separation_star([
                    Basic(Argument(path), Pointer(const, char));
                    Basic(Argument(list), Pointer("", char));
  ]);
}
let sys_flistxattr = {
  name = "sys_flistxattr";
  number = SYS_flistxattr;
  arguments = [
    ("fd", Basic(int));
    ("list", Pointer("", char));
    ("size", Basic(size_t));
                  ];
                  footprint =
                    Basic(Argument(list), Pointer("", char));
}
let sys_removexattr = {
  name = "sys_removexattr";
  number = SYS_removexattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
  ];
  footprint =
    Separation_star([
      Basic(Argument(path), Pointer(const, char));
      Basic(Argument(name), Pointer(const, char));
  ]);
}
let sys_lremovexattr = {
  name = "sys_lremovexattr";
  number = SYS_lremovexattr;
  arguments = [
    ("path", Pointer(const, char));
    ("name", Pointer(const, char));
    ];
    footprint =
      Separation_star([
        Basic(Argument(path), Pointer(const, char));
        Basic(Argument(name), Pointer(const, char));
  ]);
}
let sys_fremovexattr = {
  name = "sys_fremovexattr";
  number = SYS_fremovexattr;
  arguments = [
    ("fd", Basic(int));
    ("name", Pointer(const, char));
      ];
      footprint =
        Basic(Argument(name), Pointer(const, char));
}
let sys_brk = {
  name = "sys_brk";
  number = SYS_brk;
  arguments = [
    ("brk", Basic(long));
  ];
  footprint =
    Void;
}
let sys_mprotect = {
  name = "sys_mprotect";
  number = SYS_mprotect;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
    ("prot", Basic(long));
  ];
  footprint =
    Void;
}
let sys_mremap = {
  name = "sys_mremap";
  number = SYS_mremap;
  arguments = [
    ("addr", Basic(long));
    ("old_len", Basic(long));
    ("new_len", Basic(long));
    ("flags", Basic(long));
    ("new_addr", Basic(long));
  ];
  footprint =
    Void;
}
let sys_remap_file_pages = {
  name = "sys_remap_file_pages";
  number = SYS_remap_file_pages;
  arguments = [
    ("start", Basic(long));
    ("size", Basic(long));
    ("prot", Basic(long));
    ("pgoff", Basic(long));
    ("flags", Basic(long));
  ];
  footprint =
    Void;
}
let sys_msync = {
  name = "sys_msync";
  number = SYS_msync;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_fadvise64 = {
  name = "sys_fadvise64";
  number = SYS_fadvise64;
  arguments = [
    ("fd", Basic(int));
    ("offset", Basic(loff_t));
    ("len", Basic(size_t));
    ("advice", Basic(int));
  ];
  footprint =
    Void;
}
let sys_fadvise64_64 = {
  name = "sys_fadvise64_64";
  number = SYS_fadvise64_64;
  arguments = [
    ("fd", Basic(int));
    ("offset", Basic(loff_t));
    ("len", Basic(loff_t));
    ("advice", Basic(int));
  ];
  footprint =
    Void;
}
let sys_munmap = {
  name = "sys_munmap";
  number = SYS_munmap;
  arguments = [
    ("addr", Basic(long));
    ("len", Basic(size_t));
  ];
  footprint =
    Void;
}
let sys_mlock = {
  name = "sys_mlock";
  number = SYS_mlock;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
  ];
  footprint =
    Void;
}
let sys_munlock = {
  name = "sys_munlock";
  number = SYS_munlock;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
  ];
  footprint =
    Void;
}
let sys_mlockall = {
  name = "sys_mlockall";
  number = SYS_mlockall;
  arguments = [
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_munlockall = {
  name = "sys_munlockall";
  number = SYS_munlockall;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_madvise = {
  name = "sys_madvise";
  number = SYS_madvise;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
    ("behavior", Basic(int));
  ];
  footprint =
    Void;
}
let sys_mincore = {
  name = "sys_mincore";
  number = SYS_mincore;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(size_t));
    ("vec", Pointer("", char));
  ];
  footprint =
    Basic(Argument(vec), Pointer("", char));
}
let sys_pivot_root = {
  name = "sys_pivot_root";
  number = SYS_pivot_root;
  arguments = [
    ("new_root", Pointer(const, char));
    ("put_old", Pointer(const, char));
  ];
  footprint =
    Separation_star([
      Basic(Argument(new_root), Pointer(const, char));
      Basic(Argument(put_old), Pointer(const, char));
  ]);
}
let sys_chroot = {
  name = "sys_chroot";
  number = SYS_chroot;
  arguments = [
    ("filename", Pointer(const, char));
    ];
    footprint =
      Basic(Argument(filename), Pointer(const, char));
}
let sys_mknod = {
  name = "sys_mknod";
  number = SYS_mknod;
  arguments = [
    ("filename", Pointer(const, char));
    ("mode", Basic(int));
    ("", Basic(dev));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_link = {
  name = "sys_link";
  number = SYS_link;
  arguments = [
    ("oldname", Pointer(const, char));
    ("newname", Pointer(const, char));
  ];
  footprint =
    Separation_star([
      Basic(Argument(oldname), Pointer(const, char));
      Basic(Argument(newname), Pointer(const, char));
  ]);
}
let sys_symlink = {
  name = "sys_symlink";
  number = SYS_symlink;
  arguments = [
    ("old", Pointer(const, char));
    ("new", Pointer(const, char));
    ];
    footprint =
      Separation_star([
        Basic(Argument(old), Pointer(const, char));
        Basic(Argument(new), Pointer(const, char));
  ]);
}
let sys_unlink = {
  name = "sys_unlink";
  number = SYS_unlink;
  arguments = [
    ("pathname", Pointer(const, char));
      ];
      footprint =
        Basic(Argument(pathname), Pointer(const, char));
}
let sys_rename = {
  name = "sys_rename";
  number = SYS_rename;
  arguments = [
    ("oldname", Pointer(const, char));
    ("newname", Pointer(const, char));
  ];
  footprint =
    Separation_star([
      Basic(Argument(oldname), Pointer(const, char));
      Basic(Argument(newname), Pointer(const, char));
  ]);
}
let sys_chmod = {
  name = "sys_chmod";
  number = SYS_chmod;
  arguments = [
    ("filename", Pointer(const, char));
    ("mode", Basic(mode_t));
    ];
    footprint =
      Basic(Argument(filename), Pointer(const, char));
}
let sys_fchmod = {
  name = "sys_fchmod";
  number = SYS_fchmod;
  arguments = [
    ("fd", Basic(int));
    ("mode", Basic(mode_t));
  ];
  footprint =
    Void;
}
let sys_fcntl = {
  name = "sys_fcntl";
  number = SYS_fcntl;
  arguments = [
    ("fd", Basic(int));
    ("cmd", Basic(int));
    ("arg", Basic(long));
  ];
  footprint =
    Void;
}
let sys_fcntl64 = {
  name = "sys_fcntl64";
  number = SYS_fcntl64;
  arguments = [
    ("fd", Basic(int));
    ("cmd", Basic(int));
    ("arg", Basic(long));
  ];
  footprint =
    Void;
}
let sys_pipe = {
  name = "sys_pipe";
  number = SYS_pipe;
  arguments = [
    ("fildes", Pointer("", int));
  ];
  footprint =
    Basic(Argument(fildes), Pointer("", int));
}
let sys_pipe2 = {
  name = "sys_pipe2";
  number = SYS_pipe2;
  arguments = [
    ("fildes", Pointer("", int));
    ("flags", Basic(int));
  ];
  footprint =
    Basic(Argument(fildes), Pointer("", int));
}
let sys_dup = {
  name = "sys_dup";
  number = SYS_dup;
  arguments = [
    ("fildes", Basic(int));
  ];
  footprint =
    Void;
}
let sys_dup2 = {
  name = "sys_dup2";
  number = SYS_dup2;
  arguments = [
    ("oldfd", Basic(int));
    ("newfd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_dup3 = {
  name = "sys_dup3";
  number = SYS_dup3;
  arguments = [
    ("oldfd", Basic(int));
    ("newfd", Basic(int));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_ioperm = {
  name = "sys_ioperm";
  number = SYS_ioperm;
  arguments = [
    ("from", Basic(long));
    ("num", Basic(long));
    ("on", Basic(int));
  ];
  footprint =
    Void;
}
let sys_ioctl = {
  name = "sys_ioctl";
  number = SYS_ioctl;
  arguments = [
    ("fd", Basic(int));
    ("cmd", Basic(int));
    ("arg", Basic(long));
  ];
  footprint =
    Void;
}
let sys_flock = {
  name = "sys_flock";
  number = SYS_flock;
  arguments = [
    ("fd", Basic(int));
    ("cmd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_io_setup = {
  name = "sys_io_setup";
  number = SYS_io_setup;
  arguments = [
    ("", Basic(nr_reqs));
    ("ctx", Pointer("", aio_context_t));
  ];
  footprint =
    Basic(Argument(ctx), Pointer("", aio_context_t));
}
let sys_io_destroy = {
  name = "sys_io_destroy";
  number = SYS_io_destroy;
  arguments = [
    ("ctx", Basic(aio_context_t));
  ];
  footprint =
    Void;
}
let sys_io_getevents = {
  name = "sys_io_getevents";
  number = SYS_io_getevents;
  arguments = [
    ("ctx_id", Basic(aio_context_t));
    ("min_nr", Basic(long));
    ("nr", Basic(long));
    ("events", Pointer("", struct_io_event));
    ("timeout", Pointer("", struct_timespec));
  ];
  footprint =
    Separation_star([
      struct_io_event_footprint Argument("events");
      struct_timespec_footprint Argument("timeout");
  ]);
}
let sys_io_submit = {
  name = "sys_io_submit";
  number = SYS_io_submit;
  arguments = [
    ("", Basic(aio_context_t));
    ("", Basic(long));
    ("", Pointer("", struct_iocb));
    ];
    footprint =
      struct_iocb_footprint Argument("");
}
let sys_io_cancel = {
  name = "sys_io_cancel";
  number = SYS_io_cancel;
  arguments = [
    ("ctx_id", Basic(aio_context_t));
    ("iocb", Pointer("", struct_iocb));
    ("result", Pointer("", struct_io_event));
  ];
  footprint =
    Separation_star([
      struct_iocb_footprint Argument("iocb");
      struct_io_event_footprint Argument("result");
  ]);
}
let sys_sendfile = {
  name = "sys_sendfile";
  number = SYS_sendfile;
  arguments = [
    ("out_fd", Basic(int));
    ("in_fd", Basic(int));
    ("offset", Pointer("", off_t));
    ("count", Basic(size_t));
    ];
    footprint =
      Basic(Argument(offset), Pointer("", off_t));
}
let sys_sendfile64 = {
  name = "sys_sendfile64";
  number = SYS_sendfile64;
  arguments = [
    ("out_fd", Basic(int));
    ("in_fd", Basic(int));
    ("offset", Pointer("", loff_t));
    ("count", Basic(size_t));
  ];
  footprint =
    Basic(Argument(offset), Pointer("", loff_t));
}
let sys_readlink = {
  name = "sys_readlink";
  number = SYS_readlink;
  arguments = [
    ("path", Pointer(const, char));
    ("buf", Pointer("", char));
    ("bufsiz", Basic(int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(path), Pointer(const, char));
      Basic(Argument(buf), Pointer("", char));
  ]);
}
let sys_creat = {
  name = "sys_creat";
  number = SYS_creat;
  arguments = [
    ("pathname", Pointer(const, char));
    ("mode", Basic(int));
    ];
    footprint =
      Basic(Argument(pathname), Pointer(const, char));
}
let sys_open = {
  name = "sys_open";
  number = SYS_open;
  arguments = [
    ("filename", Pointer(const, char));
    ("flags", Basic(int));
    ("mode", Basic(int));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_close = {
  name = "sys_close";
  number = SYS_close;
  arguments = [
    ("fd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_access = {
  name = "sys_access";
  number = SYS_access;
  arguments = [
    ("filename", Pointer(const, char));
    ("mode", Basic(int));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_vhangup = {
  name = "sys_vhangup";
  number = SYS_vhangup;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_chown = {
  name = "sys_chown";
  number = SYS_chown;
  arguments = [
    ("filename", Pointer(const, char));
    ("user", Basic(uid_t));
    ("group", Basic(gid_t));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_lchown = {
  name = "sys_lchown";
  number = SYS_lchown;
  arguments = [
    ("filename", Pointer(const, char));
    ("user", Basic(uid_t));
    ("group", Basic(gid_t));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_fchown = {
  name = "sys_fchown";
  number = SYS_fchown;
  arguments = [
    ("fd", Basic(int));
    ("user", Basic(uid_t));
    ("group", Basic(gid_t));
  ];
  footprint =
    Void;
}
let sys_chown16 = {
  name = "sys_chown16";
  number = SYS_chown16;
  arguments = [
    ("filename", Pointer(const, char));
    ("user", Basic(old_uid_t));
    ("group", Basic(old_gid_t));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_lchown16 = {
  name = "sys_lchown16";
  number = SYS_lchown16;
  arguments = [
    ("filename", Pointer(const, char));
    ("user", Basic(old_uid_t));
    ("group", Basic(old_gid_t));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_fchown16 = {
  name = "sys_fchown16";
  number = SYS_fchown16;
  arguments = [
    ("fd", Basic(int));
    ("user", Basic(old_uid_t));
    ("group", Basic(old_gid_t));
  ];
  footprint =
    Void;
}
let sys_setregid16 = {
  name = "sys_setregid16";
  number = SYS_setregid16;
  arguments = [
    ("rgid", Basic(old_gid_t));
    ("egid", Basic(old_gid_t));
  ];
  footprint =
    Void;
}
let sys_setgid16 = {
  name = "sys_setgid16";
  number = SYS_setgid16;
  arguments = [
    ("gid", Basic(old_gid_t));
  ];
  footprint =
    Void;
}
let sys_setreuid16 = {
  name = "sys_setreuid16";
  number = SYS_setreuid16;
  arguments = [
    ("ruid", Basic(old_uid_t));
    ("euid", Basic(old_uid_t));
  ];
  footprint =
    Void;
}
let sys_setuid16 = {
  name = "sys_setuid16";
  number = SYS_setuid16;
  arguments = [
    ("uid", Basic(old_uid_t));
  ];
  footprint =
    Void;
}
let sys_setresuid16 = {
  name = "sys_setresuid16";
  number = SYS_setresuid16;
  arguments = [
    ("ruid", Basic(old_uid_t));
    ("euid", Basic(old_uid_t));
    ("suid", Basic(old_uid_t));
  ];
  footprint =
    Void;
}
let sys_getresuid16 = {
  name = "sys_getresuid16";
  number = SYS_getresuid16;
  arguments = [
    ("ruid", Pointer("", old_uid_t));
    ("euid", Pointer("", old_uid_t));
    ("suid", Pointer("", old_uid_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(ruid), Pointer("", old_uid_t));
      Basic(Argument(euid), Pointer("", old_uid_t));
      Basic(Argument(suid), Pointer("", old_uid_t));
  ]);
}
let sys_setresgid16 = {
  name = "sys_setresgid16";
  number = SYS_setresgid16;
  arguments = [
    ("rgid", Basic(old_gid_t));
    ("egid", Basic(old_gid_t));
    ("sgid", Basic(old_gid_t));
    ];
    footprint =
      Void;
}
let sys_getresgid16 = {
  name = "sys_getresgid16";
  number = SYS_getresgid16;
  arguments = [
    ("rgid", Pointer("", old_gid_t));
    ("egid", Pointer("", old_gid_t));
    ("sgid", Pointer("", old_gid_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(rgid), Pointer("", old_gid_t));
      Basic(Argument(egid), Pointer("", old_gid_t));
      Basic(Argument(sgid), Pointer("", old_gid_t));
  ]);
}
let sys_setfsuid16 = {
  name = "sys_setfsuid16";
  number = SYS_setfsuid16;
  arguments = [
    ("uid", Basic(old_uid_t));
    ];
    footprint =
      Void;
}
let sys_setfsgid16 = {
  name = "sys_setfsgid16";
  number = SYS_setfsgid16;
  arguments = [
    ("gid", Basic(old_gid_t));
  ];
  footprint =
    Void;
}
let sys_getgroups16 = {
  name = "sys_getgroups16";
  number = SYS_getgroups16;
  arguments = [
    ("gidsetsize", Basic(int));
    ("grouplist", Pointer("", old_gid_t));
  ];
  footprint =
    Basic(Argument(grouplist), Pointer("", old_gid_t));
}
let sys_setgroups16 = {
  name = "sys_setgroups16";
  number = SYS_setgroups16;
  arguments = [
    ("gidsetsize", Basic(int));
    ("grouplist", Pointer("", old_gid_t));
  ];
  footprint =
    Basic(Argument(grouplist), Pointer("", old_gid_t));
}
let sys_getuid16 = {
  name = "sys_getuid16";
  number = SYS_getuid16;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_geteuid16 = {
  name = "sys_geteuid16";
  number = SYS_geteuid16;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getgid16 = {
  name = "sys_getgid16";
  number = SYS_getgid16;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_getegid16 = {
  name = "sys_getegid16";
  number = SYS_getegid16;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_utime = {
  name = "sys_utime";
  number = SYS_utime;
  arguments = [
    ("filename", Pointer("", char));
    ("times", Pointer("", struct_utimbuf));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer("", char));
      struct_utimbuf_footprint Argument("times");
  ]);
}
let sys_utimes = {
  name = "sys_utimes";
  number = SYS_utimes;
  arguments = [
    ("filename", Pointer("", char));
    ("utimes", Pointer("", struct_timeval));
    ];
    footprint =
      Separation_star([
        Basic(Argument(filename), Pointer("", char));
        struct_timeval_footprint Argument("utimes");
  ]);
}
let sys_lseek = {
  name = "sys_lseek";
  number = SYS_lseek;
  arguments = [
    ("fd", Basic(int));
    ("offset", Basic(off_t));
    ("origin", Basic(int));
      ];
      footprint =
        Void;
}
let sys_llseek = {
  name = "sys_llseek";
  number = SYS_llseek;
  arguments = [
    ("fd", Basic(int));
    ("offset_high", Basic(long));
    ("offset_low", Basic(long));
    ("result", Pointer("", loff_t));
    ("origin", Basic(int));
  ];
  footprint =
    Basic(Argument(result), Pointer("", loff_t));
}
let sys_read = {
  name = "sys_read";
  number = SYS_read;
  arguments = [
    ("fd", Basic(int));
    ("buf", Pointer("", char));
    ("count", Basic(size_t));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", char));
}
let sys_readahead = {
  name = "sys_readahead";
  number = SYS_readahead;
  arguments = [
    ("fd", Basic(int));
    ("offset", Basic(loff_t));
    ("count", Basic(size_t));
  ];
  footprint =
    Void;
}
let sys_readv = {
  name = "sys_readv";
  number = SYS_readv;
  arguments = [
    ("fd", Basic(long));
    ("vec", Pointer(const, struct_iovec));
    ("vlen", Basic(long));
  ];
  footprint =
    struct_iovec_footprint Argument("vec");
}
let sys_write = {
  name = "sys_write";
  number = SYS_write;
  arguments = [
    ("fd", Basic(int));
    ("buf", Pointer(const, char));
    ("count", Basic(size_t));
  ];
  footprint =
    Basic(Argument(buf), Pointer(const, char));
}
let sys_writev = {
  name = "sys_writev";
  number = SYS_writev;
  arguments = [
    ("fd", Basic(long));
    ("vec", Pointer(const, struct_iovec));
    ("vlen", Basic(long));
  ];
  footprint =
    struct_iovec_footprint Argument("vec");
}
let sys_pread64 = {
  name = "sys_pread64";
  number = SYS_pread64;
  arguments = [
    ("fd", Basic(int));
    ("buf", Pointer("", char));
    ("count", Basic(size_t));
    ("pos", Basic(loff_t));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", char));
}
let sys_pwrite64 = {
  name = "sys_pwrite64";
  number = SYS_pwrite64;
  arguments = [
    ("fd", Basic(int));
    ("buf", Pointer(const, char));
    ("count", Basic(size_t));
    ("pos", Basic(loff_t));
  ];
  footprint =
    Basic(Argument(buf), Pointer(const, char));
}
let sys_preadv = {
  name = "sys_preadv";
  number = SYS_preadv;
  arguments = [
    ("fd", Basic(long));
    ("vec", Pointer(const, struct_iovec));
    ("vlen", Basic(long));
    ("pos_l", Basic(long));
    ("pos_h", Basic(long));
  ];
  footprint =
    struct_iovec_footprint Argument("vec");
}
let sys_pwritev = {
  name = "sys_pwritev";
  number = SYS_pwritev;
  arguments = [
    ("fd", Basic(long));
    ("vec", Pointer(const, struct_iovec));
    ("vlen", Basic(long));
    ("pos_l", Basic(long));
    ("pos_h", Basic(long));
  ];
  footprint =
    struct_iovec_footprint Argument("vec");
}
let sys_getcwd = {
  name = "sys_getcwd";
  number = SYS_getcwd;
  arguments = [
    ("buf", Pointer("", char));
    ("size", Basic(long));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", char));
}
let sys_mkdir = {
  name = "sys_mkdir";
  number = SYS_mkdir;
  arguments = [
    ("pathname", Pointer(const, char));
    ("mode", Basic(int));
  ];
  footprint =
    Basic(Argument(pathname), Pointer(const, char));
}
let sys_chdir = {
  name = "sys_chdir";
  number = SYS_chdir;
  arguments = [
    ("filename", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_fchdir = {
  name = "sys_fchdir";
  number = SYS_fchdir;
  arguments = [
    ("fd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_rmdir = {
  name = "sys_rmdir";
  number = SYS_rmdir;
  arguments = [
    ("pathname", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(pathname), Pointer(const, char));
}
let sys_lookup_dcookie = {
  name = "sys_lookup_dcookie";
  number = SYS_lookup_dcookie;
  arguments = [
    ("cookie64", Basic(u64));
    ("buf", Pointer("", char));
    ("len", Basic(size_t));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", char));
}
let sys_quotactl = {
  name = "sys_quotactl";
  number = SYS_quotactl;
  arguments = [
    ("cmd", Basic(int));
    ("special", Pointer(const, char));
    ("id", Basic(qid_t));
    ("addr", Pointer("", void));
  ];
  footprint =
    Separation_star([
      Basic(Argument(special), Pointer(const, char));
      Basic(Argument(addr), Pointer("", void));
  ]);
}
let sys_getdents = {
  name = "sys_getdents";
  number = SYS_getdents;
  arguments = [
    ("fd", Basic(int));
    ("dirent", Pointer("", struct_linux_dirent));
    ("count", Basic(int));
    ];
    footprint =
      struct_linux_dirent_footprint Argument("dirent");
}
let sys_getdents64 = {
  name = "sys_getdents64";
  number = SYS_getdents64;
  arguments = [
    ("fd", Basic(int));
    ("dirent", Pointer("", struct_linux_dirent64));
    ("count", Basic(int));
  ];
  footprint =
    struct_linux_dirent64_footprint Argument("dirent");
}
let sys_setsockopt = {
  name = "sys_setsockopt";
  number = SYS_setsockopt;
  arguments = [
    ("fd", Basic(int));
    ("level", Basic(int));
    ("optname", Basic(int));
    ("optval", Pointer("", char));
    ("optlen", Basic(int));
  ];
  footprint =
    Basic(Argument(optval), Pointer("", char));
}
let sys_getsockopt = {
  name = "sys_getsockopt";
  number = SYS_getsockopt;
  arguments = [
    ("fd", Basic(int));
    ("level", Basic(int));
    ("optname", Basic(int));
    ("optval", Pointer("", char));
    ("optlen", Pointer("", int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(optval), Pointer("", char));
      Basic(Argument(optlen), Pointer("", int));
  ]);
}
let sys_bind = {
  name = "sys_bind";
  number = SYS_bind;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Basic(int));
    ];
    footprint =
      struct_sockaddr_footprint Argument("");
}
let sys_connect = {
  name = "sys_connect";
  number = SYS_connect;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Basic(int));
  ];
  footprint =
    struct_sockaddr_footprint Argument("");
}
let sys_accept = {
  name = "sys_accept";
  number = SYS_accept;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Pointer("", int));
  ];
  footprint =
    Separation_star([
      struct_sockaddr_footprint Argument("");
      Basic(Argument(), Pointer("", int));
  ]);
}
let sys_accept4 = {
  name = "sys_accept4";
  number = SYS_accept4;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Pointer("", int));
    ("", Basic(int));
    ];
    footprint =
      Separation_star([
        struct_sockaddr_footprint Argument("");
        Basic(Argument(), Pointer("", int));
  ]);
}
let sys_getsockname = {
  name = "sys_getsockname";
  number = SYS_getsockname;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Pointer("", int));
      ];
      footprint =
        Separation_star([
          struct_sockaddr_footprint Argument("");
          Basic(Argument(), Pointer("", int));
  ]);
}
let sys_getpeername = {
  name = "sys_getpeername";
  number = SYS_getpeername;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_sockaddr));
    ("", Pointer("", int));
        ];
        footprint =
          Separation_star([
            struct_sockaddr_footprint Argument("");
            Basic(Argument(), Pointer("", int));
  ]);
}
let sys_sendmsg = {
  name = "sys_sendmsg";
  number = SYS_sendmsg;
  arguments = [
    ("fd", Basic(int));
    ("msg", Pointer("", struct_msghdr));
    ("", Basic(flags));
          ];
          footprint =
            struct_msghdr_footprint Argument("msg");
}
let sys_sendmmsg = {
  name = "sys_sendmmsg";
  number = SYS_sendmmsg;
  arguments = [
    ("fd", Basic(int));
    ("msg", Pointer("", struct_mmsghdr));
    ("vlen", Basic(int));
    ("", Basic(flags));
  ];
  footprint =
    struct_mmsghdr_footprint Argument("msg");
}
let sys_recvmsg = {
  name = "sys_recvmsg";
  number = SYS_recvmsg;
  arguments = [
    ("fd", Basic(int));
    ("msg", Pointer("", struct_msghdr));
    ("", Basic(flags));
  ];
  footprint =
    struct_msghdr_footprint Argument("msg");
}
let sys_recvmmsg = {
  name = "sys_recvmmsg";
  number = SYS_recvmmsg;
  arguments = [
    ("fd", Basic(int));
    ("msg", Pointer("", struct_mmsghdr));
    ("vlen", Basic(int));
    ("", Basic(flags));
    ("timeout", Pointer("", struct_timespec));
  ];
  footprint =
    Separation_star([
      struct_mmsghdr_footprint Argument("msg");
      struct_timespec_footprint Argument("timeout");
  ]);
}
let sys_socket = {
  name = "sys_socket";
  number = SYS_socket;
  arguments = [
    ("", Basic(int));
    ("", Basic(int));
    ("", Basic(int));
    ];
    footprint =
      Void;
}
let sys_socketpair = {
  name = "sys_socketpair";
  number = SYS_socketpair;
  arguments = [
    ("", Basic(int));
    ("", Basic(int));
    ("", Basic(int));
    ("", Pointer("", int));
  ];
  footprint =
    Basic(Argument(), Pointer("", int));
}
let sys_socketcall = {
  name = "sys_socketcall";
  number = SYS_socketcall;
  arguments = [
    ("call", Basic(int));
    ("args", Pointer("", long));
  ];
  footprint =
    Basic(Argument(args), Pointer("", long));
}
let sys_listen = {
  name = "sys_listen";
  number = SYS_listen;
  arguments = [
    ("", Basic(int));
    ("", Basic(int));
  ];
  footprint =
    Void;
}
let sys_poll = {
  name = "sys_poll";
  number = SYS_poll;
  arguments = [
    ("ufds", Pointer("", struct_pollfd));
    ("nfds", Basic(int));
    ("timeout", Basic(long));
  ];
  footprint =
    struct_pollfd_footprint Argument("ufds");
}
let sys_select = {
  name = "sys_select";
  number = SYS_select;
  arguments = [
    ("n", Basic(int));
    ("inp", Pointer("", fd_set));
    ("outp", Pointer("", fd_set));
    ("exp", Pointer("", fd_set));
    ("tvp", Pointer("", struct_timeval));
  ];
  footprint =
    Separation_star([
      Basic(Argument(inp), Pointer("", fd_set));
      Basic(Argument(outp), Pointer("", fd_set));
      Basic(Argument(exp), Pointer("", fd_set));
      struct_timeval_footprint Argument("tvp");
  ]);
}
let sys_old_select = {
  name = "sys_old_select";
  number = SYS_old_select;
  arguments = [
    ("arg", Pointer("", struct_sel_arg_struct));
    ];
    footprint =
      struct_sel_arg_struct_footprint Argument("arg");
}
let sys_epoll_create = {
  name = "sys_epoll_create";
  number = SYS_epoll_create;
  arguments = [
    ("size", Basic(int));
  ];
  footprint =
    Void;
}
let sys_epoll_create1 = {
  name = "sys_epoll_create1";
  number = SYS_epoll_create1;
  arguments = [
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_epoll_ctl = {
  name = "sys_epoll_ctl";
  number = SYS_epoll_ctl;
  arguments = [
    ("epfd", Basic(int));
    ("op", Basic(int));
    ("fd", Basic(int));
    ("event", Pointer("", struct_epoll_event));
  ];
  footprint =
    struct_epoll_event_footprint Argument("event");
}
let sys_epoll_wait = {
  name = "sys_epoll_wait";
  number = SYS_epoll_wait;
  arguments = [
    ("epfd", Basic(int));
    ("events", Pointer("", struct_epoll_event));
    ("maxevents", Basic(int));
    ("timeout", Basic(int));
  ];
  footprint =
    struct_epoll_event_footprint Argument("events");
}
let sys_epoll_pwait = {
  name = "sys_epoll_pwait";
  number = SYS_epoll_pwait;
  arguments = [
    ("epfd", Basic(int));
    ("events", Pointer("", struct_epoll_event));
    ("maxevents", Basic(int));
    ("timeout", Basic(int));
    ("sigmask", Pointer(const, sigset_t));
    ("sigsetsize", Basic(size_t));
  ];
  footprint =
    Separation_star([
      struct_epoll_event_footprint Argument("events");
      Basic(Argument(sigmask), Pointer(const, sigset_t));
  ]);
}
let sys_gethostname = {
  name = "sys_gethostname";
  number = SYS_gethostname;
  arguments = [
    ("name", Pointer("", char));
    ("len", Basic(int));
    ];
    footprint =
      Basic(Argument(name), Pointer("", char));
}
let sys_sethostname = {
  name = "sys_sethostname";
  number = SYS_sethostname;
  arguments = [
    ("name", Pointer("", char));
    ("len", Basic(int));
  ];
  footprint =
    Basic(Argument(name), Pointer("", char));
}
let sys_setdomainname = {
  name = "sys_setdomainname";
  number = SYS_setdomainname;
  arguments = [
    ("name", Pointer("", char));
    ("len", Basic(int));
  ];
  footprint =
    Basic(Argument(name), Pointer("", char));
}
let sys_newuname = {
  name = "sys_newuname";
  number = SYS_newuname;
  arguments = [
    ("name", Pointer("", struct_new_utsname));
  ];
  footprint =
    struct_new_utsname_footprint Argument("name");
}
let sys_uname = {
  name = "sys_uname";
  number = SYS_uname;
  arguments = [
    ("", Pointer("", struct_old_utsname));
  ];
  footprint =
    struct_old_utsname_footprint Argument("");
}
let sys_olduname = {
  name = "sys_olduname";
  number = SYS_olduname;
  arguments = [
    ("", Pointer("", struct_oldold_utsname));
  ];
  footprint =
    struct_oldold_utsname_footprint Argument("");
}
let sys_getrlimit = {
  name = "sys_getrlimit";
  number = SYS_getrlimit;
  arguments = [
    ("resource", Basic(int));
    ("rlim", Pointer("", struct_rlimit));
  ];
  footprint =
    struct_rlimit_footprint Argument("rlim");
}
let sys_old_getrlimit = {
  name = "sys_old_getrlimit";
  number = SYS_old_getrlimit;
  arguments = [
    ("resource", Basic(int));
    ("rlim", Pointer("", struct_rlimit));
  ];
  footprint =
    struct_rlimit_footprint Argument("rlim");
}
let sys_setrlimit = {
  name = "sys_setrlimit";
  number = SYS_setrlimit;
  arguments = [
    ("resource", Basic(int));
    ("rlim", Pointer("", struct_rlimit));
  ];
  footprint =
    struct_rlimit_footprint Argument("rlim");
}
let sys_prlimit64 = {
  name = "sys_prlimit64";
  number = SYS_prlimit64;
  arguments = [
    ("pid", Basic(pid_t));
    ("resource", Basic(int));
    ("new_rlim", Pointer(const, struct_rlimit64));
    ("old_rlim", Pointer("", struct_rlimit64));
  ];
  footprint =
    Separation_star([
      struct_rlimit64_footprint Argument("new_rlim");
      struct_rlimit64_footprint Argument("old_rlim");
  ]);
}
let sys_getrusage = {
  name = "sys_getrusage";
  number = SYS_getrusage;
  arguments = [
    ("who", Basic(int));
    ("ru", Pointer("", struct_rusage));
    ];
    footprint =
      struct_rusage_footprint Argument("ru");
}
let sys_umask = {
  name = "sys_umask";
  number = SYS_umask;
  arguments = [
    ("mask", Basic(int));
  ];
  footprint =
    Void;
}
let sys_msgget = {
  name = "sys_msgget";
  number = SYS_msgget;
  arguments = [
    ("key", Basic(key_t));
    ("msgflg", Basic(int));
  ];
  footprint =
    Void;
}
let sys_msgsnd = {
  name = "sys_msgsnd";
  number = SYS_msgsnd;
  arguments = [
    ("msqid", Basic(int));
    ("msgp", Pointer("", struct_msgbuf));
    ("msgsz", Basic(size_t));
    ("msgflg", Basic(int));
  ];
  footprint =
    struct_msgbuf_footprint Argument("msgp");
}
let sys_msgrcv = {
  name = "sys_msgrcv";
  number = SYS_msgrcv;
  arguments = [
    ("msqid", Basic(int));
    ("msgp", Pointer("", struct_msgbuf));
    ("msgsz", Basic(size_t));
    ("msgtyp", Basic(long));
    ("msgflg", Basic(int));
  ];
  footprint =
    struct_msgbuf_footprint Argument("msgp");
}
let sys_msgctl = {
  name = "sys_msgctl";
  number = SYS_msgctl;
  arguments = [
    ("msqid", Basic(int));
    ("cmd", Basic(int));
    ("buf", Pointer("", struct_msqid_ds));
  ];
  footprint =
    struct_msqid_ds_footprint Argument("buf");
}
let sys_semget = {
  name = "sys_semget";
  number = SYS_semget;
  arguments = [
    ("key", Basic(key_t));
    ("nsems", Basic(int));
    ("semflg", Basic(int));
  ];
  footprint =
    Void;
}
let sys_semop = {
  name = "sys_semop";
  number = SYS_semop;
  arguments = [
    ("semid", Basic(int));
    ("sops", Pointer("", struct_sembuf));
    ("", Basic(nsops));
  ];
  footprint =
    struct_sembuf_footprint Argument("sops");
}
let sys_semtimedop = {
  name = "sys_semtimedop";
  number = SYS_semtimedop;
  arguments = [
    ("semid", Basic(int));
    ("sops", Pointer("", struct_sembuf));
    ("", Basic(nsops));
    ("timeout", Pointer(const, struct_timespec));
  ];
  footprint =
    Separation_star([
      struct_sembuf_footprint Argument("sops");
      struct_timespec_footprint Argument("timeout");
  ]);
}
let sys_shmat = {
  name = "sys_shmat";
  number = SYS_shmat;
  arguments = [
    ("shmid", Basic(int));
    ("shmaddr", Pointer("", char));
    ("shmflg", Basic(int));
    ];
    footprint =
      Basic(Argument(shmaddr), Pointer("", char));
}
let sys_shmget = {
  name = "sys_shmget";
  number = SYS_shmget;
  arguments = [
    ("key", Basic(key_t));
    ("size", Basic(size_t));
    ("flag", Basic(int));
  ];
  footprint =
    Void;
}
let sys_shmdt = {
  name = "sys_shmdt";
  number = SYS_shmdt;
  arguments = [
    ("shmaddr", Pointer("", char));
  ];
  footprint =
    Basic(Argument(shmaddr), Pointer("", char));
}
let sys_shmctl = {
  name = "sys_shmctl";
  number = SYS_shmctl;
  arguments = [
    ("shmid", Basic(int));
    ("cmd", Basic(int));
    ("buf", Pointer("", struct_shmid_ds));
  ];
  footprint =
    struct_shmid_ds_footprint Argument("buf");
}
let sys_ipc = {
  name = "sys_ipc";
  number = SYS_ipc;
  arguments = [
    ("call", Basic(int));
    ("first", Basic(int));
    ("second", Basic(long));
    ("third", Basic(long));
    ("ptr", Pointer("", void));
    ("fifth", Basic(long));
  ];
  footprint =
    Basic(Argument(ptr), Pointer("", void));
}
let sys_mq_open = {
  name = "sys_mq_open";
  number = SYS_mq_open;
  arguments = [
    ("name", Pointer(const, char));
    ("oflag", Basic(int));
    ("mode", Basic(mode_t));
    ("attr", Pointer("", struct_mq_attr));
  ];
  footprint =
    Separation_star([
      Basic(Argument(name), Pointer(const, char));
      struct_mq_attr_footprint Argument("attr");
  ]);
}
let sys_mq_unlink = {
  name = "sys_mq_unlink";
  number = SYS_mq_unlink;
  arguments = [
    ("name", Pointer(const, char));
    ];
    footprint =
      Basic(Argument(name), Pointer(const, char));
}
let sys_mq_timedsend = {
  name = "sys_mq_timedsend";
  number = SYS_mq_timedsend;
  arguments = [
    ("mqdes", Basic(mqd_t));
    ("msg_ptr", Pointer(const, char));
    ("msg_len", Basic(size_t));
    ("msg_prio", Basic(int));
    ("abs_timeout", Pointer(const, struct_timespec));
  ];
  footprint =
    Separation_star([
      Basic(Argument(msg_ptr), Pointer(const, char));
      struct_timespec_footprint Argument("abs_timeout");
  ]);
}
let sys_mq_timedreceive = {
  name = "sys_mq_timedreceive";
  number = SYS_mq_timedreceive;
  arguments = [
    ("mqdes", Basic(mqd_t));
    ("msg_ptr", Pointer("", char));
    ("msg_len", Basic(size_t));
    ("msg_prio", Pointer("", int));
    ("abs_timeout", Pointer(const, struct_timespec));
    ];
    footprint =
      Separation_star([
        Basic(Argument(msg_ptr), Pointer("", char));
        Basic(Argument(msg_prio), Pointer("", int));
        struct_timespec_footprint Argument("abs_timeout");
  ]);
}
let sys_mq_notify = {
  name = "sys_mq_notify";
  number = SYS_mq_notify;
  arguments = [
    ("mqdes", Basic(mqd_t));
    ("notification", Pointer(const, struct_sigevent));
      ];
      footprint =
        struct_sigevent_footprint Argument("notification");
}
let sys_mq_getsetattr = {
  name = "sys_mq_getsetattr";
  number = SYS_mq_getsetattr;
  arguments = [
    ("mqdes", Basic(mqd_t));
    ("mqstat", Pointer(const, struct_mq_attr));
    ("omqstat", Pointer("", struct_mq_attr));
  ];
  footprint =
    Separation_star([
      struct_mq_attr_footprint Argument("mqstat");
      struct_mq_attr_footprint Argument("omqstat");
  ]);
}
let sys_pciconfig_iobase = {
  name = "sys_pciconfig_iobase";
  number = SYS_pciconfig_iobase;
  arguments = [
    ("which", Basic(long));
    ("bus", Basic(long));
    ("devfn", Basic(long));
    ];
    footprint =
      Void;
}
let sys_pciconfig_read = {
  name = "sys_pciconfig_read";
  number = SYS_pciconfig_read;
  arguments = [
    ("bus", Basic(long));
    ("dfn", Basic(long));
    ("off", Basic(long));
    ("len", Basic(long));
    ("buf", Pointer("", void));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", void));
}
let sys_pciconfig_write = {
  name = "sys_pciconfig_write";
  number = SYS_pciconfig_write;
  arguments = [
    ("bus", Basic(long));
    ("dfn", Basic(long));
    ("off", Basic(long));
    ("len", Basic(long));
    ("buf", Pointer("", void));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", void));
}
let sys_prctl = {
  name = "sys_prctl";
  number = SYS_prctl;
  arguments = [
    ("option", Basic(int));
    ("arg2", Basic(long));
    ("arg3", Basic(long));
    ("arg4", Basic(long));
    ("arg5", Basic(long));
  ];
  footprint =
    Void;
}
let sys_swapon = {
  name = "sys_swapon";
  number = SYS_swapon;
  arguments = [
    ("specialfile", Pointer(const, char));
    ("swap_flags", Basic(int));
  ];
  footprint =
    Basic(Argument(specialfile), Pointer(const, char));
}
let sys_swapoff = {
  name = "sys_swapoff";
  number = SYS_swapoff;
  arguments = [
    ("specialfile", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(specialfile), Pointer(const, char));
}
let sys_sysctl = {
  name = "sys_sysctl";
  number = SYS_sysctl;
  arguments = [
    ("args", Pointer("", struct___sysctl_args));
  ];
  footprint =
    struct___sysctl_args_footprint Argument("args");
}
let sys_sysinfo = {
  name = "sys_sysinfo";
  number = SYS_sysinfo;
  arguments = [
    ("info", Pointer("", struct_sysinfo));
  ];
  footprint =
    struct_sysinfo_footprint Argument("info");
}
let sys_sysfs = {
  name = "sys_sysfs";
  number = SYS_sysfs;
  arguments = [
    ("option", Basic(int));
    ("arg1", Basic(long));
    ("arg2", Basic(long));
  ];
  footprint =
    Void;
}
let sys_syslog = {
  name = "sys_syslog";
  number = SYS_syslog;
  arguments = [
    ("type", Basic(int));
    ("buf", Pointer("", char));
    ("len", Basic(int));
  ];
  footprint =
    Basic(Argument(buf), Pointer("", char));
}
let sys_uselib = {
  name = "sys_uselib";
  number = SYS_uselib;
  arguments = [
    ("library", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(library), Pointer(const, char));
}
let sys_ni_syscall = {
  name = "sys_ni_syscall";
  number = SYS_ni_syscall;
  arguments = [
  ];
  footprint =
    Void;
}
let sys_ptrace = {
  name = "sys_ptrace";
  number = SYS_ptrace;
  arguments = [
    ("request", Basic(long));
    ("pid", Basic(long));
    ("addr", Basic(long));
    ("data", Basic(long));
  ];
  footprint =
    Void;
}
let sys_add_key = {
  name = "sys_add_key";
  number = SYS_add_key;
  arguments = [
    ("_type", Pointer(const, char));
    ("_description", Pointer(const, char));
    ("_payload", Pointer(const, void));
    ("plen", Basic(size_t));
    ("destringid", Basic(key_serial_t));
  ];
  footprint =
    Separation_star([
      Basic(Argument(_type), Pointer(const, char));
      Basic(Argument(_description), Pointer(const, char));
      Basic(Argument(_payload), Pointer(const, void));
  ]);
}
let sys_request_key = {
  name = "sys_request_key";
  number = SYS_request_key;
  arguments = [
    ("_type", Pointer(const, char));
    ("_description", Pointer(const, char));
    ("_callout_info", Pointer(const, char));
    ("destringid", Basic(key_serial_t));
    ];
    footprint =
      Separation_star([
        Basic(Argument(_type), Pointer(const, char));
        Basic(Argument(_description), Pointer(const, char));
        Basic(Argument(_callout_info), Pointer(const, char));
  ]);
}
let sys_keyctl = {
  name = "sys_keyctl";
  number = SYS_keyctl;
  arguments = [
    ("cmd", Basic(int));
    ("arg2", Basic(long));
    ("arg3", Basic(long));
    ("arg4", Basic(long));
    ("arg5", Basic(long));
      ];
      footprint =
        Void;
}
let sys_ioprio_set = {
  name = "sys_ioprio_set";
  number = SYS_ioprio_set;
  arguments = [
    ("which", Basic(int));
    ("who", Basic(int));
    ("ioprio", Basic(int));
  ];
  footprint =
    Void;
}
let sys_ioprio_get = {
  name = "sys_ioprio_get";
  number = SYS_ioprio_get;
  arguments = [
    ("which", Basic(int));
    ("who", Basic(int));
  ];
  footprint =
    Void;
}
let sys_set_mempolicy = {
  name = "sys_set_mempolicy";
  number = SYS_set_mempolicy;
  arguments = [
    ("mode", Basic(int));
    ("nmask", Pointer("", long));
    ("maxnode", Basic(long));
  ];
  footprint =
    Basic(Argument(nmask), Pointer("", long));
}
let sys_migrate_pages = {
  name = "sys_migrate_pages";
  number = SYS_migrate_pages;
  arguments = [
    ("pid", Basic(pid_t));
    ("maxnode", Basic(long));
    ("from", Pointer(const, long));
    ("to", Pointer(const, long));
  ];
  footprint =
    Separation_star([
      Basic(Argument(from), Pointer(const, long));
      Basic(Argument(to), Pointer(const, long));
  ]);
}
let sys_move_pages = {
  name = "sys_move_pages";
  number = SYS_move_pages;
  arguments = [
    ("pid", Basic(pid_t));
    ("nr_pages", Basic(long));
    ("pages", Pointer(const, void));
    ("nodes", Pointer(const, int));
    ("status", Pointer("", int));
    ("flags", Basic(int));
    ];
    footprint =
      Separation_star([
        Basic(Argument(pages), Pointer(const, void));
        Basic(Argument(nodes), Pointer(const, int));
        Basic(Argument(status), Pointer("", int));
  ]);
}
let sys_mbind = {
  name = "sys_mbind";
  number = SYS_mbind;
  arguments = [
    ("start", Basic(long));
    ("len", Basic(long));
    ("mode", Basic(long));
    ("nmask", Pointer("", long));
    ("maxnode", Basic(long));
    ("", Basic(flags));
      ];
      footprint =
        Basic(Argument(nmask), Pointer("", long));
}
let sys_get_mempolicy = {
  name = "sys_get_mempolicy";
  number = SYS_get_mempolicy;
  arguments = [
    ("policy", Pointer("", int));
    ("nmask", Pointer("", long));
    ("maxnode", Basic(long));
    ("addr", Basic(long));
    ("flags", Basic(long));
  ];
  footprint =
    Separation_star([
      Basic(Argument(policy), Pointer("", int));
      Basic(Argument(nmask), Pointer("", long));
  ]);
}
let sys_inotify_init = {
  name = "sys_inotify_init";
  number = SYS_inotify_init;
  arguments = [
    ];
    footprint =
      Void;
}
let sys_inotify_init1 = {
  name = "sys_inotify_init1";
  number = SYS_inotify_init1;
  arguments = [
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_inotify_add_watch = {
  name = "sys_inotify_add_watch";
  number = SYS_inotify_add_watch;
  arguments = [
    ("fd", Basic(int));
    ("path", Pointer(const, char));
    ("mask", Basic(u32));
  ];
  footprint =
    Basic(Argument(path), Pointer(const, char));
}
let sys_inotify_rm_watch = {
  name = "sys_inotify_rm_watch";
  number = SYS_inotify_rm_watch;
  arguments = [
    ("fd", Basic(int));
    ("wd", Basic(__s32));
  ];
  footprint =
    Void;
}
let sys_spu_run = {
  name = "sys_spu_run";
  number = SYS_spu_run;
  arguments = [
    ("fd", Basic(int));
    ("unpc", Pointer("", __u32));
    ("ustatus", Pointer("", __u32));
  ];
  footprint =
    Separation_star([
      Basic(Argument(unpc), Pointer("", __u32));
      Basic(Argument(ustatus), Pointer("", __u32));
  ]);
}
let sys_spu_create = {
  name = "sys_spu_create";
  number = SYS_spu_create;
  arguments = [
    ("name", Pointer(const, char));
    ("flags", Basic(int));
    ("mode", Basic(mode_t));
    ("fd", Basic(int));
    ];
    footprint =
      Basic(Argument(name), Pointer(const, char));
}
let sys_mknodat = {
  name = "sys_mknodat";
  number = SYS_mknodat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("mode", Basic(int));
    ("", Basic(dev));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_mkdirat = {
  name = "sys_mkdirat";
  number = SYS_mkdirat;
  arguments = [
    ("dfd", Basic(int));
    ("pathname", Pointer(const, char));
    ("mode", Basic(int));
  ];
  footprint =
    Basic(Argument(pathname), Pointer(const, char));
}
let sys_unlinkat = {
  name = "sys_unlinkat";
  number = SYS_unlinkat;
  arguments = [
    ("dfd", Basic(int));
    ("pathname", Pointer(const, char));
    ("flag", Basic(int));
  ];
  footprint =
    Basic(Argument(pathname), Pointer(const, char));
}
let sys_symlinkat = {
  name = "sys_symlinkat";
  number = SYS_symlinkat;
  arguments = [
    ("oldname", Pointer(const, char));
    ("newdfd", Basic(int));
    ("newname", Pointer(const, char));
  ];
  footprint =
    Separation_star([
      Basic(Argument(oldname), Pointer(const, char));
      Basic(Argument(newname), Pointer(const, char));
  ]);
}
let sys_linkat = {
  name = "sys_linkat";
  number = SYS_linkat;
  arguments = [
    ("olddfd", Basic(int));
    ("oldname", Pointer(const, char));
    ("newdfd", Basic(int));
    ("newname", Pointer(const, char));
    ("flags", Basic(int));
    ];
    footprint =
      Separation_star([
        Basic(Argument(oldname), Pointer(const, char));
        Basic(Argument(newname), Pointer(const, char));
  ]);
}
let sys_renameat = {
  name = "sys_renameat";
  number = SYS_renameat;
  arguments = [
    ("olddfd", Basic(int));
    ("oldname", Pointer(const, char));
    ("newdfd", Basic(int));
    ("newname", Pointer(const, char));
      ];
      footprint =
        Separation_star([
          Basic(Argument(oldname), Pointer(const, char));
          Basic(Argument(newname), Pointer(const, char));
  ]);
}
let sys_futimesat = {
  name = "sys_futimesat";
  number = SYS_futimesat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("utimes", Pointer("", struct_timeval));
        ];
        footprint =
          Separation_star([
            Basic(Argument(filename), Pointer(const, char));
            struct_timeval_footprint Argument("utimes");
  ]);
}
let sys_faccessat = {
  name = "sys_faccessat";
  number = SYS_faccessat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("mode", Basic(int));
          ];
          footprint =
            Basic(Argument(filename), Pointer(const, char));
}
let sys_fchmodat = {
  name = "sys_fchmodat";
  number = SYS_fchmodat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("mode", Basic(mode_t));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_fchownat = {
  name = "sys_fchownat";
  number = SYS_fchownat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("user", Basic(uid_t));
    ("group", Basic(gid_t));
    ("flag", Basic(int));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_openat = {
  name = "sys_openat";
  number = SYS_openat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("flags", Basic(int));
    ("mode", Basic(int));
  ];
  footprint =
    Basic(Argument(filename), Pointer(const, char));
}
let sys_newfstatat = {
  name = "sys_newfstatat";
  number = SYS_newfstatat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat));
    ("flag", Basic(int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(filename), Pointer(const, char));
      struct_stat_footprint Argument("statbuf");
  ]);
}
let sys_fstatat64 = {
  name = "sys_fstatat64";
  number = SYS_fstatat64;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("statbuf", Pointer("", struct_stat64));
    ("flag", Basic(int));
    ];
    footprint =
      Separation_star([
        Basic(Argument(filename), Pointer(const, char));
        struct_stat64_footprint Argument("statbuf");
  ]);
}
let sys_readlinkat = {
  name = "sys_readlinkat";
  number = SYS_readlinkat;
  arguments = [
    ("dfd", Basic(int));
    ("path", Pointer(const, char));
    ("buf", Pointer("", char));
    ("bufsiz", Basic(int));
      ];
      footprint =
        Separation_star([
          Basic(Argument(path), Pointer(const, char));
          Basic(Argument(buf), Pointer("", char));
  ]);
}
let sys_utimensat = {
  name = "sys_utimensat";
  number = SYS_utimensat;
  arguments = [
    ("dfd", Basic(int));
    ("filename", Pointer(const, char));
    ("utimes", Pointer("", struct_timespec));
    ("flags", Basic(int));
        ];
        footprint =
          Separation_star([
            Basic(Argument(filename), Pointer(const, char));
            struct_timespec_footprint Argument("utimes");
  ]);
}
let sys_unshare = {
  name = "sys_unshare";
  number = SYS_unshare;
  arguments = [
    ("unshare_flags", Basic(long));
          ];
          footprint =
            Void;
}
let sys_splice = {
  name = "sys_splice";
  number = SYS_splice;
  arguments = [
    ("fd_in", Basic(int));
    ("off_in", Pointer("", loff_t));
    ("fd_out", Basic(int));
    ("off_out", Pointer("", loff_t));
    ("len", Basic(size_t));
    ("flags", Basic(int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(off_in), Pointer("", loff_t));
      Basic(Argument(off_out), Pointer("", loff_t));
  ]);
}
let sys_vmsplice = {
  name = "sys_vmsplice";
  number = SYS_vmsplice;
  arguments = [
    ("fd", Basic(int));
    ("iov", Pointer(const, struct_iovec));
    ("nr_segs", Basic(long));
    ("flags", Basic(int));
    ];
    footprint =
      struct_iovec_footprint Argument("iov");
}
let sys_tee = {
  name = "sys_tee";
  number = SYS_tee;
  arguments = [
    ("fdin", Basic(int));
    ("fdout", Basic(int));
    ("len", Basic(size_t));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_sync_file_range = {
  name = "sys_sync_file_range";
  number = SYS_sync_file_range;
  arguments = [
    ("fd", Basic(int));
    ("offset", Basic(loff_t));
    ("nbytes", Basic(loff_t));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_sync_file_range2 = {
  name = "sys_sync_file_range2";
  number = SYS_sync_file_range2;
  arguments = [
    ("fd", Basic(int));
    ("flags", Basic(int));
    ("offset", Basic(loff_t));
    ("nbytes", Basic(loff_t));
  ];
  footprint =
    Void;
}
let sys_get_robust_list = {
  name = "sys_get_robust_list";
  number = SYS_get_robust_list;
  arguments = [
    ("pid", Basic(int));
    ("head_ptr", Pointer("", struct_robust_list_head));
    ("len_ptr", Pointer("", size_t));
  ];
  footprint =
    Separation_star([
      struct_robust_list_head_footprint Argument("head_ptr");
      Basic(Argument(len_ptr), Pointer("", size_t));
  ]);
}
let sys_set_robust_list = {
  name = "sys_set_robust_list";
  number = SYS_set_robust_list;
  arguments = [
    ("head", Pointer("", struct_robust_list_head));
    ("len", Basic(size_t));
    ];
    footprint =
      struct_robust_list_head_footprint Argument("head");
}
let sys_getcpu = {
  name = "sys_getcpu";
  number = SYS_getcpu;
  arguments = [
    ("cpu", Pointer("", ));
    ("node", Pointer("", ));
    ("cache", Pointer("", struct_getcpu_cache));
  ];
  footprint =
    Separation_star([
      Basic(Argument(cpu), Pointer("", ));
      Basic(Argument(node), Pointer("", ));
      struct_getcpu_cache_footprint Argument("cache");
  ]);
}
let sys_signalfd = {
  name = "sys_signalfd";
  number = SYS_signalfd;
  arguments = [
    ("ufd", Basic(int));
    ("user_mask", Pointer("", sigset_t));
    ("sizemask", Basic(size_t));
    ];
    footprint =
      Basic(Argument(user_mask), Pointer("", sigset_t));
}
let sys_signalfd4 = {
  name = "sys_signalfd4";
  number = SYS_signalfd4;
  arguments = [
    ("ufd", Basic(int));
    ("user_mask", Pointer("", sigset_t));
    ("sizemask", Basic(size_t));
    ("flags", Basic(int));
  ];
  footprint =
    Basic(Argument(user_mask), Pointer("", sigset_t));
}
let sys_timerfd_create = {
  name = "sys_timerfd_create";
  number = SYS_timerfd_create;
  arguments = [
    ("clockid", Basic(int));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_timerfd_settime = {
  name = "sys_timerfd_settime";
  number = SYS_timerfd_settime;
  arguments = [
    ("ufd", Basic(int));
    ("flags", Basic(int));
    ("utmr", Pointer(const, struct_itimerspec));
    ("otmr", Pointer("", struct_itimerspec));
  ];
  footprint =
    Separation_star([
      struct_itimerspec_footprint Argument("utmr");
      struct_itimerspec_footprint Argument("otmr");
  ]);
}
let sys_timerfd_gettime = {
  name = "sys_timerfd_gettime";
  number = SYS_timerfd_gettime;
  arguments = [
    ("ufd", Basic(int));
    ("otmr", Pointer("", struct_itimerspec));
    ];
    footprint =
      struct_itimerspec_footprint Argument("otmr");
}
let sys_eventfd = {
  name = "sys_eventfd";
  number = SYS_eventfd;
  arguments = [
    ("count", Basic(int));
  ];
  footprint =
    Void;
}
let sys_eventfd2 = {
  name = "sys_eventfd2";
  number = SYS_eventfd2;
  arguments = [
    ("count", Basic(int));
    ("flags", Basic(int));
  ];
  footprint =
    Void;
}
let sys_fallocate = {
  name = "sys_fallocate";
  number = SYS_fallocate;
  arguments = [
    ("fd", Basic(int));
    ("mode", Basic(int));
    ("offset", Basic(loff_t));
    ("len", Basic(loff_t));
  ];
  footprint =
    Void;
}
let sys_old_readdir = {
  name = "sys_old_readdir";
  number = SYS_old_readdir;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", struct_old_linux_dirent));
    ("", Basic(int));
  ];
  footprint =
    struct_old_linux_dirent_footprint Argument("");
}
let sys_pselect6 = {
  name = "sys_pselect6";
  number = SYS_pselect6;
  arguments = [
    ("", Basic(int));
    ("", Pointer("", fd_set));
    ("", Pointer("", fd_set));
    ("", Pointer("", fd_set));
    ("", Pointer("", struct_timespec));
    ("", Pointer("", void));
  ];
  footprint =
    Separation_star([
      Basic(Argument(), Pointer("", fd_set));
      Basic(Argument(), Pointer("", fd_set));
      Basic(Argument(), Pointer("", fd_set));
      struct_timespec_footprint Argument("");
      Basic(Argument(), Pointer("", void));
  ]);
}
let sys_ppoll = {
  name = "sys_ppoll";
  number = SYS_ppoll;
  arguments = [
    ("", Pointer("", struct_pollfd));
    ("", Basic(int));
    ("", Pointer("", struct_timespec));
    ("", Pointer(const, sigset_t));
    ("", Basic(size_t));
    ];
    footprint =
      Separation_star([
        struct_pollfd_footprint Argument("");
        struct_timespec_footprint Argument("");
        Basic(Argument(), Pointer(const, sigset_t));
  ]);
}
let sys_fanotify_init = {
  name = "sys_fanotify_init";
  number = SYS_fanotify_init;
  arguments = [
    ("flags", Basic(int));
    ("event_f_flags", Basic(int));
      ];
      footprint =
        Void;
}
let sys_fanotify_mark = {
  name = "sys_fanotify_mark";
  number = SYS_fanotify_mark;
  arguments = [
    ("fanotify_fd", Basic(int));
    ("flags", Basic(int));
    ("mask", Basic(u64));
    ("fd", Basic(int));
    ("pathname", Pointer(const, char));
  ];
  footprint =
    Basic(Argument(pathname), Pointer(const, char));
}
let sys_syncfs = {
  name = "sys_syncfs";
  number = SYS_syncfs;
  arguments = [
    ("fd", Basic(int));
  ];
  footprint =
    Void;
}
let sys_perf_event_open = {
  name = "sys_perf_event_open";
  number = SYS_perf_event_open;
  arguments = [
    ("attr_uptr", Pointer("", struct_perf_event_attr));
    ("pid", Basic(pid_t));
    ("cpu", Basic(int));
    ("group_fd", Basic(int));
    ("flags", Basic(long));
  ];
  footprint =
    struct_perf_event_attr_footprint Argument("attr_uptr");
}
let sys_mmap_pgoff = {
  name = "sys_mmap_pgoff";
  number = SYS_mmap_pgoff;
  arguments = [
    ("addr", Basic(long));
    ("len", Basic(long));
    ("prot", Basic(long));
    ("flags", Basic(long));
    ("fd", Basic(long));
    ("pgoff", Basic(long));
  ];
  footprint =
    Void;
}
let sys_old_mmap = {
  name = "sys_old_mmap";
  number = SYS_old_mmap;
  arguments = [
    ("arg", Pointer("", struct_mmap_arg_struct));
  ];
  footprint =
    struct_mmap_arg_struct_footprint Argument("arg");
}
let sys_name_to_handle_at = {
  name = "sys_name_to_handle_at";
  number = SYS_name_to_handle_at;
  arguments = [
    ("dfd", Basic(int));
    ("name", Pointer(const, char));
    ("handle", Pointer("", struct_file_handle));
    ("mnt_id", Pointer("", int));
    ("flag", Basic(int));
  ];
  footprint =
    Separation_star([
      Basic(Argument(name), Pointer(const, char));
      struct_file_handle_footprint Argument("handle");
      Basic(Argument(mnt_id), Pointer("", int));
  ]);
}
let sys_open_by_handle_at = {
  name = "sys_open_by_handle_at";
  number = SYS_open_by_handle_at;
  arguments = [
    ("mountdirfd", Basic(int));
    ("handle", Pointer("", struct_file_handle));
    ("flags", Basic(int));
    ];
    footprint =
      struct_file_handle_footprint Argument("handle");
}
let sys_setns = {
  name = "sys_setns";
  number = SYS_setns;
  arguments = [
    ("fd", Basic(int));
    ("nstype", Basic(int));
  ];
  footprint =
    Void;
}
let sys_process_vm_readv = {
  name = "sys_process_vm_readv";
  number = SYS_process_vm_readv;
  arguments = [
    ("pid", Basic(pid_t));
    ("lvec", Pointer(const, struct_iovec));
    ("liovcnt", Basic(long));
    ("rvec", Pointer(const, struct_iovec));
    ("riovcnt", Basic(long));
    ("flags", Basic(long));
  ];
  footprint =
    Separation_star([
      struct_iovec_footprint Argument("lvec");
      struct_iovec_footprint Argument("rvec");
  ]);
}
let sys_process_vm_writev = {
  name = "sys_process_vm_writev";
  number = SYS_process_vm_writev;
  arguments = [
    ("pid", Basic(pid_t));
    ("lvec", Pointer(const, struct_iovec));
    ("liovcnt", Basic(long));
    ("rvec", Pointer(const, struct_iovec));
    ("riovcnt", Basic(long));
    ("flags", Basic(long));
    ];
    footprint =
      Separation_star([
        struct_iovec_footprint Argument("lvec");
        struct_iovec_footprint Argument("rvec");
  ]);
}
let struct___sysctl_args_footprint __sysctl_args = Separation_star([
  Struct(__sysctl_args, struct___sysctl_args);
  ... (* FILL ME WITH SEMANTICS *)
      ]);;
let struct_epoll_event_footprint epoll_event = Separation_star([
  Struct(epoll_event, struct_epoll_event);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_iovec_footprint iovec = Separation_star([
  Struct(iovec, struct_iovec);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_ipc_perm_footprint ipc_perm = Separation_star([
  Struct(ipc_perm, struct_ipc_perm);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_itimerspec_footprint itimerspec = Separation_star([
  Struct(itimerspec, struct_itimerspec);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_itimerval_footprint itimerval = Separation_star([
  Struct(itimerval, struct_itimerval);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_kexec_segment_footprint kexec_segment = Separation_star([
  Struct(kexec_segment, struct_kexec_segment);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_mmsghdr_footprint mmsghdr = Separation_star([
  Struct(mmsghdr, struct_mmsghdr);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_msghdr_footprint msghdr = Separation_star([
  Struct(msghdr, struct_msghdr);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_msqid_ds_footprint msqid_ds = Separation_star([
  Struct(msqid_ds, struct_msqid_ds);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_pollfd_footprint pollfd = Separation_star([
  Struct(pollfd, struct_pollfd);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_rlimit_footprint rlimit = Separation_star([
  Struct(rlimit, struct_rlimit);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_rusage_footprint rusage = Separation_star([
  Struct(rusage, struct_rusage);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_stat_footprint stat = Separation_star([
  Struct(stat, struct_stat);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_timespec_footprint timespec = Separation_star([
  Struct(timespec, struct_timespec);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_timeval_footprint timeval = Separation_star([
  Struct(timeval, struct_timeval);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_timex_footprint timex = Separation_star([
  Struct(timex, struct_timex);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_timezone_footprint timezone = Separation_star([
  Struct(timezone, struct_timezone);
  ... (* FILL ME WITH SEMANTICS *)
]);;
let struct_tms_footprint tms = Separation_star([
  Struct(tms, struct_tms);
  ... (* FILL ME WITH SEMANTICS *)
]);;
