handle SIGILL nostop noprint pass
# stack-zapping case, before copying stack
#break do-syscall.h:309
# stack-zapping case, before post-call bp fixup
#break do-syscall.h:383
catch syscall clone
# These don't seem to have the properties we want!
# The new LWP continues to run. Is this because
# libthread_db doesn't like raw clone() perhaps?
set detach-on-fork off
set schedule-multiple off
set non-stop off
