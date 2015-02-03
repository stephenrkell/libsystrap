#!/bin/bash

# Earlier I had used a pipe to forward the stap output
# to the process itself. 
# pipename=/tmp/stap-output-$$
# mkfifo "$pipename"
# $( dirname "$0" )/run-with-trap-syscalls.sh "$@" 7<$pipename &
# exec >$pipename
# unlink "$pipename"
# stap -x $! $(dirname "$0")/systemtap/copy-tofrom-user.stp
#
# But this sets up a feedback loop. So instead we just generate
# some extra output inside the trap library, and diff it
# externally. We use fd 7, as before, and stap outputs on fd 1.
# We filter stap's output to match our format, then do a diff.
# Minor complication: we want to separate stap's stdout from the
# stdout used by the child process being observed, so we use the
# same pipe-based trick as before. FIXME: a cleaner way to do this?

pipename=/tmp/stap-sync-$$
mkfifo "$pipename"

stap_filter () {
    while read line; do
        case "$line" in
            (saw*)
                echo -n "$line" | sed -r 's/.* with *//' | \
                sed -r 's/ *([a-zA-Z0-9_]*=)/\n\1/g' | \
                sed -r 's/(n|sz|size|len|length)=((0x)?[0-9a-f\?]*)/n=\2/' | \
                sed -r 's/(src|source|from)=((0x)?[0-9a-f\?]*)/src=\2/' | \
                sed -r 's/(dst|dest|to)=((0x)?[0-9a-f\?]*)/dst=\2/' | \
                sed -r 's/(dst|dest|to|src|source|from)=((0x)?ffff[0-9a-f\?]*)//' | \
                sed '/^$/ d' | \
                sort -t= -k1 | tr '\n' ' '
                echo # for the newline
            ;;
            (*) echo "$line"
            ;;
        esac
    done
}

# start the process -- our footprint summary goes to fd 7
$( dirname "$0" )/run-with-trap-syscalls.sh "$@" 7>"$pipename" &
child_pid=$!

# start stap -- its awkwardly-formatted info goes on stdout,
# which is handy for us to filter
stap -x $! $(dirname "$0")/copy-tofrom-user.stp | \
stap_filter | \
tee /dev/stderr | \
diff -u - "$pipename" &
stap_pid=$!

while [ -d /proc/$child_pid ]; do
    sleep 1
done

kill $stap_pid
