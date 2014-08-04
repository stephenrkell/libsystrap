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
				echo "$line" | sed -r 's/.* with (n|sz|size|len|length)=\((0x)?[0-9a-f]*\) *(src|source)=\((0x)?[0-9a-f]*\) *(dst|dest)=\((0x)?[0-9a-f]*\)/len=\1 src=\2 dest=\3/'
			;;
			(*) echo "$line"
			;;
		esac
	done
}

# start the process -- our footprint summary goes to fd 7
$( dirname "$0" )/run-with-trap-syscalls.sh "$@" 7>"$pipename" &

# start stap -- its awkwardly-formatted info goes on stdout,
# which is handy for us to filter
stap -x $! $(dirname "$0")/systemtap/copy-tofrom-user.stp | \
stap_filter | \
diff -u - "$pipename"
