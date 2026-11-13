/* sigsegv handler for virtual permissions  */
#include <stddef.h>
#include <stdlib.h>
#include "systrap.h"
#include "raw-syscalls-impl.h"

__attribute__((visibility("hidden")))
void handle_sigsegv(int n, __asm_siginfo_t *info, void *ucontext)
{
	unsigned long *frame_base = __builtin_frame_address(0);
	struct ibcs_sigframe *p_frame = (struct ibcs_sigframe *) (frame_base + 1);

	/* Is this a segv we care about? That means the faulting IP is in our list of
	 * deferred-executable mappings. */
	uintptr_t ip = p_frame->uc.uc_mcontext.MC_REG_IP;
	if (ip != (uintptr_t) info->si_addr)
	{
		/* TODO: segue to normal segfault path */ abort();
	}
	/* FIXME: taking the lock here will deadlock if we are segfaulting inside
	 * a context where we already hold the exclusive write lock. That means our
	 * code (e.g. in librunt) has a bug. It's still not ideal, though.
	 * We COULD detect the case where it's our pid that has the exclusive lock.
	 * We could do this by storing the negation of the pid/tid in the lock field,
	 * instead of -1. I *think* this is OK because Linux only uses the top half
	 * of the range of pid_t, which is signed. */
	struct vperm_range *found = find_vperm_range((void*) ip);
	if (!found) /* TODO: segue to normal segfault path */ abort();

	// FIXME: do TLS swap?

	/* CARE: what if multiple threads do this simultaneously?
	 * We need to take the write (exclusive) lock..
	 * If we fail to take the write lock and the vperm record for this
	 * address range has gone away, it means the other thread trapped it for us.
	 * If we just naively find and then remove, without locking, then
	 * a concurrent SIGSEGV in another thread, segfaulting on the same range of
	 * memory, would terminate the process.
	 *
	 * This one call does everything, because if nothing is found, no
	 * action will be taken.
	 *
	 * FIXME: should be able to find out from ret whether anything was done
	 * or not, I think, but the API doesn't currently allow this.
	 */
	/*int ret = */ with_vperm_range_exclusive((void*) ip, trap_at_vperm_range_cb, NULL);
}

void install_sigsegv_handler(void)
{
	install_signal_handler(sigsegv, SIGSEGV);
}
