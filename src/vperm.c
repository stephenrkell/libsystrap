#define _GNU_SOURCE /* for statement expressions, needed by bsearch_leq_generic and our lock macros */
#include <stdlib.h>
#include <strings.h> /* for bzero */
#include <sched.h>
#include <sys/mman.h>
#include <limits.h>

#include "vas.h"
#include "dso-meta.h"
#include "systrap.h"

/* Virtual perms are always wider than real perms, i.e. real is narrower.
 * If we temporarily add write perm, that's a separate operation and we don't
 * expect to take any faults while it is happening. */
enum vperm_perms
{
	VPERM_R,
	VPERM_RW,
	VPERM_RX,
	VPERM_RWX
};

struct vperm_range vperm_ranges[MAX_VPERM_RANGES] __attribute__((visibility("hidden")));
unsigned vperm_ranges_nused __attribute__((visibility("hidden")));
static pid_t mytid(void)
{
	/* PROBLEM: can't use thread-locals in here. :-(  I did have
	 * this working at some point, I'm sure? Using the fs/gs swap.
	 * Maybe that is only on i386? That needs it for the sysinfo slot.
	 * There is a subtle problem about fs/gs swapping across signal
	 * handlers, which I think I never addressed. A signal handler
	 * that accesses TLS probably gets the wrong one. We need to
	 * wrap any signal handler with a fs/gs swapper, much like the
	 * lazypoline paper did. */
#if 0
	static _Thread_local pid_t tid;
	if (!tid) tid = raw_gettid();
	return tid;
#else
	return -1;
#endif
}
// Need a RW multi-reader single-writer lock, and don't want to rely on pthreads
_Atomic int rwlock; // read-locked: 1..n; unlocked 0; write-locked: -1
#define TAKE_LOCK_R() \
	({ int seen; _Bool success = 0; do { seen = rwlock; if (seen < 0) sched_yield(); else \
		success = __sync_bool_compare_and_swap (&rwlock, seen, seen+1); } while (!success); success; })

#define RELEASE_LOCK_R() \
	({ int seen; _Bool success = 0; do { seen = rwlock; \
		success = __sync_bool_compare_and_swap (&rwlock, seen, seen-1); } while (!success); success; })

#define TAKE_LOCK_W() \
	({ int seen; _Bool success = 0; do { seen = rwlock; if (seen != 0) sched_yield(); else \
		success = __sync_bool_compare_and_swap (&rwlock, seen, -mytid()); } while (!success); success; })

#define RELEASE_LOCK_W() \
	({  __atomic_store_n(&rwlock, 0, __ATOMIC_RELEASE); 1; })

// We've made vperms more compact (64 bits per record) to help keep search costs down.
/* We also make this static, deliberately. The API is too confusing if an argument may be a
 * prot or a vperm enum. So we settle on prot as the API representation, and make the encoding
 * into our 2-bit form opaque. Clients can still decode it by calling prot_from_vperms (below). */
static enum vperm_perms vperms_from_prot(int prot)
{
	enum vperm_perms perms;
	switch (prot & (PROT_READ|PROT_WRITE|PROT_EXEC))
	{
		case PROT_READ:                      perms = VPERM_R; break;
		case PROT_READ|PROT_WRITE:           perms = VPERM_RW; break;
		case PROT_READ|PROT_EXEC:            perms = VPERM_RX; break;
		case PROT_READ|PROT_WRITE|PROT_EXEC: /* perm = VPERM_RWX; */ abort();
		default:
			// unsupported!
			abort();
	}
	return perms;
}
__attribute__((visibility("hidden")))
int prot_from_vperms(int perms)
{
	switch (perms)
	{
		case VPERM_R:   return PROT_READ;
		case VPERM_RW:  return PROT_READ|PROT_WRITE;
		case VPERM_RX:  return PROT_READ|PROT_EXEC;
		case VPERM_RWX: return PROT_READ|PROT_WRITE|PROT_EXEC;
		default:
			// unsupported!
			abort();
	}
}
static struct vperm_range *add_vperm_range_nolock_nosort(void *addr, size_t len, int prot)
{
	// len is in bytes! and we should have rounded up to page size before getting here
	assert(len >= MIN_PAGE_SIZE);
	struct vperm_range *ret = NULL;
	size_t len_rounded = ROUND_UP(len, MIN_PAGE_SIZE);
	size_t npages = len_rounded >> LOG_MIN_PAGE_SIZE;
	if (npages > VPERM_NPAGES_MAX) abort(); // FIXME: add in multiple goes
	if (vperm_ranges_nused == MAX_VPERM_RANGES) return NULL;
	// check 'prot'
	enum vperm_perms perms = vperms_from_prot(prot);
	ret = &vperm_ranges[vperm_ranges_nused++];
	*ret = (struct vperm_range) {
		.addr = (unsigned long) addr,
		.npages = npages,
		.perms = perms
	};
	return ret;
}
static struct vperm_range *add_vperm_range_nolock(void *addr, size_t len, int prot)
{
	struct vperm_range *ret = add_vperm_range_nolock_nosort(addr, len, prot);
	if (ret) qsort(&vperm_ranges[0], vperm_ranges_nused, sizeof vperm_ranges[0],
		compare_vperm_ranges);
	return ret;
}
__attribute__((visibility("hidden")))
struct vperm_range *add_vperm_range(void *addr, size_t len, int prot)
{
	TAKE_LOCK_W();
	struct vperm_range *ret = add_vperm_range_nolock(addr, len, prot);
	/* We may get null for unsupported perms or no-free-entries... FIXME: distinguish */
	if (vperm_ranges_nused == MAX_VPERM_RANGES) abort();
out:
	RELEASE_LOCK_W();
	return ret;
}

static struct vperm_range *find_vperm_range_nolock(void *addr)
{
#define proj_vperm_range_addr(p) (p)->addr
	struct vperm_range *found = NULL;
	if (vperm_ranges_nused == 0) return NULL;
	found = bsearch_leq_generic(
			struct vperm_range, (uintptr_t) addr,
			&vperm_ranges[0], vperm_ranges_nused, proj_vperm_range_addr);
	/* We've found the record <= addr, but does the entry overlap addr? */
	if (!found || !(found->addr + (found->npages * MIN_PAGE_SIZE) >= (uintptr_t) addr))
	{
		// it's not actually a match
		found = NULL;
	}
	return found;
}
__attribute__((visibility("hidden")))
struct vperm_range *find_vperm_range(void *addr)
{
	TAKE_LOCK_R();
	struct vperm_range *found = find_vperm_range_nolock(addr);
	RELEASE_LOCK_R();
	return found;
}

// TODO: pull out the code in here into a generic "flat partition map" implementation.

__attribute__((visibility("hidden")))
struct vperm_range *find_first_vperm_range_in(void *begin, void *end)
{
	struct vperm_range *found = NULL;
	TAKE_LOCK_R();
	if (vperm_ranges_nused == 0) goto out; /* *inside* locking protocol to avoid bsearch aborts */
	struct vperm_range *entries_end = &vperm_ranges[vperm_ranges_nused];
	struct vperm_range *found_first = bsearch_leq_generic(
			struct vperm_range, (uintptr_t) begin,
			&vperm_ranges[0], vperm_ranges_nused, proj_vperm_range_addr);
	/* If there's no range starting before 'begin', there might still be one that
	 * overlaps somewhere between there and 'end'. */
	if (!found_first) found_first = &vperm_ranges[0];
	/* We've found the highest record <= begin, but does the entry overlap [begin, end[ ? */
	if (!(found_first->addr + (found_first->npages * MIN_PAGE_SIZE) >= (uintptr_t) begin))
	{
		// it's not actually a match because it doesn't overlap any part of the interval
		// but maybe a later-starting entry does overlap part of the interval?
		// we search forward linearly, because from bsearch_leq, the next higher entry
		// (if there is one)
		// must start at a position > the interval start.
		// It may or may not overlap... if it's to ohigh, it won't.
		struct vperm_range *found_next = found_first + 1;
		if (found_next == entries_end || !(found_next->addr >= (uintptr_t) end))
		{
			// the next, if any,is too high, so we have not found anything
			found = NULL;
		}
		else
		{
			assert(found_next->addr + (found_next->npages * MIN_PAGE_SIZE) >= (uintptr_t) begin);
			assert(found_next->addr < (uintptr_t) end);
			found = found_next;
		}
	} else found = found_first;
out:
	RELEASE_LOCK_R();
	return found;
}

static void replace_vperms_over_nolock(void *begin, void *end, int prot_or_negative_one)
{
	/* If perm is -1, we drop perms, otherwise replace.
	 * We do this in two steps.
	 * Firstly, surgery on the existing ranges s.t. [begin, end[ is an
	 * exact span of ranges.
	 * Secondly, dropping or modifying this exact span. */
	assert((uintptr_t) end > (uintptr_t) begin);
	end = ROUND_UP_PTR(end, MIN_PAGE_SIZE);

	struct vperm_range *found_first = NULL;
	struct vperm_range *found_last = NULL;
/* It overlaps if it's not entirely before and not entirely after. */
#define OVERLAPS(ent, bptr, eptr) ( \
	!( ((ent)->addr + ((ent)->npages * MIN_PAGE_SIZE)) <= (uintptr_t) bptr) \
 && !( ((ent)->addr >= (uintptr_t) eptr) ) \
 )
	if (vperm_ranges_nused != 0)
	{
		/* Do our two searches first, before we break the sortedness invariant. */
		found_first = bsearch_leq_generic(
				struct vperm_range, (uintptr_t) begin,
				&vperm_ranges[0], vperm_ranges_nused, proj_vperm_range_addr);
		found_last = bsearch_leq_generic(
				struct vperm_range, (uintptr_t) end - 1,
				&vperm_ranges[0], vperm_ranges_nused, proj_vperm_range_addr);
	}
	if (found_first && !OVERLAPS(found_first, begin, end))
	{
		/* The highest entry beginning <= the beginning of our range
		 * does not overlap our range. We might as well not have found it.
		 * We will locate the first overlap by walking backwards from found_last. */
		found_first = NULL;
	}
	if (found_last && !OVERLAPS(found_last, begin, end))
	{
		/* The highest entry beginning <= the end of our range
		 * does not overlap our range. We might as well not have found it. */
		found_last = NULL;
	}
	/* If we didn't get a first, it means that no entry starts before 'begin'.
	 * There may or may not be any entries overlapping our range. If there are,
	 * we should get a found_last. */
	unsigned nfreed = 0;
	if (!found_first && !found_last && prot_or_negative_one == -1) /* no op; stays sorted */ return;
	if (!found_first && !found_last)
	{
		/* We're setting perms and there's nothing overlapping. It's a plain addition. */
		add_vperm_range_nolock_nosort(begin, (uintptr_t) end - (uintptr_t) begin, prot_or_negative_one);
		goto sort_and_return;
	}
	/* Now if we got here, we still may not have a found_first and have to find
	 * the start of our rage by walking backwards from found_last. */
	assert(!found_first || OVERLAPS(found_first, begin, end));
	if (!found_first)
	{
		assert(found_last);
		/* The highest entry beginning <= the beginning of our range
		 * does not overlap our range,
		 * OR
		 * there is no entry beginning <= the beginning of our range.
		 * We still want
		 * (1) the lowest-starting entry that overlaps our range. This *does* exist,
		 * because we have a found_last (and if it began before 'begin', it would have
		 * alos been our found_first... since it begins > begin and begins < end, it overlaps).
		 * (2) to make that entry start from 'begin' instead of somewhere > 'begin'. */
		struct vperm_range *found_lowest = found_last;
		while (found_lowest != &vperm_ranges[0]
				&& OVERLAPS(found_lowest-1, begin, end)) --found_lowest;
		if (found_lowest == &vperm_ranges[0])
		{
			assert(OVERLAPS(found_lowest, begin, end)); // this is just the "This *does* exist", above
		}
		/* found_lowest starts *after* begin, otherwise we wouldn't be here. */
		found_lowest->npages += (found_lowest->addr - (uintptr_t) begin) >> LOG_MIN_PAGE_SIZE;
		found_lowest->addr = (uintptr_t) begin;
		found_first = found_lowest;
	}
	assert(found_last);
	/* Now we have a first and a last. They may be the same range. */
	assert(found_last >= found_first);
	/* if our interval doesn't fill the first range from its start, surgery required */
	if ((uintptr_t) begin != found_first->addr)
	{
		if ((uintptr_t) begin > found_first->addr)
		{
			// we need to pre-chop it and then add a new one; found_first should be only the overlap
			size_t npages_chopped = (((uintptr_t) begin - found_first->addr) >> LOG_MIN_PAGE_SIZE);
			assert(npages_chopped < found_first->npages);
			add_vperm_range_nolock_nosort((void*)(uintptr_t) found_first->addr, npages_chopped << LOG_MIN_PAGE_SIZE, prot_from_vperms(found_first->perms));
			// NOTE that this ^^ has incremented nused
			found_first->addr = (uintptr_t) begin;
			assert(npages_chopped < found_first->npages);
			found_first->npages -= npages_chopped;
		}
		else
		{
			assert((uintptr_t) begin < found_first->addr);
			/* The portion from 'begin' to found_first's begin has no vperms, but it will do
			 * when we're finished, unless 'perms' is -1. Either way, it is safe to update 'begin'
			 * here (we have the write lock). */
			found_first->addr = (uintptr_t) begin;
			found_first->npages += (found_first->addr - (uintptr_t) begin) >> LOG_MIN_PAGE_SIZE;
		}
	}
	/* if our interval doesn't fill the last range up to its end, surgery required */
	uintptr_t found_last_end_addr = found_last->addr + (found_last->npages << LOG_MIN_PAGE_SIZE);
	if ((uintptr_t) end != found_last_end_addr)
	{
		/* found_last definitely starts before 'end'. But it might end before or after. */
		if ((uintptr_t) end < found_last_end_addr)
		{
			// we need to post-chop it and then add a new one; found_last should be only the overlap
			size_t npages_chopped = (found_last_end_addr - (uintptr_t) end) >> LOG_MIN_PAGE_SIZE;
			assert(npages_chopped < found_last->npages);
			add_vperm_range_nolock_nosort(end, npages_chopped << LOG_MIN_PAGE_SIZE, prot_from_vperms(found_last->perms));
			// NOTE that this ^^ has incremented nused
			found_last->npages -= npages_chopped;
		}
		else
		{
			assert((uintptr_t) end > found_last_end_addr);
			/* The portion from found_last's end to 'end' has no vperms, but it will do
			 * when we're finished, unless 'perms' is -1. Either way, it is safe to update
			 * found_last's end here. */
			found_last->npages += (found_last_end_addr - (uintptr_t) end) >> LOG_MIN_PAGE_SIZE;
		}
	}
	/* Now the sequence from found_first to found_last is exactly the sequence we want to modify. */
	if (prot_or_negative_one == -1)
	{
		nfreed = 1 + (found_last-found_first);
		bzero(found_first, nfreed * sizeof *found_first);
	}
	else
	{
		// we only need one... this also fills any holes, if our ranges aren't contiguous
		nfreed = found_last - found_first;
		found_first->npages = ((uintptr_t) end - (uintptr_t) begin) >> LOG_MIN_PAGE_SIZE;
		found_first->perms = vperms_from_prot(prot_or_negative_one);
		if (found_last > found_first) bzero(found_first + 1, nfreed * sizeof *found_first);
	}
	// we haven't sorted until now... do it. The zeroed entries will float to the end
sort_and_return:
	if (nfreed < vperm_ranges_nused) qsort(&vperm_ranges[0], vperm_ranges_nused, sizeof vperm_ranges[0],
		compare_vperm_ranges);
#undef proj_vperm_range_addr
	// the number used has changed
	vperm_ranges_nused -= nfreed;
	/* Sanity check our invariants.
	 * - We should get a hit querying for 'begin' and 'end-1'.
	 * - They should be the same hit.
	 * - They should be a single range spanning exactly from 'begin' to 'end-1'. We don't coalesce. */
	if (vperm_ranges_nused >= 2) for (unsigned i = 1; i < vperm_ranges_nused; ++i)
	{
		assert(vperm_ranges[i-1].addr < vperm_ranges[i].addr);
	}
	if (prot_or_negative_one == -1) return;
	// else do some sanity checks
	assert(find_vperm_range_nolock(begin));
	assert(find_vperm_range_nolock((void*) ((uintptr_t) end - 1)));
	assert(find_vperm_range_nolock(begin) == find_vperm_range_nolock((void*) ((uintptr_t) end - 1)));
	assert(find_vperm_range_nolock(begin)->addr == (uintptr_t) begin);
	assert(find_vperm_range_nolock(begin)->addr + find_vperm_range_nolock(begin)->npages * MIN_PAGE_SIZE
		== (uintptr_t) end);
}
__attribute__((visibility("hidden")))
void replace_vperms_over(void *begin, void *end, int prot_or_negative_one)
{

	TAKE_LOCK_W();
	replace_vperms_over_nolock(begin, end, prot_or_negative_one);
	RELEASE_LOCK_W();
}

__attribute__((visibility("hidden")))
int compare_vperm_ranges(const void *m1_as_void, const void *m2_as_void)
{
	const struct vperm_range *m1 = m1_as_void;
	const struct vperm_range *m2 = m2_as_void;
	if (m1->addr == m2->addr)
	{
		// null-addr entries are infinitely high, whatever their npages
		if (!m1->addr) return 0;
		return (ssize_t) m1->npages - (ssize_t) m2->npages;
	}
	// null-addr entries are infinitely high
	if (!m1->addr) /* m1 > m2 */ return 1;
	if (!m2->addr) /* m1 < m2 */ return -1;
	// the usual case
	intptr_t diff = (intptr_t) m1->addr - (intptr_t) m2->addr;
	/* We need to turn it into an 'int' in a sign-preserving way. */
#ifdef __LP64__
	if (diff > INT_MAX || diff < INT_MIN) return diff >> 32;
#endif
	return (int) diff;
}

__attribute__((visibility("hidden")))
int with_vperm_range_exclusive(void *addr, vperm_action_cb *cb, void *cb_arg)
{
	TAKE_LOCK_W();
	struct vperm_range *found = find_vperm_range_nolock(addr);
	int ret = 0;
	void *found_end = NULL;
	if (found)
	{
		found_end = (void*)(uintptr_t)(found->addr + (found->npages * MIN_PAGE_SIZE));
		ret = cb(found, cb_arg);
	}
	switch (ret)
	{
		VPERM_A_NOTHING: break;
		VPERM_A_DELETE:
			replace_vperms_over_nolock((void*)(uintptr_t) found->addr, found_end, /* drop 'em */ -1);
		default: break;
	}
	RELEASE_LOCK_W();
	return ret;
}

__attribute__((visibility("hidden")))
int with_vperm_range_ro(void *addr, vperm_action_cb *cb, void *cb_arg)
{
	TAKE_LOCK_R();
	struct vperm_range *found = find_vperm_range_nolock(addr);
	int ret = 0;
	if (found)
	{
		ret = cb(found, cb_arg);
	}
	// no need to check for an action, because deletion is not an option
	RELEASE_LOCK_R();
	return ret;
}

