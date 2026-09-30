#include "systrap.h"

struct vperm_range vperm_ranges[MAX_VPERM_RANGES] __attribute__((visibility("hidden")));

/* Really simple lock-free algorithm: unsorted array, linear search.
 * Just scan circularly, starting from a 'hint', for a free entry. Updating
 * the hint can be a non-atomic write. Bagging a free entry is CAS. Initially assume
 * we don't run out; later (TODO) keep an atomic counter of #used. Re-check counter
 * after a complete cycle of the list. We don't need a huge capacity for deferral;
 * if full, just force one. Each record needs a mutex to avoid racy forcing. Only
 * release the mutex when 'addr' is zeroed. */
struct vperm_range *vperm_ranges_free_hint = &vperm_ranges[0];
static void add_vperm_range(void *addr, size_t len, int prot)
{
	assert(addr != NULL);
	struct vperm_range *hint = vperm_ranges_free_hint;
	_Bool tried_one = 0;
#define NEXT_ENTRY(p) ( \
	((p) == &vperm_ranges[MAX_VPERM_RANGES-1]) \
						? &vperm_ranges[0] \
						: (p) + 1 \
	)
	for (struct vperm_range *m = hint;
			!(tried_one && m == hint); /* have we got around to our starting point again? */
			tried_one = 1, m = NEXT_ENTRY(m))
	{
		/* Try to bag this one if it's free */
		void *this_entry_addr = m->addr;
		if (this_entry_addr == NULL)
		{
			_Bool success = /*atomic_compare_exchange_strong*/
					__sync_bool_compare_and_swap
					(&m->addr, NULL, addr);
			if (success)
			{
				m->length = len;
				m->prot = prot;
				// update the hint
				vperm_ranges_free_hint = NEXT_ENTRY(m);
				return;
			}
		}
	}
#undef NEXT_ENTRY
	/* If we got here, we tried every slot but failed to bag any free one. */
	abort(); // FIXME
}			

/* FIXME: needs some concurrency control. */
__attribute__((visibility("hidden")))
struct vperm_range *find_vperm_range(void *addr)
{
	for (m = &vperm_ranges[0]; m != &vperm_ranges[MAX_VPERM_RANGES]; ++m)
	{
		if ((uintptr_t) m->addr <= ip && ip < (uintptr_t) m->addr + m->length) break;
	}
	if (m == &vperm_ranges[MAX_VPERM_RANGES]) return NULL;
	return m;
}

__attribute__((visibility("hidden")))
int compare_vperm_ranges(const void *m1_as_void, const void *m2_as_void)
{
	const struct vperm_range *m1 = m1_as_void;
	const struct vperm_range *m2 = m2_as_void;
	if (m1->addr != m2->addr) return (intptr_t) m1->addr - (intptr_t) m2->addr;
	return (ssize_t) m1->length - (ssize_t) m2->length;
}


