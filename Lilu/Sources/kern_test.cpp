//
//  kern_test.cpp
//  Lilu
//
//  Created by joevt on 2022-03-03.
//
// Uses source code from 11.5 xnu but made for 11.6.4 types
// for the purpose of testing why functions such as vm_map_protect and vm_map_write_user fail.

#include <Headers/kern_config.hpp>
#include <Headers/kern_compat.hpp>
#include <Headers/kern_user.hpp>
//#include <Headers/kern_test.hpp>
#include <Headers/kern_cpu.hpp>
#include <Headers/kern_file.hpp>
#include <Headers/kern_devinfo.hpp>
#include <PrivateHeaders/kern_config.hpp>

#include <mach/vm_map.h>
#include <mach-o/fat.h>
#include <kern/task.h>
#include <kern/cs_blobs.h>
#include <sys/vm.h>

#include <IOKit/IOLocks.h>

extern "C" {

#define VM_MAP_STORE_USE_RB
#define XNU_TARGET_OS_OSX 1
#define DEVELOPMENT 0
#undef DEBUG
#define DEBUG 0
#define zalloc_disable_copyio_check false

typedef struct {
	unsigned int
		vmkf_atomic_entry:1,
		vmkf_permanent:1,
		vmkf_guard_after:1,
		vmkf_guard_before:1,
		vmkf_submap:1,
		vmkf_already:1,
		vmkf_beyond_max:1,
		vmkf_no_pmap_check:1,
		vmkf_map_jit:1,
		vmkf_iokit_acct:1,
		vmkf_keep_map_locked:1,
		vmkf_fourk:1,
		vmkf_overwrite_immutable:1,
		vmkf_remap_prot_copy:1,
		vmkf_cs_enforcement_override:1,
		vmkf_cs_enforcement:1,
		vmkf_nested_pmap:1,
		vmkf_no_copy_on_read:1,
		vmkf_32bit_map_va:1,
		vmkf_copy_single_object:1,
		vmkf_copy_pageable:1,
		vmkf_copy_same_map:1,
		vmkf_translated_allow_execute:1,
		__vmkf_unused:9;
} vm_map_kernel_flags_t;
#define VM_MAP_KERNEL_FLAGS_NONE (vm_map_kernel_flags_t) {              \
	.vmkf_atomic_entry = 0, /* keep entry atomic (no coalescing) */ \
	.vmkf_permanent = 0,    /* mapping can NEVER be unmapped */     \
	.vmkf_guard_after = 0,  /* guard page after the mapping */      \
	.vmkf_guard_before = 0, /* guard page before the mapping */     \
	.vmkf_submap = 0,       /* mapping a VM submap */               \
	.vmkf_already = 0,      /* OK if same mapping already exists */ \
	.vmkf_beyond_max = 0,   /* map beyond the map's max offset */   \
	.vmkf_no_pmap_check = 0, /* do not check that pmap is empty */  \
	.vmkf_map_jit = 0,      /* mark entry as JIT region */          \
	.vmkf_iokit_acct = 0,   /* IOKit accounting */                  \
	.vmkf_keep_map_locked = 0, /* keep map locked when returning from vm_map_enter() */ \
	.vmkf_fourk = 0,        /* use fourk pager */                   \
	.vmkf_overwrite_immutable = 0,  /* can overwrite immutable mappings */ \
	.vmkf_remap_prot_copy = 0, /* vm_remap for VM_PROT_COPY */      \
	.vmkf_cs_enforcement_override = 0, /* override CS_ENFORCEMENT */ \
	.vmkf_cs_enforcement = 0,  /* new value for CS_ENFORCEMENT */   \
	.vmkf_nested_pmap = 0, /* use a nested pmap */                  \
	.vmkf_no_copy_on_read = 0, /* do not use copy_on_read */        \
	.vmkf_32bit_map_va = 0, /* allocate in low 32-bits range */     \
	.vmkf_copy_single_object = 0, /* vm_map_copy only 1 VM object */ \
	.vmkf_copy_pageable = 0, /* vm_map_copy with pageable entries */ \
	.vmkf_copy_same_map = 0, /* vm_map_copy to remap in original map */ \
	.vmkf_translated_allow_execute = 0, /* allow execute in translated processes */ \
	.__vmkf_unused = 0                                              \
}

typedef struct vm_map_entry     *vm_map_entry_t;

struct vm_map_links {
	struct vm_map_entry     *prev;          /* previous entry */
	struct vm_map_entry     *next;          /* next entry */
	vm_map_offset_t         start;          /* start address */
	vm_map_offset_t         end;            /* end address */
};

struct vm_map_store {
	void* fill[24/sizeof(void*)];
};

typedef struct vm_object        *vm_object_t;

struct vm_object {
	uint32_t fill[224/sizeof(uint32_t)];
};

typedef struct _vm_map * _vm_map_t;

typedef union vm_map_object {
	vm_object_t             vmo_object;     /* object object */
	_vm_map_t               vmo_submap;     /* belongs to another map */
} vm_map_object_t;

struct vm_map_entry {
	struct vm_map_links     links;          /* links to other entries */
#define vme_prev                links.prev
#define vme_next                links.next
#define vme_start               links.start
#define vme_end                 links.end

	struct vm_map_store     store;
	union vm_map_object     vme_object;     /* object I point to */
	vm_object_offset_t      vme_offset;     /* offset into object */

	unsigned int
	/* boolean_t */ is_shared:1,    /* region is shared */
	/* boolean_t */ is_sub_map:1,   /* Is "object" a submap? */
	/* boolean_t */ in_transition:1, /* Entry being changed */
	/* boolean_t */ needs_wakeup:1, /* Waiters on in_transition */
	/* vm_behavior_t */ behavior:2, /* user paging behavior hint */
	/* behavior is not defined for submap type */
	/* boolean_t */ needs_copy:1,   /* object need to be copied? */

	/* Only in task maps: */
	/* vm_prot_t */ protection:3,   /* protection code */
	/* vm_prot_t */ max_protection:3, /* maximum protection */
	/* vm_inherit_t */ inheritance:2, /* inheritance */
	/* boolean_t */ use_pmap:1,     /*
									 * use_pmap is overloaded:
									 * if "is_sub_map":
									 *      use a nested pmap?
									 * else (i.e. if object):
									 *      use pmap accounting
									 *      for footprint?
									 */
	/* boolean_t */ no_cache:1,     /* should new pages be cached? */
	/* boolean_t */ permanent:1,    /* mapping can not be removed */
	/* boolean_t */ superpage_size:1, /* use superpages of a certain size */
	/* boolean_t */ map_aligned:1,  /* align to map's page size */
	/* boolean_t */ zero_wired_pages:1, /* zero out the wired pages of
										 * this entry it is being deleted
										 * without unwiring them */
	/* boolean_t */ used_for_jit:1,
	/* boolean_t */ pmap_cs_associated:1, /* pmap_cs will validate */
	/* boolean_t */ from_reserved_zone:1, /* Allocated from
										   * kernel reserved zone	 */

	/* iokit accounting: use the virtual size rather than resident size: */
	/* boolean_t */ iokit_acct:1,
	/* boolean_t */ vme_resilient_codesign:1,
	/* boolean_t */ vme_resilient_media:1,
	/* boolean_t */ vme_atomic:1, /* entry cannot be split/coalesced */
	/* boolean_t */ vme_no_copy_on_read:1,
	/* boolean_t */ translated_allow_execute:1, /* execute in translated processes */
	__unused:2;

	unsigned short          wired_count;    /* can be paged if = 0 */
	unsigned short          user_wired_count; /* for vm_wire */

#define MAP_ENTRY_CREATION_DEBUG (0)
#define MAP_ENTRY_INSERTION_DEBUG (0)

#if     MAP_ENTRY_CREATION_DEBUG
	struct vm_map_header    *vme_creation_maphdr;
	uintptr_t               vme_creation_bt[16];
#endif
#if     MAP_ENTRY_INSERTION_DEBUG
	vm_map_offset_t         vme_start_original;
	vm_map_offset_t         vme_end_original;
	uintptr_t               vme_insertion_bt[16];
#endif
};

struct rb_head {
	vm_map_store *rbh_root;
};

typedef union _lck_rw_t_internal_ {
	struct {
		volatile uint16_t       lck_rw_shared_count;    /* No. of accepted readers */
		volatile uint8_t        lck_rw_interlock;       /* Interlock byte */
		volatile uint8_t
			lck_rw_priv_excl:1,                         /* Writers prioritized if set */
			lck_rw_want_upgrade:1,                      /* Read-to-write upgrade waiting */
			lck_rw_want_write:1,                        /* Writer waiting or locked for write */
			lck_r_waiting:1,                            /* Reader is sleeping on lock */
			lck_w_waiting:1,                            /* Writer is sleeping on lock */
			lck_rw_can_sleep:1,                         /* Can attempts to lock go to sleep? */
			lck_rw_padb6:2;                             /* padding */
		uint32_t                lck_rw_tag;             /* This can be obsoleted when stats are in */
		thread_t                lck_rw_owner;           /* Unused */
	};
	struct {
		uint32_t                data;                   /* Single word for count, ilk, and bitfields */
		uint32_t                lck_rw_pad4;
		uint32_t                lck_rw_pad8;
		uint32_t                lck_rw_pad12;
	};
} _lck_rw_t_internal_;

struct vm_map_header {
	struct vm_map_links     links;          /* first, last, min, max */
	int                     nentries;       /* Number of entries */
	boolean_t               entries_pageable;
	/* are map entries pageable? */
#ifdef VM_MAP_STORE_USE_RB
	struct rb_head  rb_head_store;
#endif
	int                     page_shift;     /* page shift */
};

typedef struct pmap             *pmap_t;

typedef uint64_t pmap_paddr_t;


struct pmap {
	uint8_t fill_0[0x40];
	pmap_paddr_t pm_cr3;
	uint8_t fill_0x48[0x6c-0x48];
	boolean_t pagezero_accessible;
	uint8_t fill_0x70[448-0x70];



};

struct __lck_mtx_t__ {
	uint32_t fill [16/sizeof(uint32_t)];
};

struct __lck_mtx_ext_t__ {
	uint32_t fill [72/sizeof(uint32_t)];
};

struct os_refcnt {
	uint32_t ref_count; // os_ref_atomic_t
};


struct _vm_map {
	_lck_rw_t_internal_                lock;           /* map lock */
	struct vm_map_header    hdr;            /* Map entry header */
#define min_offset              hdr.links.start /* start of range */
#define max_offset              hdr.links.end   /* end of range */
	pmap_t                  pmap;           /* Physical map */
	vm_map_size_t           size;           /* virtual size */
	vm_map_size_t           user_wire_limit;/* rlimit on user locked memory */
	vm_map_size_t           user_wire_size; /* current size of user locked memory in this map */
#if XNU_TARGET_OS_OSX
	vm_map_offset_t         vmmap_high_start;
#endif /* XNU_TARGET_OS_OSX */

	union {
		/*
		 * If map->disable_vmentry_reuse == TRUE:
		 * the end address of the highest allocated vm_map_entry_t.
		 */
		vm_map_offset_t         vmu1_highest_entry_end;
		/*
		 * For a nested VM map:
		 * the lowest address in this nested VM map that we would
		 * expect to be unnested under normal operation (i.e. for
		 * regular copy-on-write on DATA section).
		 */
		vm_map_offset_t         vmu1_lowest_unnestable_start;
	} vmu1;
#define highest_entry_end       vmu1.vmu1_highest_entry_end
#define lowest_unnestable_start vmu1.vmu1_lowest_unnestable_start
	decl_lck_mtx_data(, s_lock);                    /* Lock ref, res fields */
	lck_mtx_ext_t           s_lock_ext;
	vm_map_entry_t          hint;           /* hint for quick lookups */
	union {
		struct vm_map_links* vmmap_hole_hint;   /* hint for quick hole lookups */
		struct vm_map_corpse_footprint_header *vmmap_corpse_footprint;
	} vmmap_u_1;
#define hole_hint vmmap_u_1.vmmap_hole_hint
#define vmmap_corpse_footprint vmmap_u_1.vmmap_corpse_footprint
	union {
		vm_map_entry_t          _first_free;    /* First free space hint */
		struct vm_map_links*    _holes;         /* links all holes between entries */
	} f_s;                                          /* Union for free space data structures being used */

#define first_free              f_s._first_free
#define holes_list              f_s._holes

	struct os_refcnt        map_refcnt;       /* Reference count */

	unsigned int
	/* boolean_t */ wait_for_space:1,         /* Should callers wait for space? */
	/* boolean_t */ wiring_required:1,        /* All memory wired? */
	/* boolean_t */ no_zero_fill:1,           /* No zero fill absent pages */
	/* boolean_t */ mapped_in_other_pmaps:1,  /* has this submap been mapped in maps that use a different pmap */
	/* boolean_t */ switch_protect:1,         /* Protect map from write faults while switched */
	/* boolean_t */ disable_vmentry_reuse:1,  /* All vm entries should keep using newer and higher addresses in the map */
	/* boolean_t */ map_disallow_data_exec:1, /* Disallow execution from data pages on exec-permissive architectures */
	/* boolean_t */ holelistenabled:1,
	/* boolean_t */ is_nested_map:1,
	/* boolean_t */ map_disallow_new_exec:1, /* Disallow new executable code */
	/* boolean_t */ jit_entry_exists:1,
	/* boolean_t */ has_corpse_footprint:1,
	/* boolean_t */ terminated:1,
	/* boolean_t */ is_alien:1,              /* for platform simulation, i.e. PLATFORM_IOS on OSX */
	/* boolean_t */ cs_enforcement:1,        /* code-signing enforcement */
	/* boolean_t */ cs_debugged:1,           /* code-signed but debugged */
	/* boolean_t */ reserved_regions:1,      /* has reserved regions. The map size that userspace sees should ignore these. */
	/* boolean_t */ single_jit:1,        /* only allow one JIT mapping */
	/* reserved */ pad:14;
	unsigned int            timestamp;      /* Version number */
};


struct task_internal {
	int8_t fill_0[0x3c0];
	void *bsd_info; // proc
	int8_t fill_3c8[1656-0x3c8];
};

typedef uint16_t vm_tag_t;

typedef struct zone                     *zone_t;

struct zone {
	uint8_t fill_0[184];
};

extern pmap_t   kernel_pmap;

extern lck_rw_type_t    lck_rw_done(lck_rw_t *lck);
extern boolean_t vm_map_entry_should_cow_for_true_share(
	vm_map_entry_t  entry);

#define vm_map_lock(map)                     \
	lck_rw_lock_exclusive((lck_rw_t *)(&(map)->lock));

#define vm_map_unlock(map)          \
	(map)->timestamp++;         \
	lck_rw_done((lck_rw_t *)(&(map)->lock));


#define SUPERPAGE_NBASEPAGES 512

#define SUPERPAGE_SIZE (PAGE_SIZE*SUPERPAGE_NBASEPAGES)
#define SUPERPAGE_MASK (-SUPERPAGE_SIZE)
#define SUPERPAGE_ROUND_DOWN(a) (a & SUPERPAGE_MASK)
#define SUPERPAGE_ROUND_UP(a) ((a + SUPERPAGE_SIZE-1) & SUPERPAGE_MASK)

#define CAST_TO_VM_MAP_ENTRY(x) ((struct vm_map_entry *)(uintptr_t)(x))
#define vm_map_to_entry(map) CAST_TO_VM_MAP_ENTRY(&(map)->hdr.links)

#define VME_SUBMAP_PTR(entry)                   \
	(&((entry)->vme_object.vmo_submap))
#define VME_SUBMAP(entry)                                       \
	((_vm_map_t)((uintptr_t)0 + *VME_SUBMAP_PTR(entry)))
#define VME_OBJECT_PTR(entry)                   \
	(&((entry)->vme_object.vmo_object))
#define VME_OBJECT(entry)                                       \
	((vm_object_t)((uintptr_t)0 + *VME_OBJECT_PTR(entry)))
#define VME_OFFSET(entry)                       \
	((entry)->vme_offset & (vm_object_offset_t)~FOURK_PAGE_MASK)
#define VME_ALIAS_MASK (FOURK_PAGE_MASK)
#define VME_ALIAS(entry)                                        \
	((unsigned int)((entry)->vme_offset & VME_ALIAS_MASK))


#define FOURK_PAGE_MASK         0xFFF
#define PMAP_OPTIONS_PROTECT_IMMEDIATE 0x1000

#define VM_MAP_PAGE_SHIFT(map) ((map) ? (map)->hdr.page_shift : PAGE_SHIFT)
#define VM_MAP_PAGE_SIZE(map) (1 << VM_MAP_PAGE_SHIFT((map)))
#define VM_MAP_PAGE_MASK(map) (VM_MAP_PAGE_SIZE((map)) - 1)
#define VM_MAP_PAGE_ALIGNED(x, pgmask) (((x) & (pgmask)) == 0)

#define vm_map_round_page(x, pgmask) (((vm_map_offset_t)(x) + (pgmask)) & ~((signed)(pgmask)))
#define vm_map_trunc_page(x, pgmask) ((vm_map_offset_t)(x) & ~((signed)(pgmask)))

typedef void (*copyout_shim_fn_t)(const void *, user_addr_t, vm_size_t, unsigned co_src);

#define oneproc(_type, _name, _args) \
	using t_extern_##_name = _type (*) _args ; \
	t_extern_##_name extern_##_name  {nullptr};

#define onevar(_type, _name) _type * extern_##_name  {nullptr} ;
#define callproc(_name) extern_##_name
#define accessvar(_name) (*extern_##_name)

#include <Headers/kern_externs.hpp>


static inline bool
test_VM_MAP_IS_ALIEN(
	_vm_map_t map __unused)
{
	/*
	 * An "alien" process/task/map/pmap should mostly behave
	 * as it currently would on iOS.
	 */
#if XNU_TARGET_OS_OSX
	if (map->is_alien) {
		return true;
	}
	return false;
#else /* XNU_TARGET_OS_OSX */
	return true;
#endif /* XNU_TARGET_OS_OSX */
}

static inline bool
test_VM_MAP_POLICY_WX_FAIL(
	_vm_map_t map __unused)
{
	if (test_VM_MAP_IS_ALIEN(map)) {
		return false;
	}
	return true;
}

boolean_t
test_vm_map_cs_enforcement(
	_vm_map_t map)
{
	if (accessvar(cs_process_enforcement_enable)) {
		return TRUE;
	}
	return map->cs_enforcement;
}


/*
 *	test_vm_map_protect:
 *
 *	Sets the protection of the specified address
 *	region in the target map.  If "set_max" is
 *	specified, the maximum protection is to be set;
 *	otherwise, only the current protection is affected.
 */
kern_return_t
test_vm_map_protect(
	_vm_map_t        map,
	vm_map_offset_t start,
	vm_map_offset_t end,
	vm_prot_t       new_prot,
	boolean_t       set_max)
{
	vm_map_entry_t                  current;
	vm_map_offset_t                 prev;
	vm_map_entry_t                  entry;
	vm_prot_t                       new_max;
	int                             pmap_options = 0;

	if (new_prot & VM_PROT_COPY) {
#if 0
		return KERN_PROTECTION_FAILURE;
#else
		kern_return_t                   kr;

		vm_map_offset_t         new_start;
		vm_prot_t               cur_prot, max_prot;
		vm_map_kernel_flags_t   kflags;

		/* LP64todo - see below */
		if (start >= map->max_offset) {
			return KERN_INVALID_ADDRESS;
		}

		if ((new_prot & VM_PROT_EXECUTE) &&
			map->pmap != kernel_pmap &&
			(test_vm_map_cs_enforcement(map)
#if XNU_TARGET_OS_OSX && __arm64__
			|| !VM_MAP_IS_EXOTIC(map)
#endif /* XNU_TARGET_OS_OSX && __arm64__ */
			) &&
			test_VM_MAP_POLICY_WX_FAIL(map)) {
/*
			DTRACE_VM3(cs_wx,
				uint64_t, (uint64_t) start,
				uint64_t, (uint64_t) end,
				vm_prot_t, new_prot);
*/
			printf("CODE SIGNING: %d[%s] %s can't have both write and exec at the same time\n",
				proc_selfpid(),
				(((struct task_internal*)current_task())->bsd_info
				? callproc(proc_name_address)(((struct task_internal*)current_task())->bsd_info)
				: "?"),
				__FUNCTION__);
			return KERN_PROTECTION_FAILURE;
		}

		/*
		 * Let vm_map_remap_extract() know that it will need to:
		 * + make a copy of the mapping
		 * + add VM_PROT_WRITE to the max protections
		 * + remove any protections that are no longer allowed from the
		 *   max protections (to avoid any WRITE/EXECUTE conflict, for
		 *   example).
		 * Note that "max_prot" is an IN/OUT parameter only for this
		 * specific (VM_PROT_COPY) case.  It's usually an OUT parameter
		 * only.
		 */
		max_prot = new_prot & VM_PROT_ALL;
		cur_prot = VM_PROT_NONE;
		kflags = VM_MAP_KERNEL_FLAGS_NONE;
		kflags.vmkf_remap_prot_copy = TRUE;
		kflags.vmkf_overwrite_immutable = TRUE;
		new_start = start;
		kr = callproc(vm_map_remap)(map,
			&new_start,
			end - start,
			0, /* mask */
			VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
			kflags,
			0,
			(vm_map_t)map,
			start,
			TRUE, /* copy-on-write remapping! */
			&cur_prot, /* IN/OUT */
			&max_prot, /* IN/OUT */
			VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		new_prot &= ~VM_PROT_COPY;
#endif
	}

	vm_map_lock(map);

	/* LP64todo - remove this check when vm_map_commpage64()
	 * no longer has to stuff in a map_entry for the commpage
	 * above the map's max_offset.
	 */
	if (start >= map->max_offset) {
		DBGLOG("user", "start >= map->max_offset");
		vm_map_unlock(map);
		return KERN_INVALID_ADDRESS;
	}

	while (1) {
		/*
		 *      Lookup the entry.  If it doesn't start in a valid
		 *	entry, return an error.
		 */
		if (!callproc(vm_map_lookup_entry)(map, start, &entry)) {
			DBGLOG("user", "!vm_map_lookup_entry(map, start, &entry)");
			vm_map_unlock(map);
			return KERN_INVALID_ADDRESS;
		}

		if (entry->superpage_size && (start & (SUPERPAGE_SIZE - 1))) { /* extend request to whole entry */
			start = SUPERPAGE_ROUND_DOWN(start);
			continue;
		}
		break;
	}
	if (entry->superpage_size) {
		end = SUPERPAGE_ROUND_UP(end);
	}

	/*
	 *	Make a first pass to check for protection and address
	 *	violations.
	 */

	current = entry;
	prev = current->vme_start;
	while ((current != vm_map_to_entry(map)) &&
		(current->vme_start < end)) {
		/*
		 * If there is a hole, return an error.
		 */
		if (current->vme_start != prev) {
			DBGLOG("user", "current->vme_start != prev");
			vm_map_unlock(map);
			return KERN_INVALID_ADDRESS;
		}

		new_max = current->max_protection;
		if ((new_prot & new_max) != new_prot) {
			DBGLOG("user", "(new_prot:%d & new_max:%d) != new_prot:%d", new_prot, new_max, new_prot);
#if 1
			DBGLOG("user", "setting max_prot:%d", current->max_protection | new_prot);
			current->max_protection |= new_prot;
#else
			vm_map_unlock(map);
			return KERN_PROTECTION_FAILURE;
#endif
		}

		if (current->used_for_jit &&
			callproc(pmap_has_prot_policy)(map->pmap, current->translated_allow_execute, current->protection)) {
			DBGLOG("user", "current->used_for_jit && pmap_has_prot_policy");
			vm_map_unlock(map);
			return KERN_PROTECTION_FAILURE;
		}

		if ((new_prot & VM_PROT_WRITE) &&
			(new_prot & VM_PROT_EXECUTE) &&
#if XNU_TARGET_OS_OSX
			map->pmap != kernel_pmap &&
			(test_vm_map_cs_enforcement(map)
#if __arm64__
			|| !VM_MAP_IS_EXOTIC(map)
#endif /* __arm64__ */
			) &&
#endif /* XNU_TARGET_OS_OSX */
			!(current->used_for_jit)) {
/*
			DTRACE_VM3(cs_wx,
				uint64_t, (uint64_t) current->vme_start,
				uint64_t, (uint64_t) current->vme_end,
				vm_prot_t, new_prot);
*/
			printf("CODE SIGNING: %d[%s] %s can't have both write and exec at the same time\n",
				proc_selfpid(),
				(((struct task_internal*)current_task())->bsd_info
				? callproc(proc_name_address)(((struct task_internal*)current_task())->bsd_info)
				: "?"),
				__FUNCTION__);
			new_prot &= ~VM_PROT_EXECUTE;
			if (test_VM_MAP_POLICY_WX_FAIL(map)) {
				DBGLOG("user", "test_VM_MAP_POLICY_WX_FAIL(map)");
				vm_map_unlock(map);
				return KERN_PROTECTION_FAILURE;
			}
		}

		/*
		 * If the task has requested executable lockdown,
		 * deny both:
		 * - adding executable protections OR
		 * - adding write protections to an existing executable mapping.
		 */
		if (map->map_disallow_new_exec == TRUE) {
			if ((new_prot & VM_PROT_EXECUTE) ||
				((current->protection & VM_PROT_EXECUTE) && (new_prot & VM_PROT_WRITE))) {
				DBGLOG("user", "map->map_disallow_new_exec == TRUE");
				vm_map_unlock(map);
				return KERN_PROTECTION_FAILURE;
			}
		}

		prev = current->vme_end;
		current = current->vme_next;
	}

#if __arm64__
	if (end > prev &&
		end == vm_map_round_page(prev, VM_MAP_PAGE_MASK(map))) {
		vm_map_entry_t prev_entry;

		prev_entry = current->vme_prev;
		if (prev_entry != vm_map_to_entry(map) &&
			!prev_entry->map_aligned &&
			(vm_map_round_page(prev_entry->vme_end,
			VM_MAP_PAGE_MASK(map))
			== end)) {
			/*
			 * The last entry in our range is not "map-aligned"
			 * but it would have reached all the way to "end"
			 * if it had been map-aligned, so this is not really
			 * a hole in the range and we can proceed.
			 */
			prev = end;
		}
	}
#endif /* __arm64__ */

	if (end > prev) {
		DBGLOG("user", "end > prev");
		vm_map_unlock(map);
		return KERN_INVALID_ADDRESS;
	}

	/*
	 *	Go back and fix up protections.
	 *	Clip to start here if the range starts within
	 *	the entry.
	 */

	current = entry;
	if (current != vm_map_to_entry(map)) {
		/* clip and unnest if necessary */
		callproc(vm_map_clip_start)(map, current, start);
	}

	while ((current != vm_map_to_entry(map)) &&
		(current->vme_start < end)) {
		vm_prot_t       old_prot;

		callproc(vm_map_clip_end)(map, current, end);

		if (current->is_sub_map) {
			/* clipping did unnest if needed */
			assert(!current->use_pmap);
		}

		old_prot = current->protection;

		if (set_max) {
			current->max_protection = new_prot;
			current->protection = new_prot & old_prot;
		} else {
			current->protection = new_prot;
		}

		/*
		 *	Update physical map if necessary.
		 *	If the request is to turn off write protection,
		 *	we won't do it for real (in pmap). This is because
		 *	it would cause copy-on-write to fail.  We've already
		 *	set, the new protection in the map, so if a
		 *	write-protect fault occurred, it will be fixed up
		 *	properly, COW or not.
		 */
		if (current->protection != old_prot) {
			/* Look one level in we support nested pmaps */
			/* from mapped submaps which are direct entries */
			/* in our map */

			vm_prot_t prot;

			prot = current->protection;
			if (current->is_sub_map || (VME_OBJECT(current) == NULL) || (VME_OBJECT(current) != accessvar(compressor_object))) {
				prot &= ~VM_PROT_WRITE;
			} else {
				assert(!VME_OBJECT(current)->code_signed);
				assert(VME_OBJECT(current)->copy_strategy == MEMORY_OBJECT_COPY_NONE);
			}

			if (callproc(override_nx)(map, VME_ALIAS(current)) && prot) {
				prot |= VM_PROT_EXECUTE;
			}

#if DEVELOPMENT || DEBUG
			aaaaaa
			if (!(old_prot & VM_PROT_EXECUTE) &&
				(prot & VM_PROT_EXECUTE) &&
				accessvar(panic_on_unsigned_execute) &&
				(callproc(proc_selfcsflags)() & CS_KILL)) {
				panic("vm_map_protect(%p,0x" PRIKADDR ",0x" PRIKADDR ") old=0x%x new=0x%x - <rdar://23770418> code-signing bypass?\n", map, CASTKADDR((uint64_t)current->vme_start), CASTKADDR((uint64_t)current->vme_end), old_prot, prot);
			}
#endif /* DEVELOPMENT || DEBUG */

			if (callproc(pmap_has_prot_policy)(map->pmap, current->translated_allow_execute, prot)) {
				if (current->wired_count) {
					panic("vm_map_protect(%p,0x" PRIKADDR ",0x" PRIKADDR ") new=0x%x wired=%x\n",
						map, CASTKADDR((uint64_t)current->vme_start), CASTKADDR((uint64_t)current->vme_end), prot, current->wired_count);
				}

				/* If the pmap layer cares about this
				 * protection type, force a fault for
				 * each page so that vm_fault will
				 * repopulate the page with the full
				 * set of protections.
				 */
				/*
				 * TODO: We don't seem to need this,
				 * but this is due to an internal
				 * implementation detail of
				 * pmap_protect.  Do we want to rely
				 * on this?
				 */
				prot = VM_PROT_NONE;
			}

			if (current->is_sub_map && current->use_pmap) {
				callproc(pmap_protect)( VME_SUBMAP(current)->pmap,
					current->vme_start,
					current->vme_end,
					prot);
			} else {
				if (prot & VM_PROT_WRITE) {
					if (VME_OBJECT(current) == accessvar(compressor_object)) {
						/*
						 * For write requests on the
						 * compressor, we wil ask the
						 * pmap layer to prevent us from
						 * taking a write fault when we
						 * attempt to access the mapping
						 * next.
						 */
						pmap_options |= PMAP_OPTIONS_PROTECT_IMMEDIATE;
					}
				}

				callproc(pmap_protect_options)(map->pmap,
					current->vme_start,
					current->vme_end,
					prot,
					pmap_options,
					NULL);
			}
		}
		current = current->vme_next;
	}

	current = entry;
	while ((current != vm_map_to_entry(map)) &&
		(current->vme_start <= end)) {
		callproc(vm_map_simplify_entry)(map, current);
		current = current->vme_next;
	}

	DBGLOG("user", "test_vm_map_protect success");
	vm_map_unlock(map);
	return KERN_SUCCESS;
}

kern_return_t
test_vm_protect(
	_vm_map_t               map,
	vm_offset_t             start,
	vm_size_t               size,
	boolean_t               set_maximum,
	vm_prot_t               new_protection)
{
//	if (!get_kernel_externals()) return KERN_FAILURE;

	if ((map == (_vm_map_t)VM_MAP_NULL) || (start + size < start) ||
		(new_protection & ~(VM_PROT_ALL | VM_PROT_COPY))) {
		return KERN_INVALID_ARGUMENT;
	}

	if (size == 0) {
		return KERN_SUCCESS;
	}

	return test_vm_map_protect(map,
			   vm_map_trunc_page(start,
			   VM_MAP_PAGE_MASK(map)),
			   vm_map_round_page(start + size,
			   VM_MAP_PAGE_MASK(map)),
			   new_protection,
			   set_maximum);
}

#if 1

extern "C" {
void vm_map_deallocate(vm_map_t map);
//extern pt_entry_t *debugger_ptep;
extern vm_map_offset_t debugger_window_kva;
extern int _bcopy2(const void *, void *);
extern int _bcopy4(const void *, void *);
extern int _bcopy8(const void *, void *);

}


static inline uintptr_t
test_get_cr3_raw(void)
{
	uintptr_t cr3;
	__asm__ volatile ("mov %%cr3, %0" : "=r" (cr3));
	return cr3;
}

static inline uintptr_t
test_get_cr3_base(void)
{
	uintptr_t cr3;
	__asm__ volatile ("mov %%cr3, %0" : "=r" (cr3));
	return cr3 & ~(0xFFFULL);
}

static inline void
test_set_cr3_raw(uintptr_t value)
{
	__asm__ volatile ("mov %0, %%cr3" : : "r" (value));
}

#define ENABLE_SMAPLOG 0


static inline void
test_stac(void)
{
	__asm__  volatile ("stac");
}

static inline void
test_clac(void)
{
	__asm__  volatile ("clac");
}

static inline void
test_user_access_enable(void)
{
	if (accessvar(pmap_smap_enabled)) {
		test_stac();
#if ENABLE_SMAPLOG
		smaplog_add_entry(TRUE);
#endif
	}
}

static inline void
test_user_access_disable(void)
{
	if (accessvar(pmap_smap_enabled)) {
		test_clac();
#if ENABLE_SMAPLOG
		smaplog_add_entry(FALSE);
#endif
	}
}



#define CO_SRC_NORMAL 1       //copyout() called
#define CO_SRC_MSG    (1<<1)    //copyoutmsg() called
#define CO_SRC_PHYS   (1<<2)    //copyio(COPYOUTPHYS,...) called

#define CALL_COPYOUT_SHIM_NRML(ka, ua, nb)
//	if(accessvar(copyout_shim_fn) && (accessvar(co_src_flags) & CO_SRC_NORMAL)) {accessvar(copyout_shim_fn)(ka,ua,nb,CO_SRC_NORMAL); }

/*
 * Types of copies:
 */
#define COPYIN          0       /* from user virtual to kernel virtual */
#define COPYOUT         1       /* from kernel virtual to user virtual */
#define COPYINSTR       2       /* string variant of copyout */
#define COPYINPHYS      3       /* from user virtual to kernel physical */
#define COPYOUTPHYS     4       /* from kernel physical to user virtual */
#define COPYINATOMIC32  5       /* from user virtual to kernel virtual */
#define COPYINATOMIC64  6       /* from user virtual to kernel virtual */
#define COPYOUTATOMIC32 7       /* from user virtual to kernel virtual */
#define COPYOUTATOMIC64 8       /* from user virtual to kernel virtual */

#define COPYIO_TRACE(...)

typedef struct thread *_thread_t;

#define         CopyIOActive    0x2 /* Checked to ensure DTrace actions do not re-enter copyio(). */

#define         vm_map_max(map) ((map)->max_offset)


struct machine_thread {
	uint8_t fill[0x48];
	uint32_t specFlags;
	uint64_t thread_gpu_ns;
	uint8_t fill_0x58[896-0x58];
};

struct thread {
	uint8_t fill_0[0x98];
	struct machine_thread machine;
	uint8_t fill_0x418[0x6b0-0x418];
	_vm_map_t map;
	uint8_t fill_0x6b8[2208-0x6b8];
};



static  inline void *
test_PHYSMAP_PTOV_check(void *paddr)
{
	uint64_t pvaddr = (uint64_t)paddr + accessvar(physmap_base);

	if (__improbable(pvaddr >= accessvar(physmap_max))) {
		panic("PHYSMAP_PTOV bounds exceeded, 0x%qx, 0x%qx, 0x%qx",
			pvaddr, accessvar(physmap_base), accessvar(physmap_max));
	}

	return (void *)pvaddr;
}

#define PHYSMAP_PTOV(x) (test_PHYSMAP_PTOV_check((void*) (x)))


static int
test_copyio(int copy_type, user_addr_t user_addr, char *kernel_addr,
	vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
	DBGLOG("user", "[ test_copyio");
	_thread_t       thread = current_thread();
	pmap_t          pmap;
	vm_size_t       bytes_copied;
	int             error = 0;
	boolean_t       istate = FALSE;
	boolean_t       recursive_CopyIOActive;
#if     COPYIO_TRACE_ENABLED
	int             debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif
#if 0 // not testing this
	vm_size_t kernel_buf_size = 0;
#endif

/*
	if (__improbable(nbytes > copysize_limit_panic)) {
		panic("%s(%p, %p, %lu) - transfer too large", __func__,
			(void *)user_addr, (void *)kernel_addr, nbytes);
	}
*/
	COPYIO_TRACE(debug_type | DBG_FUNC_START,
		user_addr, kernel_addr, nbytes, use_kernel_map, 0);

	if (__improbable(nbytes == 0)) {
		DBGLOG("user", "] test_copyio __improbable(nbytes == 0)");
		return error;
		//goto out;
	}

	pmap = thread->map->pmap;
	boolean_t nopagezero = thread->map->pmap->pagezero_accessible;

	if ((copy_type != COPYINPHYS) && (copy_type != COPYOUTPHYS)) {
#if 0 // not testing this
		if (__improbable((vm_offset_t)kernel_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS)) {
			panic("Invalid copy parameter, copy type: %d, kernel address: %p", copy_type, kernel_addr);
		}
		if (__probable(!zalloc_disable_copyio_check)) {
			zone_t src_zone = NULL;
			kernel_buf_size = callproc(zone_element_size)(kernel_addr, &src_zone);
			/*
			 * Size of elements in the permanent zone is not saved as a part of the
			 * zone's info
			 */
			if (__improbable(src_zone && !src_zone->z_permanent &&
				kernel_buf_size < nbytes)) {
				panic("copyio: kernel buffer %p has size %lu < nbytes %lu", kernel_addr, kernel_buf_size, nbytes);
			}
		}
#endif
	}

	/* Sanity and security check for addresses to/from a user */

	if (__improbable(((pmap != kernel_pmap) && (use_kernel_map == 0)) &&
		((nbytes && (user_addr + nbytes <= user_addr)) || ((user_addr + nbytes) > vm_map_max(thread->map))))) {
		error = EFAULT;
		DBGLOG("user", "] test_copyio sanity check fail");
		return error;
		//goto out;
	}

	if (copy_type >= COPYINATOMIC32 && copy_type <= COPYOUTATOMIC64) {
		if (__improbable(pmap == kernel_pmap)) {
			error = EFAULT;
			DBGLOG("user", "] test_copyio cant use atomic in kernel_pmap");
			return error;
			//goto out;
		}
	}

#if KASAN
	switch (copy_type) {
	case COPYIN:
	case COPYINSTR:
	case COPYINATOMIC32:
	case COPYINATOMIC64:
		__asan_storeN((uptr)kernel_addr, nbytes);
		break;
	case COPYOUT:
	case COPYOUTATOMIC32:
	case COPYOUTATOMIC64:
		__asan_loadN((uptr)kernel_addr, nbytes);
		kasan_check_uninitialized((vm_address_t)kernel_addr, nbytes);
		break;
	}
#endif

	/*
	 * If the no_shared_cr3 boot-arg is set (true), the kernel runs on
	 * its own pmap and cr3 rather than the user's -- so that wild accesses
	 * from kernel or kexts can be trapped. So, during copyin and copyout,
	 * we need to switch back to the user's map/cr3. The thread is flagged
	 * "CopyIOActive" at this time so that if the thread is pre-empted,
	 * we will later restore the correct cr3.
	 */
	recursive_CopyIOActive = thread->machine.specFlags & CopyIOActive;

	boolean_t pdswitch = accessvar(no_shared_cr3) || nopagezero;

	if (__improbable(pdswitch)) {
		istate = ml_set_interrupts_enabled(FALSE);
		if (nopagezero && accessvar(pmap_pcid_ncpus)) {
			callproc(pmap_pcid_activate)(pmap, cpu_number(), TRUE, TRUE);
		} else if (test_get_cr3_base() != pmap->pm_cr3) {
			test_set_cr3_raw(pmap->pm_cr3);
		}
		thread->machine.specFlags |= CopyIOActive;
	} else {
		thread->machine.specFlags |= CopyIOActive;
	}

	test_user_access_enable();

#if DEVELOPMENT || DEBUG
	/*
	 * Ensure that we're running on the target thread's cr3.
	 */
	if ((pmap != kernel_pmap) && !use_kernel_map &&
		(test_get_cr3_base() != pmap->pm_cr3)) {
		panic("copyio(%d,%p,%p,%ld,%p,%d) cr3 is %p expects %p",
			copy_type, (void *)user_addr, kernel_addr, nbytes, lencopied, use_kernel_map,
			(void *) test_get_cr3_raw(), (void *) pmap->pm_cr3);
	}
#endif

	if (__improbable(pdswitch)) {
		(void) ml_set_interrupts_enabled(istate);
	}

	COPYIO_TRACE(0xeff70044 | DBG_FUNC_NONE, user_addr,
		kernel_addr, nbytes, 0, 0);

	switch (copy_type) {
	case COPYIN:
		error = callproc(_bcopy)((const void *) user_addr,
			kernel_addr,
			nbytes);
		break;

	case COPYOUT:
		error = callproc(_bcopy)(kernel_addr,
			(void *) user_addr,
			nbytes);
		DBGLOG_COND(error, "user", "_bcopy error:%d", error);
		break;

	case COPYINPHYS:
		error = callproc(_bcopy)((const void *) user_addr,
			PHYSMAP_PTOV(kernel_addr),
			nbytes);
		break;

	case COPYOUTPHYS:
		error = callproc(_bcopy)((const void *) PHYSMAP_PTOV(kernel_addr),
			(void *) user_addr,
			nbytes);
		break;

	case COPYINATOMIC32:
		error = callproc(_copyin_atomic32)((const void *) user_addr,
			(void *) kernel_addr);
		break;

	case COPYINATOMIC64:
		error = callproc(_copyin_atomic64)((const void *) user_addr,
			(void *) kernel_addr);
		break;

	case COPYOUTATOMIC32:
		error = callproc(_copyout_atomic32)((const void *) kernel_addr,
			(void *) user_addr);
		break;

	case COPYOUTATOMIC64:
		error = callproc(_copyout_atomic64)((const void *) kernel_addr,
			(void *) user_addr);
		break;

	case COPYINSTR:
		error = callproc(_bcopystr)((const void *) user_addr,
			kernel_addr,
			(int) nbytes,
			&bytes_copied);

		/*
		 * lencopied should be updated on success
		 * or ENAMETOOLONG...  but not EFAULT
		 */
		if (error != EFAULT) {
			*lencopied = bytes_copied;
		}

		if (error) {
#if KDEBUG
			nbytes = *lencopied;
#endif
			break;
		}
		if (*(kernel_addr + bytes_copied - 1) == 0) {
			/*
			 * we found a NULL terminator... we're done
			 */
#if KDEBUG
			nbytes = *lencopied;
#endif
			break;
		} else {
			/*
			 * no more room in the buffer and we haven't
			 * yet come across a NULL terminator
			 */
#if KDEBUG
			nbytes = *lencopied;
#endif
			error = ENAMETOOLONG;
			break;
		}
	}

	test_user_access_disable();

	if (__improbable(pdswitch)) {
		istate = ml_set_interrupts_enabled(FALSE);
		if (!recursive_CopyIOActive && (test_get_cr3_raw() != kernel_pmap->pm_cr3)) {
			if (nopagezero && accessvar(pmap_pcid_ncpus)) {
				callproc(pmap_pcid_activate)(pmap, cpu_number(), TRUE, FALSE);
			} else {
				test_set_cr3_raw(kernel_pmap->pm_cr3);
			}
		}

		if (!recursive_CopyIOActive) {
			thread->machine.specFlags &= ~CopyIOActive;
		}
		(void) ml_set_interrupts_enabled(istate);
	} else if (!recursive_CopyIOActive) {
		thread->machine.specFlags &= ~CopyIOActive;
	}

//out:
	COPYIO_TRACE(debug_type | DBG_FUNC_END, user_addr, kernel_addr, nbytes, error, 0);

	DBGLOG("user", "] test_copyio result:%d", error);
	return error;
} // test_copyio

int
test_copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
/*
	if (extern_copyout_shim_fn) {
		if(*extern_copyout_shim_fn && (accessvar(co_src_flags) & CO_SRC_NORMAL)) {
			(*extern_copyout_shim_fn)(kernel_addr, user_addr, nbytes, CO_SRC_NORMAL);
		}
	}
	else {
		DBGLOG("user", "extern_copyout_shim_fn is not initialized");
	}
*/
	return test_copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}


static bool foundExternals = false;

kern_return_t
test_vm_map_write_user(
	vm_map_t                map,
	void                    *src_p,
	vm_map_address_t        dst_addr,
	vm_size_t               size)
{
	if (!foundExternals) {
		return KERN_FAILURE;
	}

	kern_return_t   kr = KERN_SUCCESS;

	if (callproc(current_map)() == map) {
		if (test_copyout(src_p, dst_addr, size)) {
			DBGLOG("user", "copyout current_map fail KERN_INVALID_ADDRESS");
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_t        oldmap;

		/* take on the identity of the target map while doing */
		/* the transfer */

		callproc(vm_map_reference)(map);
		oldmap = callproc(vm_map_switch)(map);
		if (test_copyout(src_p, dst_addr, size)) {
			DBGLOG("user", "copyout different map fail KERN_INVALID_ADDRESS");
			kr = KERN_INVALID_ADDRESS;
		}
		callproc(vm_map_switch)(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

#endif

}

void get_kernel_externals(KernelPatcher &patcher) {
	bool good = true;
	#define onevar(_type, _name) \
		extern_##_name = reinterpret_cast<_type *>(patcher.solveSymbol(patcher.KernelID, "_" # _name )); \
		DBGLOG_COND(!extern_##_name, "user", "symbol not found _%s", #_name ); \
		if (!extern_##_name) good = false;
	#define oneproc(_type, _name, _args) \
		extern_##_name = reinterpret_cast<t_extern_##_name>(patcher.solveSymbol(patcher.KernelID, "_" # _name )); \
		DBGLOG_COND(!extern_##_name, "user", "symbol not found _%s", #_name ); \
		if (!extern_##_name) good = false;

	#include <Headers/kern_externs.hpp>

	if (good) {
		foundExternals = true;
	}
}
