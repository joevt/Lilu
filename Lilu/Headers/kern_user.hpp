//
//  kern_user.hpp
//  Lilu
//
//  Copyright © 2016-2017 vit9696. All rights reserved.
//

#ifndef kern_user_hpp
#define kern_user_hpp

#include <Headers/kern_config.hpp>
#include <Headers/kern_patcher.hpp>

#include <mach/shared_region.h>
#include <sys/kauth.h>

class UserPatcher {
public:
	/**
	 *  Initialise UserPatcher, prepare for modifications
	 *
	 *  @param patcher        kernel patcher instance
	 *  @param preferSlowMode policy boot type
	 *
	 *  @return true on success
	 */
	bool init(KernelPatcher &patcher, bool preferSlowMode);

	/**
	 *  Deinitialise UserPatcher, must be called regardless of the init error
	 */
	void deinit();

	/**
	 *  Obtain page protection
	 *
	 *  @param map  vm map
	 *  @param addr map offset
	 *
	 *  @return protection
	 */
	EXPORT vm_prot_t getPageProtection(vm_map_t map, vm_map_address_t addr);

	/**
	 *  Mach segment/section references for patch locations
	 */
	enum FileSegment : uint32_t {
		SegmentsTextStart,
		SegmentTextText = SegmentsTextStart,
		SegmentTextStubs,
		SegmentTextConst,
		SegmentTextCstring,
		SegmentTextUstring,
		SegmentsTextEnd = SegmentTextUstring,
		SegmentsDataStart,
		SegmentDataConst = SegmentsDataStart,
		SegmentDataCfstring,
		SegmentDataCommon,
		SegmentsDataEnd = SegmentDataCommon,
		SegmentTotal
	};

	/**
	 *  Mach segment names kept in sync with FileSegment
	 */
	const char *fileSegments[SegmentTotal] {
		"__TEXT",
		"__TEXT",
		"__TEXT",
		"__TEXT",
		"__TEXT",
		"__DATA",
		"__DATA",
		"__DATA"
	};

	/**
	 *  Mach section names kept in sync with FileSegment
	 */
	const char *fileSections[SegmentTotal] {
		"__text",
		"__stubs",
		"__const",
		"__cstring",
		"__ustring",
		"__const",
		"__cfstring",
		"__common"
	};

	/**
	 * Binary modification patches flags
	 */
	enum BinaryModPatchFlags {
		/*
		 * Only applies to one process, not globally.
		 */
		LocalOnly = 1
	};

	/**
	 *  Structure holding lookup-style binary patches
	 */
	struct BinaryModPatch {
		cpu_type_t cpu;
		uint32_t flags;
		const uint8_t *find;
		const uint8_t *replace;
		size_t size;
		size_t skip;
		size_t count;
		FileSegment segment;
		uint32_t section;
	};

#if defined(__i386__)
	static_assert(sizeof(BinaryModPatch) == 36, "BinaryModPatch 32-bit ABI compatibility failure");
#elif defined(__x86_64__)
	static_assert(sizeof(BinaryModPatch) == 56, "BinaryModPatch 64-bit ABI compatibility failure");
#else
#error Unsupported arch.
#endif

	/**
	 *  Structure describing the modifications for the binary
	 */
	struct BinaryModInfo {
		const char *path;
		BinaryModPatch *patches;
		size_t count;
		vm_address_t startTEXT;
		vm_address_t endTEXT;
		vm_address_t startDATA;
		vm_address_t endDATA;
	};

	/**
	 *  Structure describing relevant processes run
	 */
	struct ProcInfo {
		/**
		 *  Process matching flags
		 */
		enum ProcFlags {
			MatchExact  = 0,
			MatchAny    = 1,
			MatchPrefix = 2,
			MatchSuffix = 4,
			MatchMask   = MatchExact | MatchAny | MatchPrefix | MatchSuffix
		};

		/**
		 *  Unused (aka disabled) proc info section
		 */
		static constexpr uint32_t SectionDisabled {0};

		const char *path {nullptr};
		uint32_t len {0};
		uint32_t section {SectionDisabled};
		uint32_t flags {MatchExact};
	};

	/**
	 *  External callback type for on process invocation
	 *
	 *  @param user    user provided pointer at registering
	 *  @param patcher user patcher instance
	 *  @param map     process image vm_map
	 *  @param path    path to the binary absolute or relative
	 *  @param len     path length excluding null terminator
	 */
	using t_BinaryLoaded = void (*)(void *user, UserPatcher &patcher, vm_map_t map, const char *path, size_t len);

	/**
	 *  Instructs user patcher to do further actions
	 *
	 *  @param procs    process list
	 *  @param procNum  process list size
	 *  @param mods     modification list
	 *  @param modNum   modification list size
	 *  @param callback callback function
	 *  @param user     pointer that will be passed to the callback function
	 */
	bool registerPatches(ProcInfo **procs, size_t procNum, BinaryModInfo **mods, size_t modNum, t_BinaryLoaded callback, void *user);

	/**
	 *  Reads current process header
	 *
	 *  @param map     vm map
	 *  @param header  Mach-O header
	 *
	 *  @return false on failure
	 */
	EXPORT bool getTaskHeader(vm_map_t map, mach_header_64 &header);

	/**
	 *  Disables dyld_shared_cache for the current process
	 *
	 *  @param map  vm map
	 *
	 *  @return false on mach image failure
	 */
	EXPORT bool injectRestrict(vm_map_t map);

	/**
	 *  Injects payload into the process right after the header with EP replacement.
	 *
	 *  @param map      vm map
	 *  @param payload  code
	 *  @param size     code size (up to PAGE_SIZE)
	 *  @param ep       original entrypoint (may be written to code before copying)
	 *
	 *  @return false on mach image failure
	 */
	EXPORT bool injectPayload(vm_map_t map, uint8_t *payload, size_t size, void *ep=nullptr);

	/**
	 *  Allocates a new segment in the process.
	 *
	 *  @param map      vm map
	 *  @param addr     allocation address (e.g. a little below SHARED_REGION_BASE_X86_64)
	 *  @param payload  code
	 *  @param size     code size (must be PAGE_SIZE-aligned)
	 *  @param prot     segment protection
	 *
	 *  @return allocated address or 0 on failure
	 */
	EXPORT vm_address_t injectSegment(vm_map_t taskPort, vm_address_t addr, uint8_t *payload, size_t size, vm_prot_t prot);

	/**
	 *  Activates monitoring functions if necessary
	 */
	void activate();

	/**
	 *  Get active dyld shared cache path.
	 *
	 *  @return shared cache path constant
	 */
	EXPORT static const char *getSharedCachePath() DEPRECATE("Use matchSharedCachePath, macOS 12 has multiple caches");

	/**
	 *  Check if the supplied path matches dyld shared cache path.
	 *
	 *  @param path  image path
	 *
	 *  @return shared cache path constant
	 */
	EXPORT static bool matchSharedCachePath(const char *path);

	/**
	 *  Dump debug counters
	 */
	EXPORT static void dumpCounters();

private:

	/**
	 *  Kernel function prototypes
	 */
	using vm_map_entry_t = void *;
	using vm_shared_region_t = void *;
	using shared_file_mapping_np = void *;
	using sr_file_mappings = void *;
	using vm_page_t = void *;
	using t_current_map = vm_map_t (*)(void);
	using t_get_task_map = vm_map_t (*)(task_t);
	using t_get_map_min = vm_map_offset_t (*)(vm_map_t);
	using t_vm_map_switch_protect = void (*)(vm_map_t, boolean_t);
	using t_vm_map_check_protection = boolean_t (*)(vm_map_t, vm_map_offset_t, vm_map_offset_t, vm_prot_t);
	using t_vm_map_read_user = kern_return_t (*)(vm_map_t, vm_map_address_t, const void *, vm_size_t);
	using t_vm_map_write_user = kern_return_t (*)(vm_map_t, const void *, vm_map_address_t, vm_size_t);
	using t_vm_map_lookup_entry = boolean_t (*)(vm_map_t map, vm_map_address_t address, vm_map_entry_t *entry);
	using t_vm_page_validate_cs_mapped = void (*)(vm_page_t page, vm_map_size_t fault_page_size, vm_map_offset_t fault_phys_offset, const void *kaddr);
	using t_vm_page_validate_cs_mapped_slow = void (*)(vm_page_t page, const void *kaddr);

	/**
	 *  Original kernel function trampolines
	 */
	mach_vm_address_t orgCodeSignValidatePageWrapper {};
	mach_vm_address_t orgCodeSignValidateRangeWrapper {};
	mach_vm_address_t orgVmSharedRegionMapFile {};
	mach_vm_address_t orgVmSharedRegionSlide {};
	mach_vm_address_t orgTaskSetMainThreadQos {};
	mach_vm_address_t org_vm_page_validate_cs_mapped {};
	mach_vm_address_t org_vm_page_validate_cs_mapped_slow {};

	t_current_map org_current_map {nullptr};
	t_get_map_min org_get_map_min {nullptr};
	t_get_task_map org_get_task_map {nullptr};
	t_vm_map_switch_protect org_vm_map_switch_protect {nullptr};
	t_vm_map_check_protection org_vm_map_check_protection {nullptr};
	t_vm_map_read_user org_vm_map_read_user {nullptr};
	t_vm_map_write_user org_vm_map_write_user {nullptr};
	t_vm_map_lookup_entry org_vm_map_lookup_entry {nullptr};

	/**
	 *  Kernel function wrappers
	 */
	static boolean_t codeSignValidateRangeWrapper           (vnode_t vp , memory_object_t pager, memory_object_offset_t range_offset, const void *data, memory_object_size_t data_size, unsigned *tainted);
	static void      codeSignValidatePageWrapperBigSur      (vnode_t vp , memory_object_t pager, memory_object_offset_t page_offset , const void *data, int *validated_p,                    int *tainted_p, int *nx_p);
	static boolean_t codeSignValidatePageWrapperYosemite    (void *blobs, memory_object_t pager, memory_object_offset_t page_offset , const void *data,                                 unsigned *tainted);
	static boolean_t codeSignValidatePageWrapperMountainLion(void *blobs, memory_object_t pager, memory_object_offset_t page_offset , const void *data,                                boolean_t *tainted);
	static boolean_t codeSignValidatePageWrapperLeopard     (void *blobs,                        memory_object_offset_t page_offset , const void *data,                                boolean_t *tainted);

	static void wrap_vm_page_validate_cs_mapped(vm_page_t page, vm_map_size_t fault_page_size, vm_map_offset_t fault_phys_offset, const void *kaddr);
	static void wrap_vm_page_validate_cs_mapped_slow(vm_page_t page, const void *kaddr);

	static vm_map_t swapTaskMap(task_t task, thread_t thread, vm_map_t map, boolean_t doswitch);
	static vm_map_t vmMapSwitch(vm_map_t map);

	static kern_return_t vmSharedRegionMapFileBigSur   (vm_shared_region_t shared_region,       int sr_mappings_count, sr_file_mappings *sr_mappings);
	static kern_return_t vmSharedRegionMapFileMavericks(vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir, uint32_t slide, user_addr_t slide_start, user_addr_t slide_size);
	static kern_return_t vmSharedRegionMapFileLion     (vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir, shared_file_mapping_np *mapping_to_slide);
	static kern_return_t vmSharedRegionMapFileLeopard  (vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir);

	static int vmSharedRegionSlideBigSur   (uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, mach_vm_offset_t slid_mapping, memory_object_control_t sr_file_control, vm_prot_t prot);
	static int vmSharedRegionSlideMojave   (uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, mach_vm_offset_t slid_mapping, memory_object_control_t sr_file_control);
	static int vmSharedRegionSlideMavericks(uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, memory_object_control_t sr_file_control);
	static kern_return_t vmSharedRegionSlideLion(vm_offset_t vaddr, uint32_t pageIndex);

	static void execsigs(proc_t p, thread_t thread);
	static void taskSetMainThreadQos(task_t task, thread_t main_thread);

	/**
	 *  Applies page patches to the memory range
	 *
	 *  @param data_ptr  pages in kernel memory
	 *  @param data_size data size divisible by PAGE_SIZE
	 *  @param vp vnode that the pages belong to
	 *  @param page_offset offset
	 */
	void performPagePatchForSharedCacheWithoutLookupStorage(const void *data_ptr, size_t data_size, vnode_t vp, memory_object_offset_t page_offset);
	void performPagePatch(const void *data_ptr, size_t data_size, vnode_t vp, memory_object_offset_t page_offset);

	/**
	 * dyld shared cache map entry structure
	 */
	struct MapEntry {
		const char *filename;
		size_t length;
		vm_address_t startTEXT;
		vm_address_t endTEXT;
		vm_address_t startDATA;
		vm_address_t endDATA;
	};

	/**
	 *  Obtains __TEXT addresses from .map files
	 *
	 *  @param mapBuf     read .map file
	 *  @param mapSz      .map file size
	 *  @param mapEntries entries to look for
	 *  @param nentries   number of entries
	 *
	 *  @return number of entries found
	 */
	size_t mapAddresses(const char *mapBuf, MapEntry *mapEntries, size_t nentries);

	/**
	 *  Stored ASLR slide of dyld shared cache
	 */
	uint32_t storedSharedCacheSlide {0};

	/**
	 *  Set once shared cache slide is defined
	 */
	bool sharedCacheSlideStored {false};

	/**
	 *  Set on init to decide on whether to use __RESTRICT or patch dyld shared cache
	 */
	bool patchDyldSharedCache {false};

	/**
	 *  Kernel patcher instance
	 */
	KernelPatcher *patcher {nullptr};

	/**
	 *  Pending callback entry
	 */
	struct PendingUser {
		/**
		 *  Patch requested for path
		 */
		char path[MAXPATHLEN] {};

		/**
		 *  Patch requested for path
		 */
		uint32_t pathLen {0};
	};

	/**
	 *  Stored pending callback
	 */
	ThreadLocal<PendingUser *, 32> pending;

	/**
	 *  Current minimal proc name length
	 */
	uint32_t currentMinProcLength {0};

	/**
	 *  Provided binary modification list
	 */
	BinaryModInfo **binaryMod {nullptr};

	/**
	 *  Amount of provided binary modifications
	 */
	size_t binaryModSize {0};

	/**
	 *  Provided process list
	 */
	ProcInfo **procInfo {nullptr};

	/**
	 *  Amount of provided processes
	 */
	size_t procInfoSize {0};

	/**
	 *  Provided global callback for on proc invocation
	 */
	ppair<t_BinaryLoaded, void *> userCallback {};

	/**
	 *  Applies dyld shared cache patches
	 *
	 *  @param map     current process map
	 *  @param slide   ASLR offset
	 *  @param cpu     cache cpu type
	 *  @param restore true to rollback the changes
	 */
	void patchSharedCache(vm_map_t map, uint32_t slide, cpu_type_t cpu, bool applyChanges=true);

	/**
	 *  Structure holding userspace lookup patches for a single page
	 */
	struct LookupStorage {
		struct PatchRef {
			size_t i {0}; // the patch index

			// a single patch may occur more than once in a page
			evector<off_t> pageOffs;
			evector<off_t> segOffs;
			static PatchRef *create() {
				PatchRef *r = new PatchRef;
				if (!r) {
					DBGLOG("user", "create: r is NULL!");
				}
				return r;
			}
			static void deleter(PatchRef *r) {
				if (!r) {
					DBGLOG("user", "deleter: r is NULL!");
				}
				else {
					r->pageOffs.deinit();
					r->segOffs.deinit();
					delete r;
				}
			}
		};

		// these three fields indentify a single page
		const BinaryModInfo *mod {nullptr}; // the binary
		FileSegment section; // the section of the binary
		vm_address_t pageOff {0}; // the page of the section

		// multiple patches may be applied to the same page
		evector<PatchRef *, PatchRef::deleter> refs;

		// a copy of the page from the binary file
		Page *page {nullptr};

		static LookupStorage *create() {
			auto p = new LookupStorage;
			if (p) {
				p->page = Page::create();
				if (!p->page) {
					DBGLOG("user", "create: p->page is NULL!");
					deleter(p);
					p = nullptr;
				}
			}
			else {
				DBGLOG("user", "create: p is NULL!");
			}
			return p;
		}

		static void deleter(LookupStorage *p) {
			if (!p) {
				DBGLOG("user", "deleter: p is NULL!");
			}
			else {
				if (p->page) {
					Page::deleter(p->page);
					p->page = nullptr;
				}
				p->refs.deinit();
				delete p;
			}
		}
	};

	evector<LookupStorage *, LookupStorage::deleter> lookupStorage;

	struct Lookup {
		// how many values to store per lookup page
		static constexpr size_t matchNum {4};

		// offs[0] is a page offset where the values at that offset in all the lookup pages differ (are unique)
		// If no such offset exists, then offs[0] = 4088.
		// offs[1,2,3] are after offs[0] and wrap arround to 0 if the offset reaches 4096.
		uint32_t offs[matchNum] {};

		// true if the lookup pages have unique values for the first offset
		bool firstValueIsUnique {false};

		// the number of lookup pages; show match lookupStorage.size()
		size_t lookupCount {0};

		// two dimensional array stores 4 values per lookup page where the offset of each value is in the above offs array.
		uint64_t *c {nullptr};

		// set to true when lookups are ready to use
		bool ready {false};

		// allocate the two dimensional array
		void init(size_t initlookups) {
			lookupCount = initlookups;
			c = reinterpret_cast<uint64_t*>(kern_os_calloc(matchNum * lookupCount, sizeof(uint64_t)));
		}

		// get a value from the two dimensional array
		uint64_t get(size_t i, size_t page) {
			if (c) return c[i * lookupCount + page];
			return 0;
		}

		// set a value in the two dimensional array
		void set(size_t i, size_t page, uint64_t val) {
			if (c) c[i * lookupCount + page] = val;
		}

		// mark the lookups as ready
		void setReady() {
			ready = true;
		}

		// deallocate the two dimensional array
		void deinit() {
			if (c) kern_os_free(c);
		}
	};

	Lookup lookup;

	/**
	 *  Restrict 64-bit entry overlapping DYLD_SHARED_CACHE to enforce manual library loading
	 */
	segment_command_64 restrictSegment64 {
		LC_SEGMENT_64,
		sizeof(segment_command_64),
		"__RESTRICT",
		SHARED_REGION_BASE_X86_64,
		1, 0, 0, 0, 0, 0, 0
	};

	/**
	 *  Restrict 32-bit entry overlapping DYLD_SHARED_CACHE to enforce manual library loading
	 */
	segment_command restrictSegment32 {
		LC_SEGMENT,
		sizeof(segment_command),
		"__RESTRICT",
		SHARED_REGION_BASE_I386,
		1, 0, 0, 0, 0, 0, 0
	};

	/**
	 *  Temporary buffer for reading image data
	 */
	uint8_t tmpBufferData[PAGE_SIZE*3] {};

	/**
	 *  Kernel auth listener handle
	 */
	kauth_listener_t listener {nullptr};

	/**
	 *  Patcher status
	 */
	_Atomic(bool) activated = false;

	/**
	 *  Validation cookie
	 */
	void *cookie {nullptr};

	/**
	 *  Flags for codesign (PL) offset in struct proc. (uint32_t p_csflags)
	 */
	size_t csFlagsOffset {0};

	/**
	 *  Exec callback
	 *
	 *  @param credential kauth credential
	 *  @param idata      cookie
	 *  @param action     passed action, we only need KAUTH_FILEOP_EXEC
	 *  @param arg0       pointer to vnode (vnode *) for executable
	 *  @param arg1       pointer to path (char *) to executable
	 *
	 *  @return 0 to allow further execution
	 */
	static int execListener(kauth_cred_t /* credential */, void *idata, kauth_action_t action, uintptr_t /* arg0 */, uintptr_t arg1, uintptr_t, uintptr_t);

	/**
	 *  Unrestricted vm_protect, that takes care of Mojave codesign limitations for everyone's good.
	 *  See vm_protect description.
	 */
	kern_return_t vmProtect(vm_map_t map, vm_offset_t start, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

	/**
	 *  For vm_protect, to set max protection. See vm_map_check_protection. The set_maximum option of vm_protect cannot increase permissions. This function is used to get around that.
	 */
	bool vmSetMaxProtection(vm_map_t map, vm_map_offset_t start, vm_size_t size, vm_prot_t set_protection, vm_prot_t clear_protection = 0);

	/**
	 *  Callback invoked at process loading
	 *
	 *  @param path binary path
	 *  @param len  path length
	 */
	void onPath(const char *path, uint32_t len);

	/**
	 *  Reads files from BinaryModInfos and prepares lookupStorage
	 *
	 *  @return true on success
	 */
	bool loadFilesForPatching();

	/**
	 *  Reads dyld shared cache and obtains segment offsets
	 *
	 *  @return true on success
	 */
	bool loadDyldSharedCacheMapping();

	/**
	 *  Prepares quick page lookup based on lookupStorage values
	 *
	 *  @return true on success
	 */
	bool loadLookups();

	/**
	 *  Hooks memory access to get ready for patching
	 *
	 *  @return true on success
	 */
	bool hookMemoryAccess();

	/**
	 *  Peforms the actual binary patching
	 *
	 *  @param map  vm map
	 *  @param path binary path
	 *  @param len  path length
	 */
	void patchBinary(vm_map_t map, const char *path, uint32_t len);

	/**
	 *  DYLD shared cache map path for 10.10+ on Haswell
	 */
	static constexpr const char *SharedCacheMapHaswell {"/private/var/db/dyld/dyld_shared_cache_x86_64h.map"};

	/**
	 *  DYLD shared cache map path for all other systems and older CPUs
	 */
	static constexpr const char *SharedCacheMapLegacy {"/private/var/db/dyld/dyld_shared_cache_x86_64.map"};

	/**
	 *  DYLD shared cache path on Haswell+ before Big Sur
	 */
	static constexpr const char *sharedCacheHaswell {"/private/var/db/dyld/dyld_shared_cache_x86_64h"};

	/**
	 *  DYLD shared cache path on older systems before Big Sur
	 */
	static constexpr const char *sharedCacheLegacy {"/private/var/db/dyld/dyld_shared_cache_x86_64"};

	/**
	 *  DYLD shared cache map path on Haswell+ on Big Sur
	 */
	static constexpr const char *bigSurSharedCacheMapHaswell {"/System/Library/dyld/dyld_shared_cache_x86_64h.map"};

	/**
	 *  DYLD shared cache map path on older systems on Big Sur
	 */
	static constexpr const char *bigSurSharedCacheMapLegacy {"/System/Library/dyld/dyld_shared_cache_x86_64.map"};

	/**
	 *  DYLD shared cache path on Haswell+ on Big Sur
	 */
	static constexpr const char *bigSurSharedCacheHaswell {"/System/Library/dyld/dyld_shared_cache_x86_64h"};

	/**
	 *  DYLD shared cache path on older systems on Big Sur
	 */
	static constexpr const char *bigSurSharedCacheLegacy {"/System/Library/dyld/dyld_shared_cache_x86_64"};

	/**
	 *  DYLD shared cache map path on Haswell+ on Ventura
	 */
	static constexpr const char *venturaSharedCacheMapHaswell {"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64h.map"};

	/**
	 *  DYLD shared cache map path on older systems on Ventura
	 */
	static constexpr const char *venturaSharedCacheMapLegacy {"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64.map"};

	/**
	 *  DYLD shared cache path on Haswell+ on Ventura
	 */
	static constexpr const char *venturaSharedCacheHaswell {"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64h"};

	/**
	 *  DYLD shared cache path on older systems on Ventura
	 */
	static constexpr const char *venturaSharedCacheLegacy {"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64"};

};

#endif /* kern_user_hpp */
