//
//  kern_user.cpp
//  Lilu
//
//  Copyright © 2016-2017 vit9696. All rights reserved.
//

#include <Headers/kern_test.hpp>
#include <Headers/kern_config.hpp>
#include <Headers/kern_compat.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_cpu.hpp>
#include <Headers/kern_file.hpp>
#include <Headers/kern_devinfo.hpp>
#include <PrivateHeaders/kern_config.hpp>

#include <mach/vm_map.h>
#include <mach-o/fat.h>
#include <kern/task.h>
#include <kern/cs_blobs.h>
#include <sys/vm.h>

static UserPatcher *that {nullptr};

/*

[????] (struct) proc {
// (i386)
// 10.5.9, 10.6.8
*   0x0,[   8] (struct) (anonymous struct) p_list { le_next, le_prev }
+  0x08,[   4] (pid_t) p_pid
+  0x0c,[   4] (void *) task

// (x86_64)
// 10.6.8, 10.7.5, 10.8, 10.9, 10.10.5, 10.11.6, 10.12.6, 10.13.6
*   0x0,[  16] (struct) (anonymous struct) p_list { le_next, le_prev }
+  0x10,[   4] (pid_t) p_pid
+  0x18,[   8] (void *) task

// 10.14.6, 10.15.7, 11.6.4
*   0x0,[  16] (struct) (anonymous struct) p_list { le_next, le_prev }
+  0x10,[   8] (void *) task

// 12.2.1
*   0x0,[  16] (struct) (anonymous struct) p_list { le_next, le_prev }
+  0x10,[   8] (void *) task
+  0x18,[   8] (proc *) p_pptr
+  0x20,[   8] (proc_ro_t) p_proc_ro

// 13.0.0 b3
*   0x0,[  16] (struct) (anonymous struct) p_list { le_next, le_prev }
+  0x10,[   8] (proc *) p_pptr
+  0x18,[   8] (proc_ro_t) p_proc_ro

}

// 12.2.1, 13.0.0 b3
[ 120] (struct) proc_ro {
+   0x0,[   8] (proc *) pr_proc
+   0x8,[   8] (task *) pr_task
*  0x10,[  48] (union) (anonymous union)  {
    *  0x10,[  48] (struct) (anonymous struct) { same as proc_data }
    *  0x10,[  48] (struct) proc_ro_data proc_data {
        +  0x10,[   8] (uint64_t) p_uniqueid
        +  0x18,[   4] (int) p_idversion
        +  0x1c,[   4] (uint32_t) p_csflags
        +  0x20,[   8] (ucred *) p_ucred
        +  0x28,[   8] (uint8_t *) syscall_filter_mask
        *  0x30,[  12] (struct) proc_platform_ro_data p_platform_data {
            +  0x30,[   4] (uint32_t) p_platform
            +  0x34,[   4] (uint32_t) p_min_sdk
            +  0x38,[   4] (uint32_t) p_sdk
            }
        }
    }
*  0x40,[  56] (union) (anonymous union)  {
    *  0x40,[  56] (struct) (anonymous struct) { same as task_data }
    *  0x40,[  56] (struct) task_ro_data task_data {
        *  0x40,[  40] (struct) task_token_ro_data task_tokens {
            *  0x40,[   8] (struct) security_token_t sec_token {
                +  0x40,[   8] (unsigned int[2]) val
                }
            *  0x48,[  32] (struct) audit_token_t audit_token {
                +  0x48,[  32] (unsigned int[8]) val
                }
            }
        *  0x68,[  16] (struct) task_filter_ro_data task_filters {
            +  0x68,[   8] (uint8_t *) mach_trap_filter_mask
            +  0x70,[   8] (uint8_t *) mach_kobj_filter_mask
            }
        }
    }
}

*/

static void dump_csFlags(UInt32 flags) {
	DBGLOG("user", "p_csflags 0x%X %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", flags,
		(flags & CS_VALID                 ) ?                   "VALID," : "",
		(flags & CS_ADHOC                 ) ?                   "ADHOC," : "",
		(flags & CS_GET_TASK_ALLOW        ) ?          "GET_TASK_ALLOW," : "",
		(flags & CS_INSTALLER             ) ?               "INSTALLER," : "",
		(flags & CS_FORCED_LV             ) ?               "FORCED_LV," : "",
		(flags & CS_INVALID_ALLOWED       ) ?         "INVALID_ALLOWED," : "",
		(flags & CS_HARD                  ) ?                    "HARD," : "",
		(flags & CS_KILL                  ) ?                    "KILL," : "",
		(flags & CS_CHECK_EXPIRATION      ) ?        "CHECK_EXPIRATION," : "",
		(flags & CS_RESTRICT              ) ?                "RESTRICT," : "",
		(flags & CS_ENFORCEMENT           ) ?             "ENFORCEMENT," : "",
		(flags & CS_REQUIRE_LV            ) ?              "REQUIRE_LV," : "",
		(flags & CS_ENTITLEMENTS_VALIDATED) ?  "ENTITLEMENTS_VALIDATED," : "",
		(flags & CS_NVRAM_UNRESTRICTED    ) ?      "NVRAM_UNRESTRICTED," : "",
		(flags & CS_RUNTIME               ) ?                 "RUNTIME," : "",
		(flags & CS_LINKER_SIGNED         ) ?           "LINKER_SIGNED," : "",
		(flags & CS_EXEC_SET_HARD         ) ?           "EXEC_SET_HARD," : "",
		(flags & CS_EXEC_SET_KILL         ) ?           "EXEC_SET_KILL," : "",
		(flags & CS_EXEC_SET_ENFORCEMENT  ) ?    "EXEC_SET_ENFORCEMENT," : "",
		(flags & CS_EXEC_INHERIT_SIP      ) ?        "EXEC_INHERIT_SIP," : "",
		(flags & CS_KILLED                ) ?                  "KILLED," : "",
		(flags & CS_NO_UNTRUSTED_HELPERS  ) ?    "NO_UNTRUSTED_HELPERS," : "",
		(flags & CS_PLATFORM_BINARY       ) ?         "PLATFORM_BINARY," : "",
		(flags & CS_PLATFORM_PATH         ) ?           "PLATFORM_PATH," : "",
		(flags & CS_DEBUGGED              ) ?                "DEBUGGED," : "",
		(flags & CS_SIGNED                ) ?                  "SIGNED," : "",
		(flags & CS_DEV_CODE              ) ?                "DEV_CODE," : "",
		(flags & CS_DATAVAULT_CONTROLLER  ) ?    "DATAVAULT_CONTROLLER," : "",
		(flags & 0x000c00c0               ) ?                        "?" : ""
	);
}

kern_return_t UserPatcher::vmProtect(vm_map_t map, vm_offset_t start, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
	// On 10.14 XNU attempted to fix broken W^X and introduced several changes:
	// 1. vm_protect (vm_map_protect) got a call to cs_process_enforcement (formerly cs_enforcement), which aborts
	//    with a KERN_PROTECTION_FAILURE abort on failure. So far global codesign enforcement is not enabled,
	//    and it is enough to remove CS_ENFORCEMENT from each process specifically. A thing to consider in future
	//    macOS versions. Watch out for sysctl vm.cs_process_enforcement.
	// 2. More processes get CS_KILL in addition to CS_ENFORCEMENT, which does not let us easily lift CS_ENFORCEMENT
	//    during the vm_protect call, we also should remove CS_KILL from the process we patch. This slightly lowers
	//    the security, but only for the patched process, and in no worse way than 10.13 by default. Watch out for
	//    vm.cs_force_kill in the future.
	auto currproc = reinterpret_cast<void *>(current_proc());
	if ((new_protection & (VM_PROT_EXECUTE|VM_PROT_WRITE)) == (VM_PROT_EXECUTE|VM_PROT_WRITE) &&
		getKernelVersion() >= KernelVersion::Mojave && currproc != nullptr) {
		DBGLOG("user", "found request for W^X switch-off set_max:%d new_prot:%d", set_maximum, new_protection);

		// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_internal.h
		// struct proc layout usually changes with time, so we will calculate the offset based on partial layout:
		// uint32_t      p_csflags      flags for codesign (PL)
		// uint32_t      p_pcaction     action  for process control on starvation
		// uint8_t       p_uuid[16]     from LC_UUID load command
		// cpu_type_t    p_cputype
		// cpu_subtype_t p_cpusubtype

		uint32_t *flags = NULL;

		if (csFlagsOffset == 0) {
			switch (getKernelVersion()) {
				// These offsets can be found in the kernel dSYM files of each KDK (use dwarfdump)
				case KernelVersion::Tiger        :                      ; break; // 10.4 doesn't have code signing
				case KernelVersion::Leopard      : csFlagsOffset = 0x1dc; break; // ppc: 0x1c0
#if defined(__i386__)
				case KernelVersion::SnowLeopard  : csFlagsOffset = 0x1e0; break;
				case KernelVersion::Lion         : csFlagsOffset = 0x1f4; break;
#else
				case KernelVersion::SnowLeopard  : csFlagsOffset = 0x2fc; break;
				case KernelVersion::Lion         : csFlagsOffset = 0x308; break;
#endif
				case KernelVersion::MountainLion : csFlagsOffset = 0x308; break;
				case KernelVersion::Mavericks    : csFlagsOffset = 0x310; break;
				case KernelVersion::Yosemite     : csFlagsOffset = 0x310; break;
				case KernelVersion::ElCapitan    : csFlagsOffset = 0x320; break;
				case KernelVersion::Sierra       : csFlagsOffset = 0x320; break;
				case KernelVersion::HighSierra   : csFlagsOffset = 0x320; break;
				case KernelVersion::Mojave       : csFlagsOffset = 0x308; break;
				case KernelVersion::Catalina     : csFlagsOffset = 0x328; break;
				case KernelVersion::BigSur       : csFlagsOffset = 0x310; break;
				case KernelVersion::Monterey     :
				case KernelVersion::Ventura      :                      ; break;
			}
			if (getKernelVersion() >= KernelVersion::Yosemite && getKernelVersion() <= KernelVersion::BigSur) {
				// These versions have a p_cputype and p_cpusubtype at fixed offset from p_csflags
				size_t off;
				for (off = 0x300; off < 0x400; off += sizeof (uint32_t)) {
					auto csOff = (off > 0x300) ? off : csFlagsOffset; // test the default first
					auto csflags = getMember<uint32_t>(currproc, csOff);
					auto cpu     = getMember<uint32_t>(currproc, csOff + sizeof(uint32_t)*2 + sizeof(uint8_t[16]));
					auto subcpu  = getMember<uint32_t>(currproc, csOff + sizeof(uint32_t)*3 + sizeof(uint8_t[16])) & ~CPU_SUBTYPE_MASK;
					if ((cpu == CPU_TYPE_X86_64 || cpu == CPU_TYPE_I386) &&
						(subcpu == CPU_SUBTYPE_X86_64_ALL || subcpu == CPU_SUBTYPE_X86_64_H) &&
						!(csflags & CS_KILLED)
					) {
						if (csFlagsOffset == csOff) {
							DBGLOG("user", "found p_csflags at default offset %X", (uint32_t)csFlagsOffset);
						}
						else {
							DBGLOG("user", "found p_csflags at offset %X which is not the default offset %X", (uint32_t)csOff, (uint32_t)csFlagsOffset);
							csFlagsOffset = csOff;
						}
						break;
					}
					else if (off == 0x300) {
						SYSLOG("user", "default p_csflags has unexpected value (%X), cpu type (%X), or cpu sub type (%X)", csflags, cpu, subcpu);
						csFlagsOffset = 0;
					}
				}
				if (off >= 0x400) {
					SYSLOG("user", "did not find p_csflags, cannot check or change p_csflags");
					csFlagsOffset = 0;
				}
			}
			else if (getKernelVersion() >= KernelVersion::Monterey) {
				void *proc_ro = getMember<void *>(currproc, (getKernelVersion() >= KernelVersion::Ventura) ? 0x18 : 0x20);
				void *proc = getMember<void *>(proc_ro, 0x00);
				if (proc == currproc) {
					flags = &getMember<uint32_t>(proc_ro, 0x1c);
					if (!(*flags & CS_KILLED)) {
						DBGLOG("user", "using p_csflags proc 0x" PRIKADDR " -> proc_ro 0x" PRIKADDR " for Monterey", CASTKADDR((uint64_t)proc), CASTKADDR((uint64_t)proc_ro));
						kern_return_t r = vm_protect(kernel_map, (vm_address_t)flags, sizeof(uint32_t), FALSE, VM_PROT_READ|VM_PROT_WRITE);

						if (r != KERN_SUCCESS) {
							SYSLOG("user", "W removal for proc_ro failed with %d", r); // KERN_PROTECTION_FAILURE

							vmSetMaxProtection(kernel_map, (vm_address_t)flags, sizeof(uint32_t), VM_PROT_WRITE);
							r = vm_protect(kernel_map, (vm_address_t)flags, sizeof(uint32_t), FALSE, VM_PROT_READ|VM_PROT_WRITE);

							if (r == KERN_SUCCESS) {
								SYSLOG("user", "W^X removal for proc_ro succeeded after changing max_protection");
							}
							else {
								SYSLOG("user", "W^X removal also failed after changing max_protection");
#if 0 // test_* is currently only for BigSur 11.6.4
								r = test_vm_protect(kernel_map, (vm_address_t)flags, sizeof(uint32_t), FALSE, VM_PROT_READ|VM_PROT_WRITE);
								SYSLOG("user", "retry with test_vm_protect result: %d", r);
#endif
							}
						}

						if (r != KERN_SUCCESS) {
							flags = NULL;
						}
					}
					else {
						SYSLOG("user", "p_csflags has CS_KILLED");
						flags = NULL;
					}
				}
				else {
					SYSLOG("user", "proc_ro for Monterey doesn't point to proc; cannot check or change p_csflags");
				}
			}
			else if (csFlagsOffset) {
				DBGLOG("user", "using p_csflags at default offset %X", (uint32_t)csFlagsOffset);
			}
			else {
				DBGLOG("user", "no p_csflags; cannot check or change p_csflags");
			}
		}

		if (csFlagsOffset && !flags) {
			flags = &getMember<uint32_t>(currproc, csFlagsOffset);
		}

		if (flags) {
			dump_csFlags(*flags);

			if (*flags & CS_ENFORCEMENT) {
				DBGLOG("user", "W^X is enforced, disabling");
				*flags &= ~(CS_KILL|CS_HARD|CS_ENFORCEMENT); // CS_NO_UNTRUSTED_HELPERS
				// Changing CS_HARD, CS_DEBUGGED, and vm_map switch protection is not required, yet may avoid issues
				// in the future.
				*flags |= CS_DEBUGGED;
				dump_csFlags(*flags);
				if (that->org_vm_map_switch_protect) {
					DBGLOG("user", "calling org_vm_map_switch_protect");
					size_t taskOffset =
						getKernelVersion() >= KernelVersion::Mojave      ? 0x10 :
#if defined(__i386__)
#else
						getKernelVersion() >= KernelVersion::SnowLeopard ? 0x18 :
#endif
						0x0c;

					that->org_vm_map_switch_protect(that->org_get_task_map(getMember<task_t>(currproc, taskOffset)), false);
				}
				else {
					DBGLOG("user", "not calling org_vm_map_switch_protect");
				}
			}
		}

		kern_return_t r;
		r = vm_protect(map, start, size, set_maximum, new_protection);
		if (r != KERN_SUCCESS) {
			SYSLOG("user", "W^X removal failed with %d", r); // KERN_PROTECTION_FAILURE

			vmSetMaxProtection(map, start, size, new_protection);
			r = vm_protect(map, start, size, set_maximum, new_protection);

			if (r == KERN_SUCCESS) {
				SYSLOG("user", "W^X removal succeeded after changing max_protection");
			}
			else {
				SYSLOG("user", "W^X removal also failed after changing max_protection");
#if 0 // test_* is currently only for BigSur 11.6.4
				r = test_vm_protect(map, start, size, set_maximum, new_protection);
				SYSLOG("user", "retry with test_vm_protect result: %d", r);

				if (r != KERN_SUCCESS && !set_maximum) {
					// let's try setting the maximum
					kern_return_t r2;
					r2 = vm_protect(map, start, size, true, new_protection);
					SYSLOG("user", "set max result: %d", r2);
					if (r2 != KERN_SUCCESS) {
						r2 = test_vm_protect(map, start, size, true, new_protection);
						SYSLOG("user", "set max test result: %d", r2);
					}

					if (r2 == KERN_SUCCESS) {
						r = vm_protect(map, start, size, set_maximum, new_protection);
						SYSLOG("user", "set prot after setting max result: %d", r);
					}
				}

				if (r != KERN_SUCCESS && ! (new_protection & VM_PROT_COPY)) {
					r = vm_protect(map, start, size, true, new_protection | VM_PROT_COPY);
					SYSLOG("user", "set VM_PROT_COPY result: %d", r);
					if (r != KERN_SUCCESS) {
						r = test_vm_protect(map, start, size, true, new_protection | VM_PROT_COPY);
						SYSLOG("user", "test set VM_PROT_COPY result: %d", r);
					}
				}
#endif
			}
		}
		// Initially thought that we could return CS_ENFORCEMENT, yet this causes certain binaries to crash,
		// like WindowServer patched by -cdfon.
		return r;
	}

	// Forward to the original proc routine
	return vm_protect(map, start, size, set_maximum, new_protection);
}

int UserPatcher::execListener(kauth_cred_t, void *idata, kauth_action_t action, uintptr_t, uintptr_t arg1, uintptr_t, uintptr_t) {
	// Make sure this is ours
	if (atomic_load_explicit(&that->activated, memory_order_relaxed) &&
		idata == &that->cookie && action == KAUTH_FILEOP_EXEC && arg1) {
		const char *path = reinterpret_cast<const char *>(arg1);
		that->onPath(path, static_cast<uint32_t>(strlen(path)));
	}

	return 0;
}

bool UserPatcher::init(KernelPatcher &kernelPatcher, bool preferSlowMode) {
	DBGLOG("user", "[ UserPatcher::init preferSlowMode:%d", preferSlowMode);
	if (ADDPR(config).isUserDisabled) {
		SYSLOG_COND(ADDPR(debugEnabled), "user", "disabling user patcher on request!");
		DBGLOG("user", "] UserPatcher::init true");
		return true;
	}

	that = this;
	patchDyldSharedCache = !preferSlowMode;
	patcher = &kernelPatcher;
	hookMemoryAccess(); // hook early
	get_kernel_externals(*patcher);

	pending.init();

	listener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, execListener, &cookie);

	if (!listener) {
		SYSLOG("user", "failed to register a listener");
		DBGLOG("user", "] UserPatcher::init false");
		return false;
	}

	DBGLOG("user", "] UserPatcher::init true");
	return true;
}

bool UserPatcher::registerPatches(ProcInfo **procs, size_t procNum, BinaryModInfo **mods, size_t modNum, t_BinaryLoaded callback, void *user) {
	// Silently return if disabled
	DBGLOG("user", "[ UserPatcher::registerPatches");
	if (ADDPR(config).isUserDisabled) {
		DBGLOG("user", "] UserPatcher::registerPatches true");
		return true;
	}

	procInfo = procs;
	procInfoSize = procNum;
	binaryMod = mods;
	binaryModSize = modNum;
	userCallback.first = callback;
	userCallback.second = user;

	if (procNum) {
		currentMinProcLength = procs[0]->len;
		for (size_t i = 1; i < procNum; i++) {
			if (procs[i]->len < currentMinProcLength)
				currentMinProcLength = procs[i]->len;
		}
	}

	bool result = loadFilesForPatching() && (!patchDyldSharedCache || loadDyldSharedCacheMapping()) && loadLookups();
	DBGLOG("user", "] UserPatcher::registerPatches %s", result ? "true" : "false");
	return result;
}

void UserPatcher::deinit() {
	DBGLOG("user", "[ UserPatcher::deinit");
	// Silently return if disabled
	if (ADDPR(config).isUserDisabled)
		return;

	if (listener) {
		kauth_unlisten_scope(listener);
		listener = nullptr;
	}

	pending.deinit();
	lookupStorage.deinit();
	for (size_t i = 0; i < Lookup::matchNum; i++)
		lookup.c[i].deinit();
	DBGLOG("user", "] UserPatcher::deinit");
}

static int counter_cs_validate_page = 0;
static int counter_cs_validate_page_true = 0;
static int counterPagePatch = 0;
static int counterPagePatchWithLookupStorageSize = 0;
static int counterPagePatchWithLookupStorageMatch = 0;
static int counterPagePatchWithLookupStorageMaybe = 0;
static int counterPagePatchWithLookupStorageDefinitely = 0;
static int counterPagePatchWithLookupStoragePageMatched = 0;
static int counterPagePatchWithLookupStorageReplaceSuccess = 0;
static int counterPagePatchWithoutLookupStorageBigSur = 0;
static int counterPagePatchWithoutLookupStorageGetPath = 0;
static int counterPagePatchWithoutLookupStoragePathIsSharedCache = 0;
static int counterPagePatchWithoutLookupStorageModSize = 0;
static int counterPagePatchWithoutLookupStorageMatchPath = 0;
static int counterPagePatchWithoutLookupStoragePatches = 0;
static int counterPagePatchWithoutLookupStoragePatchesEnabled = 0;
static int counterPagePatchWithoutLookupStorageSearchReplaceSuccess = 0;
static int counter_vm_page_validate_cs_mapped = 0;
static int counter_vm_page_validate_cs_mapped_slow = 0;

void UserPatcher::dumpCounters() {
#define dumponecounter(a) DBGLOG("user", #a " = %d", a);
	dumponecounter(counter_vm_page_validate_cs_mapped)
	dumponecounter(counter_vm_page_validate_cs_mapped_slow)
	dumponecounter(counter_cs_validate_page)
	dumponecounter(counter_cs_validate_page_true)
	dumponecounter(counterPagePatch)
	dumponecounter(counterPagePatchWithLookupStorageSize)
	dumponecounter(counterPagePatchWithLookupStorageMatch)
	dumponecounter(counterPagePatchWithLookupStorageMaybe)
	dumponecounter(counterPagePatchWithLookupStorageDefinitely)
	dumponecounter(counterPagePatchWithLookupStoragePageMatched)
	dumponecounter(counterPagePatchWithLookupStorageReplaceSuccess)
	dumponecounter(counterPagePatchWithoutLookupStorageBigSur)
	dumponecounter(counterPagePatchWithoutLookupStorageGetPath)
	dumponecounter(counterPagePatchWithoutLookupStoragePathIsSharedCache)
	dumponecounter(counterPagePatchWithoutLookupStorageModSize)
	dumponecounter(counterPagePatchWithoutLookupStorageMatchPath)
	dumponecounter(counterPagePatchWithoutLookupStoragePatches)
	dumponecounter(counterPagePatchWithoutLookupStoragePatchesEnabled)
	dumponecounter(counterPagePatchWithoutLookupStorageSearchReplaceSuccess)
}

#define FRAMEWORKSPATH "/System/Library/Frameworks/"

void UserPatcher::performPagePatchForSharedCacheWithoutLookupStorage(const void *data_ptr, size_t data_size, vnode_t vp, memory_object_offset_t page_offset) {
	if (binaryModSize && vp && getKernelVersion() >= KernelVersion::BigSur) {
		// BigSur has shared dyld cache without framework binaries.
		// lookupStorage is not populated for patches without binaries.
		// Therefore, we need to bypass lookupStorage to perform patches on shared dyld cache frameworks.
		
		counterPagePatchWithoutLookupStorageBigSur++;

		char path[PATH_MAX];
		int pathlen = PATH_MAX;
		if (vn_getpath(vp, path, &pathlen) == 0) {
			counterPagePatchWithoutLookupStorageGetPath++;
			bool isSharedCache = UserPatcher::matchSharedCachePath(path);
			if (isSharedCache) {
				counterPagePatchWithoutLookupStoragePathIsSharedCache++;
				for (size_t i = 0; i < binaryModSize; i++) {
					counterPagePatchWithoutLookupStorageModSize++;
					if (
						/* !strcmp(binaryMod[i]->path, path) || */
						(
							(
								// startTEXT is only set for shared dyld cache frameworks (but only if the map file is successfully read.
								// For Ventura, the map file is on Preboot but it's not mounted at /Volumes/Preboot/System/Library/ when Lilu tries to read it?
								binaryMod[i]->startTEXT
								||
								(getKernelVersion() >= KernelVersion::Ventura && !strncmp(binaryMod[i]->path, FRAMEWORKSPATH, sizeof(FRAMEWORKSPATH) - 1))
							)
						)
					) {
						// For patches that are not shared dyld cache, use lookupStorage method below.
						// TO DO: One day we'll want to be able to create lookupStorage for patches of shared dyld cache frameworks, but not today.
						// TO DO: check process info - for example, don't do patch on CoreDisplay framework unless the process is WindowServer
						counterPagePatchWithoutLookupStorageMatchPath++;
						for (size_t p = 0; p < binaryMod[i]->count; p++) {
							counterPagePatchWithoutLookupStoragePatches++;
							if (binaryMod[i]->patches[p].section != ProcInfo::SectionDisabled) {
								counterPagePatchWithoutLookupStoragePatchesEnabled++;
								// TO DO: check cpu, flags, skip, count, segment
								if (UNLIKELY(KernelPatcher::findAndReplace(const_cast<void *>(data_ptr), data_size, binaryMod[i]->patches[p].find, binaryMod[i]->patches[p].size, binaryMod[i]->patches[p].replace, binaryMod[i]->patches[p].size))) {
									counterPagePatchWithoutLookupStorageSearchReplaceSuccess++;
									DBGLOG("user", "performPagePatch page:%llx page_offset:%llx mod:%d patch:%d size:%d path:%s modpath:%s", (uint64_t)data_ptr, (uint64_t)page_offset, (int)i, (int)p, (int)binaryMod[i]->patches[p].size, path, binaryMod[i]->path);
								}
							}
						} // for patch
					} // if name match
				} // for binaryMod
			} // if (isSharedCache)
		} // if vn_getpath
	} // if BigSur
}

void UserPatcher::performPagePatch(const void *data_ptr, size_t data_size, vnode_t vp, memory_object_offset_t page_offset) {
	counterPagePatch++;
	bool foundpatch = false;
	for (size_t data_off = 0; data_off < data_size; data_off += PAGE_SIZE) {
		size_t sz = that->lookupStorage.size();
		size_t maybe = 0;
		auto ptr = static_cast<const uint8_t *>(data_ptr) + data_off;

		if (sz > 0) {
			counterPagePatchWithLookupStorageSize++;
			for (size_t i = 0; i < Lookup::matchNum && maybe != sz; i++) {
				counterPagePatchWithLookupStorageMatch++;
				uint64_t value = *reinterpret_cast<const uint64_t *>(ptr + lookup.offs[i]);

				if (i == 0) {
					for (maybe = 0; maybe < sz; maybe++) {
						counterPagePatchWithLookupStorageMaybe++;
						if (lookup.c[i][maybe] == value) {
							// We have a possible match
							DBGLOG("user", "found a possible match for %lu of %016llX", i, OSSwapHostToBigInt64(value));
							break;
						}
					}
				} else {
					if (lookup.c[i][maybe] != value) {
						// We failed
						DBGLOG("user", "failure not matching %lu of %016llX to expected %016llX", i, OSSwapHostToBigInt64(value), OSSwapHostToBigInt64(lookup.c[i][maybe]));
						maybe = sz;
					} else {
						DBGLOG("user", "found a possible match for %lu of %016llX", i, OSSwapHostToBigInt64(value));
					}
				}

			}

			if (maybe < sz) {
				counterPagePatchWithLookupStorageDefinitely++;
				auto &storage = that->lookupStorage[maybe];

				// That's a patch
				if (!memcmp(storage->page->p, ptr, PAGE_SIZE)) {
					counterPagePatchWithLookupStoragePageMatched++;
					for (size_t r = 0, rsz = storage->refs.size(); r < rsz; r++) {
						// Apply the patches
						auto &ref = storage->refs[r];
						auto &rpatch = storage->mod->patches[ref->i];
						sz = ref->pageOffs.size();

						// Skip patches that are meant to apply only to select processes.
						if (rpatch.flags & LocalOnly) {
							continue;
						}

						DBGLOG("user", "found what we are looking for %02X %02X %02X %02X %02X %02X %02X %02X", rpatch.find[0],
								rpatch.size > 1 ? rpatch.find[1] : 0xff,
								rpatch.size > 2 ? rpatch.find[2] : 0xff,
								rpatch.size > 3 ? rpatch.find[3] : 0xff,
								rpatch.size > 4 ? rpatch.find[4] : 0xff,
								rpatch.size > 5 ? rpatch.find[5] : 0xff,
								rpatch.size > 6 ? rpatch.find[6] : 0xff,
								rpatch.size > 7 ? rpatch.find[7] : 0xff
						);

						if (sz > 0 && MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock) == KERN_SUCCESS) {
							DBGLOG("user", "obtained write permssions");

							for (size_t i = 0; i < sz; i++) {
								uint8_t *patch = const_cast<uint8_t *>(ptr + ref->pageOffs[i]);

								switch(rpatch.size) {
									case sizeof(uint8_t):
										*const_cast<uint8_t *>(patch) = *rpatch.replace;
										break;
									case sizeof(uint16_t):
										*reinterpret_cast<uint16_t *>(patch) = *reinterpret_cast<const uint16_t *>(rpatch.replace);
										break;
									case sizeof(uint32_t):
										*reinterpret_cast<uint32_t *>(patch) = *reinterpret_cast<const uint32_t *>(rpatch.replace);
										break;
									case sizeof(uint64_t):
										*reinterpret_cast<uint64_t *>(patch) = *reinterpret_cast<const uint64_t *>(rpatch.replace);
										break;
									default:
										DBGLOG("user", "memcpy dst:0x%llX size:%d", (uint64_t)patch, (int)rpatch.size);
										lilu_os_memcpy(patch, rpatch.replace, rpatch.size);
								}
								
								char path[PATH_MAX];
								int pathlen = PATH_MAX;
								if (vn_getpath(vp, path, &pathlen) != 0) path[0] = '\0';
								DBGLOG("user", "performPagePatch page:%llx page_offset:%llx patch:%d size:%d path:%s modpath:%s", (uint64_t)data_ptr, (uint64_t)page_offset, (int)ref->i, (int)rpatch.size, path, storage->mod->path);
								foundpatch = true;
								counterPagePatchWithLookupStorageReplaceSuccess++;
							}

							if (MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock) == KERN_SUCCESS) {
								DBGLOG("user", "restored write permssions");
							}
						} else {
							SYSLOG("user", "failed to obtain write permssions for %lu", sz);
						}
					}
				} else {
					DBGLOG("user", "failed to match a complete page with %lu", maybe);
				}
			}
		}
	}
	if (!foundpatch) {
		performPagePatchForSharedCacheWithoutLookupStorage(data_ptr, data_size, vp, page_offset);
	}
}

void UserPatcher::codeSignValidatePageWrapperBigSur(vnode_t vp, memory_object_t pager, memory_object_offset_t page_offset, const void *data, int *validated_p, int *tainted_p, int *nx_p) {
	counter_cs_validate_page++;
	FunctionCast(codeSignValidatePageWrapperBigSur, that->orgCodeSignValidatePageWrapper)(vp, pager, page_offset, data, validated_p, tainted_p, nx_p);
	that->performPagePatch(data, PAGE_SIZE, vp, page_offset);
}

boolean_t UserPatcher::codeSignValidatePageWrapperYosemite(void *blobs, memory_object_t pager, memory_object_offset_t page_offset, const void *data, unsigned *tainted) {
	counter_cs_validate_page++;
	boolean_t res = FunctionCast(codeSignValidatePageWrapperYosemite, that->orgCodeSignValidatePageWrapper)(blobs, pager, page_offset, data, tainted);
	if (res) counter_cs_validate_page_true++;
	if (res) that->performPagePatch(data, PAGE_SIZE, NULL, page_offset);
	return res;
}

boolean_t UserPatcher::codeSignValidatePageWrapperMountainLion(void *blobs, memory_object_t pager, memory_object_offset_t page_offset, const void *data, boolean_t *tainted) {
	counter_cs_validate_page++;
	boolean_t res = FunctionCast(codeSignValidatePageWrapperMountainLion, that->orgCodeSignValidatePageWrapper)(blobs, pager, page_offset, data, tainted);
	if (res) counter_cs_validate_page_true++;
	if (res) that->performPagePatch(data, PAGE_SIZE, NULL, page_offset);
	return res;
}

boolean_t UserPatcher::codeSignValidatePageWrapperLeopard(void *blobs, memory_object_offset_t page_offset, const void *data, boolean_t *tainted) {
	counter_cs_validate_page++;
	boolean_t res = FunctionCast(codeSignValidatePageWrapperLeopard, that->orgCodeSignValidatePageWrapper)(blobs, page_offset, data, tainted);
	if (res) counter_cs_validate_page_true++;
	if (res) that->performPagePatch(data, PAGE_SIZE, NULL, page_offset);
	return res;
}

boolean_t UserPatcher::codeSignValidateRangeWrapper(vnode_t vp, memory_object_t pager, memory_object_offset_t range_offset, const void *data, memory_object_size_t data_size, unsigned *tainted) {
	counter_cs_validate_page++;
	boolean_t res = FunctionCast(codeSignValidateRangeWrapper, that->orgCodeSignValidateRangeWrapper)(vp, pager, range_offset, data, data_size, tainted);
	if (res) counter_cs_validate_page_true++;
	if (res) that->performPagePatch(data, (size_t)data_size, vp, range_offset);
	return res;
}

void UserPatcher::wrap_vm_page_validate_cs_mapped(vm_page_t page, vm_map_size_t fault_page_size, vm_map_offset_t fault_phys_offset, const void *kaddr) {
	counter_vm_page_validate_cs_mapped++;
	FunctionCast(wrap_vm_page_validate_cs_mapped, that->org_vm_page_validate_cs_mapped)(page, fault_page_size, fault_phys_offset, kaddr);
}

void UserPatcher::wrap_vm_page_validate_cs_mapped_slow(vm_page_t page, const void *kaddr) {
	counter_vm_page_validate_cs_mapped_slow++;
	FunctionCast(wrap_vm_page_validate_cs_mapped_slow, that->org_vm_page_validate_cs_mapped_slow)(page, kaddr);
}

void UserPatcher::onPath(const char *path, uint32_t len) {
	static unsigned int NumPaths = 0;
	NumPaths++;
	if (len >= currentMinProcLength) {
		for (uint32_t i = 0; i < procInfoSize; i++) {
			auto p = procInfo[i];
			if (len >= p->len) {
				auto match = p->flags & ProcInfo::MatchMask;
				if ((match == ProcInfo::MatchExact && len == p->len && !strncmp(p->path, path, len)) ||
					(match == ProcInfo::MatchPrefix && !strncmp(p->path, path, p->len)) ||
					(match == ProcInfo::MatchSuffix && !strncmp(p->path, path + (len - p->len), p->len+1)) ||
					(match == ProcInfo::MatchAny && strstr(path, p->path))) {
					DBGLOG("user", "[ UserPatcher::onPath %d; info #%d", NumPaths, i);
					DBGLOG("user", "caught %s performing injection", path);
					if (orgTaskSetMainThreadQos) {
						DBGLOG("user", "requesting delayed patch " PRIKADDR, CASTKADDR(current_thread()));

						auto previous = pending.get();
						if (previous) {
							// This is possible when execution does not happen, and thus we do not remove the patch.
							DBGLOG("user", "found dangling user patch request");
							PANIC_COND(!pending.erase(), "user", "failed to remove dangling user patch");
							delete *previous;
						}

						auto pend = new PendingUser;
						if (pend != nullptr) {
							lilu_strlcpy(pend->path, path, MAXPATHLEN);
							pend->pathLen = len;
							// This should not happen after we added task_set_main_thread_qos hook, which gets always called
							// unlike proc_exec_switch_task. Increasing pending count to 32 should accomodate for most CPUs.
							// Still do not cause a kernel panic but rather just report this.
							if (!pending.set(pend)) {
								SYSLOG("user", "failed to set user patch request, report this!!!");
								delete pend;
							}
						} else {
							SYSLOG("user", "failed to allocate pending user callback");
						}

					} else {
						patchBinary(org_current_map(), path, len);
					}

					DBGLOG("user", "] UserPatcher::onPath");
					return;
				}
			}
		}
	}
}

void UserPatcher::patchBinary(vm_map_t map, const char *path, uint32_t len) {
	DBGLOG("user", "[ UserPatcher::patchBinary path:%s", path);
	if (patchDyldSharedCache && sharedCacheSlideStored) {
		// note: patchSharedCache doesn't do anything if lookupStorage is empty or if all the lookupStorage items are not for shared cache binaries
		patchSharedCache(map, storedSharedCacheSlide, CPU_TYPE_X86_64);
	}
	if (getKernelVersion() >= KernelVersion::Ventura) {
		SYSLOG("user", "Not going to try restrict method for Ventura");
		// because we might get a panic when we try to change the permission of a single page:
		// vm_map_clip(0x*): Attempting to clip an atomic VM map entry 0x* [0x*:0x*] at 0x* @vm_map.c:5514
	}
	else if (!patchDyldSharedCache || !sharedCacheSlideStored/* || !lookupStorage.size() */) {
		if (patchDyldSharedCache) {
			SYSLOG("user", "%s%sfallback to restrict",
				sharedCacheSlideStored ? "" : "no slide present, ",
				lookupStorage.size() ? "" : "no lookupStorage, do not ");
			if (lookupStorage.size()) {
				injectRestrict(map);
			}
		}
		else {
			SYSLOG("user", "fallback to restrict");
			injectRestrict(map);
		}
	}
	userCallback.first(userCallback.second, *this, map, path, len);
	DBGLOG("user", "] UserPatcher::patchBinary path:%s", path);
}

bool UserPatcher::getTaskHeader(vm_map_t taskPort, mach_header_64 &header) {
	auto baseAddr = org_get_map_min(taskPort);
	DBGLOG("user", "getTaskHeader map min is " PRIKADDR, CASTKADDR(baseAddr));

	kern_return_t err = org_vm_map_read_user(taskPort, baseAddr, &header, sizeof(mach_header_64));
	if (err == KERN_SUCCESS)
		return true;

	SYSLOG("user", "failed to read image header %d", err);
	return false;
}

bool UserPatcher::injectRestrict(vm_map_t taskPort) {
	DBGLOG("user", "[ UserPatcher::injectRestrict");
	// Get task's mach-o header and determine its cpu type
	auto baseAddr = org_get_map_min(taskPort);

	DBGLOG("user", "injectRestrict map min is " PRIKADDR, CASTKADDR(baseAddr));

	auto &tmpHeader = *reinterpret_cast<mach_header_64 *>(tmpBufferData);
	kern_return_t err = org_vm_map_read_user(taskPort, baseAddr, &tmpHeader, sizeof(mach_header_64));

	if (err == KERN_SUCCESS){
		if (tmpHeader.magic == MH_MAGIC_64 || tmpHeader.magic == MH_MAGIC) {
			size_t hdrSize = tmpHeader.magic == MH_MAGIC ? sizeof(mach_header) : sizeof(mach_header_64);
			size_t restrSize = tmpHeader.magic == MH_MAGIC ? sizeof(restrictSegment32) : sizeof(restrictSegment64);

			struct {
				vm_map_offset_t off;
				vm_prot_t val;
			} prots[3] {};
			size_t orgBound = hdrSize + tmpHeader.sizeofcmds;
			size_t newBound = orgBound + restrSize;

			prots[0].off = baseAddr;
			prots[0].val = getPageProtection(taskPort, prots[0].off);

			if (orgBound + restrSize > PAGE_SIZE){
				prots[1].off = baseAddr + orgBound - orgBound % PAGE_SIZE;
				prots[1].val = getPageProtection(taskPort, prots[1].off);
				if (baseAddr + newBound  > prots[1].off + PAGE_SIZE){
					prots[2].off = prots[1].off + PAGE_SIZE;
					prots[2].val = getPageProtection(taskPort, prots[2].off);
				}
			}

			//TODO: Should implement a check whether the space is available to ensure that we do not break processes.

			// Note, that we don't restore memory protection if we fail somewhere (no need to push something non-critical)
			// Enable writing for the calculated regions
			for (size_t i = 0; i < 3; i++) {
				if (prots[i].off && !(prots[i].val & VM_PROT_WRITE)) {
					DBGLOG("user", "changing memory protection #%lu to %d", i, prots[i].val|VM_PROT_WRITE);
					auto res = vmProtect(taskPort, (vm_offset_t)prots[i].off, PAGE_SIZE, FALSE, prots[i].val|VM_PROT_WRITE);
					if (res != KERN_SUCCESS) {
						SYSLOG("user", "failed to change memory protection (%lu, %d)", i, res);
						DBGLOG("user", "] UserPatcher::injectRestrict true");
						return true;
					}
				}
			}

			vm_map_address_t ncmdsAddr = baseAddr + offsetof(mach_header, ncmds);
			vm_map_address_t newCmdAddr = baseAddr + hdrSize + tmpHeader.sizeofcmds;

			uint64_t orgCombVal = (static_cast<uint64_t>(tmpHeader.sizeofcmds) << 32) | tmpHeader.ncmds;
			uint64_t newCombVal = (static_cast<uint64_t>(tmpHeader.sizeofcmds + restrSize) << 32) | (tmpHeader.ncmds + 1);

			// Write new number and size of commands
			DBGLOG("user", "write new number and size of commands");
			auto res = org_vm_map_write_user(taskPort, &newCombVal, ncmdsAddr, sizeof(uint64_t));
			if (res != KERN_SUCCESS) {
				SYSLOG("user", "failed to change mach header (%d)", res);
#if 0 // test_* is currently only for BigSur 11.6.4
				kern_return_t r2 = test_vm_map_write_user(taskPort, &newCombVal, ncmdsAddr, sizeof(uint64_t));
				DBGLOG("user", "test_vm_map_write_user result:%d", r2);
				if (r2 != KERN_SUCCESS) {

				}
#endif
				DBGLOG("user", "] UserPatcher::injectRestrict true");
				return true;
			}

			DBGLOG("user", "write the load command");
			// Write the load command
			auto restrSegment = tmpHeader.magic == MH_MAGIC ? static_cast<void *>(&restrictSegment32) : static_cast<void *>(&restrictSegment64);
			res = org_vm_map_write_user(taskPort, restrSegment, newCmdAddr, restrSize);
			if (res != KERN_SUCCESS) {
				SYSLOG("user", "failed to add dylib load command (%d), reverting...", res);
				res = org_vm_map_write_user(taskPort, &orgCombVal, ncmdsAddr, sizeof(uint64_t));
				if (res != KERN_SUCCESS) {
					SYSLOG("user", "failed to restore mach header (%d), this process will crash...", res);
				}
				DBGLOG("user", "] UserPatcher::injectRestrict true");
				return true;
			}

			DBGLOG("user", "restore protection flags");
			// Restore protection flags
			for (size_t i = 0; i < 3; i++) {
				if (prots[i].off && !(prots[i].val & VM_PROT_WRITE)) {
					res = vmProtect(taskPort, (vm_offset_t)prots[i].off, PAGE_SIZE, FALSE, prots[i].val);
					if (res != KERN_SUCCESS) {
						SYSLOG("user", "failed to restore memory protection (%lu, %d)", i, res);
						DBGLOG("user", "] UserPatcher::injectRestrict true");
						return true;
					}
				}
			}

		} else {
			SYSLOG("user", "unknown header magic %X", tmpHeader.magic);
		}
	} else {
		SYSLOG("user", "could not read target mach-o header (error %d)", err);
		DBGLOG("user", "] UserPatcher::injectRestrict false");
		return false;
	}

	DBGLOG("user", "] UserPatcher::injectRestrict true");
	return true;
}

vm_address_t UserPatcher::injectSegment(vm_map_t taskPort, vm_address_t addr, uint8_t *payload, size_t size, vm_prot_t prot) {
	auto ret = vm_allocate(taskPort, &addr, size, VM_FLAGS_FIXED);
	if (ret != KERN_SUCCESS) {
		SYSLOG("user", "vm_allocate fail %d", ret);
		return 0;
	}

	auto writeProt = prot|VM_PROT_READ|VM_PROT_WRITE;
	ret = vmProtect(taskPort, addr, size, FALSE, writeProt);
	if (ret == KERN_SUCCESS) {
		ret = org_vm_map_write_user(taskPort, payload, addr, size);
		if (ret == KERN_SUCCESS) {
			if (writeProt != prot)
				ret = vmProtect(taskPort, addr, size, FALSE, prot);
			if (ret == KERN_SUCCESS)
				return addr;
			else
				SYSLOG("user", "vm_protect final %X fail %d", prot, ret);
		} else {
			SYSLOG("user", "vm_write_user fail %d", ret);
		}
	} else {
		SYSLOG("user", "vm_protect initial %X fail %d", writeProt, ret);
	}

	return 0;
}

bool UserPatcher::injectPayload(vm_map_t taskPort, uint8_t *payload, size_t size, void *ep) {
	if (size > PAGE_SIZE) {
		SYSLOG("user", "unreasonably large payload %lu", size);
		return false;
	}

	// Get task's mach-o header and determine its cpu type
	auto baseAddr = org_get_map_min(taskPort);
	DBGLOG("user", "injectPayload map min is " PRIKADDR, CASTKADDR(baseAddr));

	kern_return_t err = org_vm_map_read_user(taskPort, baseAddr, tmpBufferData, sizeof(tmpBufferData));
	auto machHeader = reinterpret_cast<mach_header_64 *>(tmpBufferData);
	if (err == KERN_SUCCESS){
		if (machHeader->magic == MH_MAGIC_64 || machHeader->magic == MH_MAGIC) {
			size_t hdrSize = machHeader->magic == MH_MAGIC ? sizeof(mach_header) : sizeof(mach_header_64);
			uintptr_t newEp = hdrSize + machHeader->sizeofcmds;
			if (newEp + PAGE_SIZE > sizeof(tmpBufferData)) {
				SYSLOG("user", "unpredictably large image header %lu", newEp);
				return false;
			}

			uint32_t *entry32 = nullptr;
			uint64_t *entry64 = nullptr;
			bool vmEp = true;
			uint64_t vmBase = 0;

			uint8_t *currPtr = tmpBufferData + hdrSize;
			for (uint32_t i = 0; i < machHeader->ncmds; i++) {
				auto cmd = reinterpret_cast<load_command *>(currPtr);

				if (cmd->cmd == LC_MAIN) {
					static constexpr size_t MainOff {0x8};
					entry64 = reinterpret_cast<uint64_t *>(currPtr + MainOff);
					vmEp = false;
				} else if (cmd->cmd == LC_UNIXTHREAD) {
					if (machHeader->magic == MH_MAGIC_64) {
						static constexpr size_t UnixThreadOff64 {0x90};
						entry64 = reinterpret_cast<uint64_t *>(currPtr + UnixThreadOff64);
					} else {
						static constexpr size_t UnixThreadOff32 {0x38};
						entry32 = reinterpret_cast<uint32_t *>(currPtr + UnixThreadOff32);
					}
				} else if (cmd->cmd == LC_SEGMENT) {
					auto seg = reinterpret_cast<segment_command *>(currPtr);
					if (seg->fileoff == 0 && seg->filesize > 0)
						vmBase = seg->vmaddr;
				} else if (cmd->cmd == LC_SEGMENT_64) {
					auto seg = reinterpret_cast<segment_command_64 *>(currPtr);
					if (seg->fileoff == 0 && seg->filesize > 0)
						vmBase = seg->vmaddr;
				}
				currPtr += cmd->cmdsize;
			}

			uint64_t orgEp = baseAddr - (vmEp ? vmBase : 0);
			uint64_t dstEp = newEp + (vmEp ? vmBase : 0);
			if (entry64) {
				orgEp += *entry64;
				*entry64 = dstEp;
			} else if (entry32) {
				orgEp += *entry32;
				*entry32 = static_cast<uint32_t>(dstEp);
			} else {
				SYSLOG("user", "failed to find valid entrypoint");
				return false;
			}

			if (ep) {
				if (machHeader->magic == MH_MAGIC_64)
					*static_cast<uint64_t *>(ep) = orgEp;
				else
					*static_cast<uint32_t *>(ep) = static_cast<uint32_t>(orgEp);
			}

			vm_prot_t prots[sizeof(tmpBufferData)/PAGE_SIZE] {};

			for (size_t i = 0; i < arrsize(prots); i++) {
				prots[i] = getPageProtection(taskPort, baseAddr + i * PAGE_SIZE);

				// Note, that we don't restore memory protection if we fail somewhere (no need to push something non-critical)
				// Enable writing for the calculated regions
				if (!(prots[i] & VM_PROT_WRITE)) {
					auto res = vmProtect(taskPort, (vm_offset_t)baseAddr + i * PAGE_SIZE, PAGE_SIZE, FALSE, prots[i]|VM_PROT_WRITE);
					if (res != KERN_SUCCESS) {
						SYSLOG("user", "failed to change memory protection (%lu, %d)", i, res);
						return false;
					}
				}
			}

			// Write new ep
			lilu_os_memcpy(tmpBufferData + newEp, payload, size);
			auto res = org_vm_map_write_user(taskPort, tmpBufferData, baseAddr, sizeof(tmpBufferData));
			if (res != KERN_SUCCESS) {
				SYSLOG("user", "failed to chage ep (%d)", res);
				return false;
			}

			// Restore protection flags
			for (size_t i = 0; i < arrsize(prots); i++) {
				if (!(prots[i] & VM_PROT_WRITE)) {
					res = vmProtect(taskPort, (vm_offset_t)baseAddr + i * PAGE_SIZE, PAGE_SIZE, FALSE, prots[i]);
					if (res != KERN_SUCCESS) {
						SYSLOG("user", "failed to restore memory protection (%lu, %d)", i, res);
						return true;
					}
				}
			}

		} else {
			SYSLOG("user", "unknown header magic %X", machHeader->magic);
		}
	} else {
		SYSLOG("user", "could not read target mach-o header (error %d)", err);
		return false;
	}

	return true;
}

kern_return_t UserPatcher::vmSharedRegionMapFileBigSur(vm_shared_region_t shared_region, int sr_mappings_count, sr_file_mappings *sr_mappings) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionMapFileBigSur");
	auto res = FunctionCast(vmSharedRegionMapFileBigSur, that->orgVmSharedRegionMapFile)(shared_region, sr_mappings_count, sr_mappings);
	//that->patchSharedCache(that->org_current_map(), 0, CPU_TYPE_X86_64);
	DBGLOG("user", "] UserPatcher::vmSharedRegionMapFileBigSur result:%d", res);
	return res;
}

kern_return_t UserPatcher::vmSharedRegionMapFileMavericks(vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir, uint32_t slide, user_addr_t slide_start, user_addr_t slide_size) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionMapFileMavericks slide:%X", slide);
	auto res = FunctionCast(vmSharedRegionMapFileMavericks, that->orgVmSharedRegionMapFile)(shared_region, mappings_count, mappings, file_control, file_size, root_dir, slide, slide_start, slide_size);
	if (!slide) {
		that->patchSharedCache(that->org_current_map(), 0, CPU_TYPE_X86_64);
	}
	DBGLOG("user", "] UserPatcher::vmSharedRegionMapFileMavericks result:%d", res);
	return res;
}

kern_return_t UserPatcher::vmSharedRegionMapFileLion(vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir, shared_file_mapping_np *mapping_to_slide) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionMapFileLion");
	auto res = FunctionCast(vmSharedRegionMapFileLion, that->orgVmSharedRegionMapFile)(shared_region, mappings_count, mappings, file_control, file_size, root_dir, mapping_to_slide);
	//that->patchSharedCache(that->org_current_map(), 0, CPU_TYPE_X86_64);
	DBGLOG("user", "] UserPatcher::vmSharedRegionMapFileLion result:%d", res);
	return res;
}

kern_return_t UserPatcher::vmSharedRegionMapFileLeopard(vm_shared_region_t shared_region, unsigned int mappings_count, shared_file_mapping_np *mappings, memory_object_control_t file_control, memory_object_size_t file_size, void *root_dir) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionMapFileLeopard");
	auto res = FunctionCast(vmSharedRegionMapFileLeopard, that->orgVmSharedRegionMapFile)(shared_region, mappings_count, mappings, file_control, file_size, root_dir);
	//that->patchSharedCache(that->org_current_map(), 0, CPU_TYPE_X86_64);
	DBGLOG("user", "] UserPatcher::vmSharedRegionMapFileLeopard result:%d", res);
	return res;
}

int UserPatcher::vmSharedRegionSlideBigSur(uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, mach_vm_offset_t slid_mapping, memory_object_control_t sr_file_control, vm_prot_t prot) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionSlideBigSur slide:%X start:%llX size:%llX slide_start:%llX slide_size:%llX prot:%X", slide, entry_start_address, entry_size, slide_start, slide_size, prot);
	that->patchSharedCache(that->org_current_map(), slide, CPU_TYPE_X86_64);
	int result = FunctionCast(vmSharedRegionSlideBigSur, that->orgVmSharedRegionSlide)(slide, entry_start_address, entry_size, slide_start, slide_size, slid_mapping, sr_file_control, prot);
	DBGLOG("user", "] UserPatcher::vmSharedRegionSlideBigSur result:%d", result);
	return result;
}

int UserPatcher::vmSharedRegionSlideMojave(uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, mach_vm_offset_t slid_mapping, memory_object_control_t sr_file_control) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionSlideMojave slide:%X start:%llX size:%llX slide_start:%llX slide_size:%llX", slide, entry_start_address, entry_size, slide_start, slide_size);
	that->patchSharedCache(that->org_current_map(), slide, CPU_TYPE_X86_64);
	int result = FunctionCast(vmSharedRegionSlideMojave, that->orgVmSharedRegionSlide)(slide, entry_start_address, entry_size, slide_start, slide_size, slid_mapping, sr_file_control);
	DBGLOG("user", "] UserPatcher::vmSharedRegionSlideMojave result:%d", result);
	return result;
}

int UserPatcher::vmSharedRegionSlideMavericks(uint32_t slide, mach_vm_offset_t entry_start_address, mach_vm_size_t entry_size, mach_vm_offset_t slide_start, mach_vm_size_t slide_size, memory_object_control_t sr_file_control) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionSlideMavericks slide:%X start:%llX size:%llX slide_start:%llX slide_size:%llX", slide, entry_start_address, entry_size, slide_start, slide_size);
	that->patchSharedCache(that->org_current_map(), slide, CPU_TYPE_X86_64);
	int result = FunctionCast(vmSharedRegionSlideMavericks, that->orgVmSharedRegionSlide)(slide, entry_start_address, entry_size, slide_start, slide_size, sr_file_control);
	DBGLOG("user", "] UserPatcher::vmSharedRegionSlideMavericks result:%d", result);
	return result;
}

kern_return_t UserPatcher::vmSharedRegionSlideLion(vm_offset_t vaddr, uint32_t pageIndex) {
	DBGLOG("user", "[ UserPatcher::vmSharedRegionSlideLion vaddr:%lX pageIndex:%X", vaddr, pageIndex);
	//that->patchSharedCache(that->org_current_map(), slide, CPU_TYPE_X86_64);
	kern_return_t result = FunctionCast(vmSharedRegionSlideLion, that->orgVmSharedRegionSlide)(vaddr, pageIndex);
	DBGLOG("user", "] UserPatcher::vmSharedRegionSlideLion result:%d", result);
	return result;
}

void UserPatcher::taskSetMainThreadQos(task_t task, thread_t main_thread) {
	FunctionCast(taskSetMainThreadQos, that->orgTaskSetMainThreadQos)(task, main_thread);

	auto entry = that->pending.get();
	if (entry) {
		DBGLOG("user", "[ UserPatcher::taskSetMainThreadQos");
		DBGTRACE("user", "firing hook from task_set_main_thread_qos " PRIKADDR, CASTKADDR(current_thread()));
		that->patchBinary(that->org_get_task_map(task), (*entry)->path, (*entry)->pathLen);
		PANIC_COND(!that->pending.erase(), "user", "failed to remove pending user patch in task_set_main_thread_qos");
		delete *entry;
		DBGLOG("user", "] UserPatcher::taskSetMainThreadQos");
	}
}

void UserPatcher::patchSharedCache(vm_map_t taskPort, uint32_t slide, cpu_type_t cpu, bool applyChanges) {
	DBGLOG("user", "[ UserPatcher::patchSharedCache applyChanges:%d", applyChanges);
	// Save the slide for restoration
	if (applyChanges && !sharedCacheSlideStored) {
		DBGLOG("user", "setting slide to 0x%x", slide);
		storedSharedCacheSlide = slide;
		sharedCacheSlideStored = true;
	}

	DBGLOG("user", "[ lookupStorage loop %lld", (uint64_t)lookupStorage.size());
	for (size_t i = 0, sz = lookupStorage.size(); i < sz; i++) {
		DBGLOG("user", "[ lookupStorage[%lld]", (uint64_t)i);
		auto &storageEntry = lookupStorage[i];
		auto &mod = storageEntry->mod;
		DBGLOG("user", "[ storageEntry loop %lld", (uint64_t)storageEntry->refs.size());
		for (size_t j = 0, rsz = storageEntry->refs.size(); j < rsz; j++) {
			DBGLOG("user", "[ storageEntry->refs[%lld]", (uint64_t)j);
			auto &ref = storageEntry->refs[j];
			auto &patch = storageEntry->mod->patches[ref->i];
			size_t offNum = ref->segOffs.size();

			vm_address_t modStart = 0;
			vm_address_t modEnd = 0;

			static_assert(FileSegment::SegmentsTextStart == 0, "ABI changes should reflect code changes!");
			if (patch.segment <= FileSegment::SegmentsTextEnd) {
				modStart = mod->startTEXT;
				modEnd = mod->endTEXT;
			} else if (patch.segment >= FileSegment::SegmentsDataStart && patch.segment <= FileSegment::SegmentsDataEnd) {
				modStart = mod->startDATA;
				modEnd = mod->endDATA;
			} else {
				DBGLOG("user", "no modStart and modEnd");
			}

			if (modStart && modEnd && offNum && patch.cpu == cpu) {
				DBGLOG("user", "patch for %s in %llX %llX", mod->path, (uint64_t)modStart, (uint64_t)modEnd);
				auto tmp = Buffer::create<uint8_t>(patch.size);
				if (tmp) {
					for (size_t k = 0; k < offNum; k++) {
						auto place = modStart+ref->segOffs[k]+slide;
						auto r = org_vm_map_read_user(taskPort, place, tmp, patch.size);
						if (!r) {
							bool comparison = !memcmp(tmp, applyChanges? patch.find : patch.replace, patch.size);
							DBGLOG("user", "%d/%d found %02X %02X %02X %02X", applyChanges, comparison, tmp[0], tmp[1], tmp[2], tmp[3]);
							if (comparison) {
								r = vmProtect(taskPort, (vm_offset_t)(place & -PAGE_SIZE), PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
								if (r == KERN_SUCCESS) {
									DBGLOG("user", "obtained write permssions");

									r = org_vm_map_write_user(taskPort, applyChanges ? patch.replace : patch.find, place, patch.size);

									SYSLOG("user", "patching %llX -> result:%d", place, r);

									r = vmProtect(taskPort, (vm_offset_t)(place & -PAGE_SIZE), PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_EXECUTE);
									if (r == KERN_SUCCESS)
										DBGLOG("user", "restored write permssions");
									else
										DBGLOG("user", "failed to restore write permssions %d", r);
								} else {
									SYSLOG("user", "failed to obtain write permissions for patching %d", r);
								}
							} else if (ADDPR(debugEnabled)) {
								for (size_t l = 0; l < patch.size; l++) {
									auto v = (applyChanges? patch.find : patch.replace)[l];
									if (tmp[l] != v) {
										DBGLOG("user", "miss at %lu: %02X vs %02X", l, tmp[l], v);
										break;
									}
								}
							}
						}

						DBGLOG("user", "done reading patches for %llX", ref->segOffs[k]);
					}
					Buffer::deleter(tmp);
				}
			}
			else {
				// startTEXT is only set for shared dyld cache frameworks so this patching method doesn't apply to non-dyld shared cache patches
				DBGLOG("user", "not patching here because modStart:%llx modEnd:%llx offNum:%llx patch.cpu:%d cpu:%d", (uint64_t)modStart, (uint64_t)modEnd, (uint64_t)offNum, patch.cpu, cpu);
			}
			DBGLOG("user", "] storageEntry->refs[%lld]", (uint64_t)j);
		} // for storageEntry->refs
		DBGLOG("user", "] storageEntry loop %lld", (uint64_t)storageEntry->refs.size());
		DBGLOG("user", "] lookupStorage[%lld]", (uint64_t)i);
	} // for lookupStorage
	DBGLOG("user", "] lookupStorage loop %lld", (uint64_t)lookupStorage.size());
	DBGLOG("user", "] UserPatcher::patchSharedCache");
}

size_t UserPatcher::mapAddresses(const char *mapBuf, MapEntry *mapEntries, size_t nentries) {
	DBGLOG("user", "[ UserPatcher::mapAddresses nentries:%d", (int)nentries);
	if (nentries == 0 || !mapBuf) {
		DBGLOG("user", "] UserPatcher::mapAddresses (no entries)");
		return 0;
	}

	size_t nfound = 0;
	const char *ptr = mapBuf;
	while (*ptr) {
			MapEntry *currEntry = nullptr;

		//const char *lineStart = ptr;

			for (size_t j = 0; j < nentries; j++) {
				if (!mapEntries[j].filename)
					continue;
			if (!strncmp(ptr, mapEntries[j].filename, mapEntries[j].length)) {
					currEntry = &mapEntries[j];
				ptr += mapEntries[j].length;
					break;
				}
			}

		// find section mappings or next line
		for (; *ptr && *ptr != '\n'; ptr++) {};
		if (!*ptr) break;

		//DBGLOG("user", "line: %.*s", (int)(ptr - lineStart), lineStart);
		ptr++;

			if (currEntry) {
			bool foundSection = false;
			for (; *ptr == '\t'; ptr++) { // iterate section mappings
				// find section name
				for (ptr++; *ptr == ' '; ptr++) {}
				const char *sectionName = ptr;
				for (; *ptr && *ptr != ' '; ptr++) {}
				if (!*ptr) break;

				// find section start
				for (ptr++; *ptr == ' '; ptr++) {}
				const char *sectionStart = ptr;
				for (; *ptr && *ptr != ' '; ptr++) {}
				if (!*ptr) break;

				// find section end
				const char *sectionEnd = nullptr;
				if (!strncmp(ptr, " -> ", strlen(" -> "))) { ptr += strlen(" -> "); sectionEnd = ptr; }
				for (; *ptr && *ptr != '\n'; ptr++) {}
				if (!sectionEnd) break;
				if (!*ptr) break;

				if (!strncmp(sectionName, "__TEXT ", strlen("__TEXT "))) {
					currEntry->startTEXT = lilu_strtou(sectionStart, nullptr, 16);
					currEntry->endTEXT = lilu_strtou(sectionEnd, nullptr, 16);
					foundSection = true;
				}
				else if (!strncmp(sectionName, "__DATA ", strlen("__DATA "))) {
					currEntry->startDATA = lilu_strtou(sectionStart, nullptr, 16);
					currEntry->endDATA = lilu_strtou(sectionEnd, nullptr, 16);
					foundSection = true;
				}
			}
			if (foundSection) nfound++;
		}
	}

	DBGLOG("user", "] UserPatcher::mapAddresses found:%d", (int)nfound);
	return nfound;
}

bool UserPatcher::loadDyldSharedCacheMapping() {
	DBGLOG("user", "[ UserPatcher::loadDyldSharedCacheMapping binaryModSize:%lu", binaryModSize);

	if (binaryModSize == 0) {
		DBGLOG("user", "] UserPatcher::loadDyldSharedCacheMapping true");
		return true;
	}

	uint8_t *buffer {nullptr};
	size_t bufferSize {0};
	bool isHaswell = BaseDeviceInfo::get().cpuHasAvx2;
	if (getKernelVersion() >= KernelVersion::Ventura) {
		// This probably fails because /System/Volumes/Preboot hasn't been mounted yet!
		buffer = FileIO::readFileToBuffer(isHaswell ? venturaSharedCacheMapHaswell : venturaSharedCacheMapLegacy, bufferSize);
	}
	else if (getKernelVersion() >= KernelVersion::BigSur) {
		buffer = FileIO::readFileToBuffer(isHaswell ? bigSurSharedCacheMapHaswell : bigSurSharedCacheMapLegacy, bufferSize);
	}
	else if (isHaswell && getKernelVersion() >= KernelVersion::Yosemite) {
		buffer = FileIO::readFileToBuffer(SharedCacheMapHaswell, bufferSize);
	}

	if (!buffer)
		buffer = FileIO::readFileToBuffer(SharedCacheMapLegacy, bufferSize);

	bool res {false};

	if (buffer && bufferSize > 0) {
		auto entries = Buffer::create<MapEntry>(binaryModSize);
		if (entries) {
			for (size_t i = 0; i < binaryModSize; i++) {
				entries[i].filename = binaryMod[i]->path;
				entries[i].length = strlen(binaryMod[i]->path);
				entries[i].startTEXT = entries[i].endTEXT = entries[i].startDATA = entries[i].endDATA = 0;
			}

			size_t nEntries = mapAddresses(reinterpret_cast<char *>(buffer), entries, binaryModSize);

			if (nEntries > 0) {
				DBGLOG("user", "mapped %lu entries out of %lu", nEntries, binaryModSize);

				for (size_t i = 0; i < binaryModSize; i++) {
					DBGLOG("user", "entry:%d TEXT:%llX..%llX DATA:%llX..%llX path:%s", (int)i,
						(uint64_t)entries[i].startTEXT, (uint64_t)entries[i].endTEXT,
						(uint64_t)entries[i].startDATA, (uint64_t)entries[i].endDATA,
						entries[i].filename ? entries[i].filename : "NULL");
					binaryMod[i]->startTEXT = entries[i].startTEXT;
					binaryMod[i]->endTEXT = entries[i].endTEXT;
					binaryMod[i]->startDATA = entries[i].startDATA;
					binaryMod[i]->endDATA = entries[i].endDATA;
				}

				res = true;
			} else {
				SYSLOG("user", "failed to map any entry out of %lu", binaryModSize);
			}
		} else {
			SYSLOG("user", "failed to allocate memory for MapEntry %lu", binaryModSize);
		}

		if (entries) Buffer::deleter(entries);
	} else {
		SYSLOG("user", "no dyld_shared_cache discovered, fallback to slow!");
		patchDyldSharedCache = false;
		res = true;
	}

	if (buffer) Buffer::deleter(buffer);

	DBGLOG("user", "] UserPatcher::loadDyldSharedCacheMapping result:%d", res);
	return res;
}

bool UserPatcher::loadFilesForPatching() {
	DBGLOG("user", "[ UserPatcher::loadFilesForPatching binaryModSize:%lu", binaryModSize);

	for (size_t i = 0; i < binaryModSize; i++) {
		bool hasPatches = false;

		for (size_t p = 0; p < binaryMod[i]->count; p++) {
			if (binaryMod[i]->patches[p].section != ProcInfo::SectionDisabled) {
				hasPatches = true;
				break;
			}
		}

		if (hasPatches) {
			DBGLOG("user", "[ requesting file %s at %lu", binaryMod[i]->path, i);
		} else {
			DBGLOG("user", "[] ignoring file %s at %lu, no mods out of %lu apply", binaryMod[i]->path, i, binaryMod[i]->count);
			continue;
		}

		size_t fileSize;
		auto buf = FileIO::readFileToBuffer(binaryMod[i]->path, fileSize);
		if (buf) {
			vm_address_t vmsegment {0};
			vm_address_t vmsection {0};
			void *sectionptr {nullptr};
			size_t size {0};

			DBGLOG("user", "have %lu mods for %s (fileSize:%lu)", binaryMod[i]->count, binaryMod[i]->path, fileSize);

			for (size_t p = 0; p < binaryMod[i]->count; p++) {
				auto &patch = binaryMod[i]->patches[p];

				if (patch.section == ProcInfo::SectionDisabled) {
					DBGLOG("user", "[] skipping not requested patch %s for %lu", binaryMod[i]->path, p);
					continue;
				}

				if (patch.segment >= FileSegment::SegmentTotal) {
					SYSLOG("user", "[] skipping patch %s for %lu with invalid segment id %u", binaryMod[i]->path, p, patch.segment);
					continue;
				}

				DBGLOG("user", "[ mod %lu", p);
				
				MachInfo::findSectionBounds(buf, fileSize, vmsegment, vmsection, sectionptr, size,
											fileSegments[patch.segment], fileSections[patch.segment], patch.cpu);

				DBGLOG("user", "findSectionBounds returned vmsegment %llX vmsection %llX sectionptr %p size %lu", (uint64_t)vmsegment, (uint64_t)vmsection, sectionptr, size);

				if (size) {
					uint8_t *start = reinterpret_cast<uint8_t *>(sectionptr);
					uint8_t *end = start + size - patch.size;
					size_t skip = patch.skip;
					size_t count = patch.count;

					DBGLOG("user", "this patch will start from %lu entry and will replace %lu findings", skip, count);

					while (start < end && count) {
						if (!memcmp(start, patch.find, patch.size)) {
							DBGLOG("user", "found entry of %02X %02X %02X %02X patch", patch.find[0], patch.find[1], patch.find[2], patch.find[3]);

							if (skip == 0) {
								off_t sectOff = start - reinterpret_cast<uint8_t *>(sectionptr);
								vm_address_t vmpage = (vmsection + (vm_address_t)sectOff) & -PAGE_SIZE;
								vm_address_t pageOff = vmpage - vmsection;
								off_t valueOff = reinterpret_cast<uintptr_t>(start - pageOff - reinterpret_cast<uintptr_t>(sectionptr));
								off_t segOff = vmsection-vmsegment+sectOff;

								DBGLOG("user", "using it off %llX pageOff %llX new %llX segOff %llX", sectOff, (uint64_t)pageOff, (uint64_t)vmpage, segOff);

								// We need binary entry, i.e. the page our patch belong to
								LookupStorage *entry = nullptr;
								for (size_t e = 0, esz = lookupStorage.size(); e < esz && !entry; e++) {
									if (lookupStorage[e]->pageOff == static_cast<vm_address_t>(pageOff))
										entry = lookupStorage[e];
								}


								if (!entry) {
									entry = LookupStorage::create();
									if (entry) {
										entry->mod = binaryMod[i];
										if (!entry->page->alloc()) {
											LookupStorage::deleter(entry);
											entry = nullptr;
										} else {
											// One could find entries by flooring first ref address but that's unreasonably complicated
											entry->pageOff = pageOff;
											// Now copy page data
											lilu_os_memcpy(entry->page->p, reinterpret_cast<uint8_t *>(sectionptr) + pageOff, PAGE_SIZE);
											DBGLOG("user", "first page bytes are %02X %02X %02X %02X %02X %02X %02X %02X",
												entry->page->p[0], entry->page->p[1], entry->page->p[2], entry->page->p[3],
												entry->page->p[4], entry->page->p[5], entry->page->p[6], entry->page->p[7]);
											// Save entry in lookupStorage
											if (!lookupStorage.push_back<2>(entry)) {
												SYSLOG("user", "failed to push entry to LookupStorage");
												LookupStorage::deleter(entry);
												entry = nullptr;
												continue;
											}
										}
									}

									if (!entry) {
										SYSLOG("user", "failed to allocate memory for LookupStorage");
										continue;
									}
								}

								// Use an existent reference to the same patch in the same page if any.
								// Happens when a patch has 2+ replacements and they are close to each other.
								LookupStorage::PatchRef *ref = nullptr;
								for (size_t r = 0, rsz = entry->refs.size(); r < rsz && !ref; r++) {
									if (entry->refs[r]->i == p) {
										ref = entry->refs[r];
									}
								}

								DBGLOG("user", "ref find %d", ref != nullptr);

								// Or add a new patch reference
								if (!ref) {
									ref = LookupStorage::PatchRef::create();
									if (!ref) {
										SYSLOG("user", "failed to allocate memory for PatchRef");
										continue;
									}
									ref->i = p; // Set the reference patch
									if (!entry->refs.push_back<2>(ref)) {
										SYSLOG("user", "failed to insert PatchRef");
										LookupStorage::PatchRef::deleter(ref);
										continue;
									}
								}

								if (ref) {
									DBGLOG("user", "pushing off %llX to patch", valueOff);
									// These values belong to the current ref
									ref->pageOffs.push_back<2>(valueOff);
									ref->segOffs.push_back<2>(segOff);
								}
								count--;
							} else {
								skip--;
							}
						}
						start++;
					}
				} else {
					SYSLOG("user", "failed to obtain a corresponding section");
				}
				DBGLOG("user", "] mod %lu", p);
			} // for patch

			Buffer::deleter(buf);
		}
		DBGLOG("user", "]");
	} // for binaryMod
	DBGLOG("user", "] UserPatcher::loadFilesForPatching true");
	return true;
}

bool UserPatcher::loadLookups() {
	DBGLOG("user", "[ UserPatcher::loadLookups");
	uint32_t off = 0;

	for (size_t i = 0; i < Lookup::matchNum; i++) {
		auto &lookupCurr = lookup.c[i];

		DBGLOG("user", "loading lookup %lu current off is %X", i, off);

		auto obtainValues = [&lookupCurr, &off, this]() {
			for (size_t p = 0; p < lookupStorage.size(); p++) {
				uint64_t val = *reinterpret_cast<uint64_t *>(lookupStorage[p]->page->p + off);
				if (p >= lookupCurr.size()) {
					lookupCurr.push_back<2>(val);
				} else {
					lookupCurr[p] = val;
				}
			}
		};

		auto hasSameValues = [&lookupCurr]() {
			for (size_t i = 0, sz = lookupCurr.size(); i < sz; i++) {
				for (size_t j = i + 1; j < sz; j++) {
					if (lookupCurr[i] == lookupCurr[j]) {
						return true;
					}
				}
			}

			return false;
		};

		// First match must choose a page
		if (i == 0) {
			// Find non matching off
			while (off < PAGE_SIZE) {
				// Obtain values
				obtainValues();

				if (!hasSameValues()) {
					DBGLOG("user", "successful finding at %X", off);
					lookup.offs[i] = off;
					break;
				}

				off += sizeof(uint64_t);
			}
		} else {
			if (off == PAGE_SIZE) {
				DBGLOG("user", "resetting off to 0");
				off = 0;
			}

			if (off == lookup.offs[0]) {
				DBGLOG("user", "matched off %X with 0th", off);
				off += sizeof(uint64_t);
			}

			DBGLOG("user", "chose %X", off);

			obtainValues();
			lookup.offs[i] = off;

			off += sizeof(uint64_t);
		}

	}

	DBGLOG("user", "] UserPatcher::loadLookups true");
	return true;
}

vm_prot_t UserPatcher::getPageProtection(vm_map_t map, vm_map_address_t addr) {
	vm_prot_t prot = VM_PROT_NONE;
	if (org_vm_map_check_protection(map, addr, addr+PAGE_SIZE, VM_PROT_READ))
		prot |= VM_PROT_READ;
	if (org_vm_map_check_protection(map, addr, addr+PAGE_SIZE, VM_PROT_WRITE))
		prot |= VM_PROT_WRITE;
	if (org_vm_map_check_protection(map, addr, addr+PAGE_SIZE, VM_PROT_EXECUTE))
		prot |= VM_PROT_EXECUTE;

	return prot;
}

extern "C" {
	lck_rw_type_t lck_rw_done(lck_rw_t *lck);
}
#define vm_map_lock(map) lck_rw_lock_exclusive((lck_rw_t *)map);
#define vm_map_unlock(map) lck_rw_done((lck_rw_t *)map);
#if defined(__i386__) // i386 and ppc
	#define vm_map_to_entry(map) (vm_map_entry_t)&getMember<void*>(map, 12)
	#define vme_next(entry) getMember<vm_map_entry_t>(entry, 4)
	#define vme_start(entry) getMember<vm_map_offset_t>(entry, 8)
	#define vme_end(entry) getMember<vm_map_offset_t>(entry, 16)
#else
	#define vm_map_to_entry(map) (vm_map_entry_t)&getMember<void*>(map, 16)
	#define vme_next(entry) getMember<vm_map_entry_t>(entry, 8)
	#define vme_start(entry) getMember<vm_map_offset_t>(entry, 16)
	#define vme_end(entry) getMember<vm_map_offset_t>(entry, 24)
#endif
#define vme_max_protection(entry) (((getMember<int32_t>(entry, vme_flags_offset)) >> vme_flag_max_protection_shift) & ~(-1 << vme_flag_max_protection_size))
#define set_vme_max_protection(entry, protection) ((getMember<int32_t>(entry, vme_flags_offset)) |= ((protection & ~(-1 << vme_flag_max_protection_size)) << vme_flag_max_protection_shift ))

/* Change max protection */
bool UserPatcher::vmSetMaxProtection(
	vm_map_t map,
	vm_map_offset_t start,
	vm_size_t size,
	vm_prot_t set_protection,
	vm_prot_t clear_protection)
{
	vm_map_entry_t entry;
	vm_map_entry_t tmp_entry;
	vm_map_offset_t end = start + size;

	// from examining disassembly of each kernel:
	// 10.4.11 Tiger         = byte:0x25 shift:2 = int32:0x24 shift:10 // i386 (did not check ppc)
	// 10.5.8  Leopard       = byte:0x25 shift:2 = int32:0x24 shift:10 // i386 (did not check ppc)
	// 10.6.8  Snow Leopard  = byte:0x31 shift:2 = int32:0x30 shift:10 // i386 is 0x24
	// 10.7.5  Lion          =                     int32:0x48 shift:10 // i386 is 0x30
	// 10.8.5  Mountain Lion =                     int32:0x48 shift:10
	// 10.9.5  Mavericks     =                     int32:0x48 shift:10
	// 10.10.5 Yosemite      =                     int32:0x48 shift:10
	// 10.11.6 El Capitan    =                     int32:0x48 shift:10
	// 10.12.6 Sierra        =                     int32:0x48 shift:10
	// 10.13.6 High Sierra   =                     int32:0x48 shift:10
	// 10.14.6 Mojave        =                     int32:0x48 shift:10
	// 10.15.7 Catalina      =                     int32:0x48 shift:10
	// 11.6.4  Big Sur       =                     int32:0x48 shift:10
	// 12.2.1  Monterey      =                     int32:0x48 shift:11

	int vme_flags_offset =
#if defined(__i386__)
		getKernelVersion() >= KernelVersion::Lion        ? 0x30 :
#else
		getKernelVersion() >= KernelVersion::Lion        ? 0x48 :
		getKernelVersion() >= KernelVersion::SnowLeopard ? 0x30 :
#endif
		0x24;

	// DWARF debug symbols (dSYM) for i386/x86_64 between 10.5 and 10.12 incorrectly shows bit offset of 19 which is the result of counting bits from the MSB instead of the LSB
	// meaning the LSB (bit 0) is bit offset 31 in DWARF and bit 10 is bit offset 19 in DWARF.
	// 19 = 32(int32 total bits) - 10(bit# counted from LSB) - 3(field width in bits)
	// DWARF debug symbols after 10.13 use the correct bit number (counting from LSB) which is 10 (11 for Monterey)
	int vme_flag_max_protection_shift = getKernelVersion() >= KernelVersion::Monterey ? 11 : 10;
	int vme_flag_max_protection_size  = getKernelVersion() >= KernelVersion::Monterey ? 4  : 3;

	vm_map_lock(map);

	if (!org_vm_map_lookup_entry(map, start, &tmp_entry)) {
		DBGLOG("user", "orgVmMapLookupEntry failed");
		vm_map_unlock(map);
		return FALSE;
	}

	entry = tmp_entry;

	while (start < end) {
		if (entry == vm_map_to_entry(map)) {
			DBGLOG("user", "entry == vm_map");
			vm_map_unlock(map);
			return FALSE;
		}

		if (start < vme_start(entry)) {
			// No holes allowed!
			DBGLOG("user", "vm entry hole");
			vm_map_unlock(map);
			return FALSE;
		}

		int old_max_protection = vme_max_protection(entry);
		int new_max_protection = (old_max_protection & ~clear_protection) | set_protection;

		if (new_max_protection != old_max_protection) {
			DBGLOG("user", "changed max protection of 0x%llx from %d to %d", start, old_max_protection, new_max_protection);
			set_vme_max_protection(entry, new_max_protection);
		}

		start = vme_end(entry);
		entry = vme_next(entry);
	}
	vm_map_unlock(map);
	return TRUE;
}

bool UserPatcher::hookMemoryAccess() {
	DBGLOG("user", "[ UserPatcher::hookMemoryAccess");

	KernelPatcher::RouteRequest pageRoute =
		/**/ getKernelVersion() >= KernelVersion::BigSur       ? KernelPatcher::RouteRequest("_cs_validate_page" , codeSignValidatePageWrapperBigSur      , orgCodeSignValidatePageWrapper ) // 11
		:    getKernelVersion() >= KernelVersion::Sierra       ? KernelPatcher::RouteRequest("_cs_validate_range", codeSignValidateRangeWrapper           , orgCodeSignValidateRangeWrapper) // 10.12, 10.13, 10.14, 10.15 // this exists for 11 but it doesn't get used
		:    getKernelVersion() >= KernelVersion::Yosemite     ? KernelPatcher::RouteRequest("_cs_validate_page" , codeSignValidatePageWrapperYosemite    , orgCodeSignValidatePageWrapper ) // 10.10, 10.11
		:    getKernelVersion() >= KernelVersion::MountainLion ? KernelPatcher::RouteRequest("_cs_validate_page" , codeSignValidatePageWrapperMountainLion, orgCodeSignValidatePageWrapper ) // 10.8, 10.9
		:    getKernelVersion() >= KernelVersion::Leopard      ? KernelPatcher::RouteRequest("_cs_validate_page" , codeSignValidatePageWrapperLeopard     , orgCodeSignValidatePageWrapper ) // 10.5, 10.6, 10.7
		:                                                        KernelPatcher::RouteRequest(NULL, NULL);
	if (pageRoute.symbol && !patcher->routeMultipleLong(KernelPatcher::KernelID, &pageRoute, 1)) {
		SYSLOG("user", "failed to resolve _cs_validate function");
		DBGLOG("user", "] UserPatcher::hookMemoryAccess false");
		return false;
	}

	#define solveone(fatal, name) \
		org ## name = reinterpret_cast<t ## name>(patcher->solveSymbol(KernelPatcher::KernelID, # name)); \
		if (patcher->getError() != KernelPatcher::Error::NoError) { \
			if (fatal) { \
				SYSLOG("user", "failed to resolve " # name); \
				patcher->clearError(); \
				DBGLOG("user", "] UserPatcher::hookMemoryAccess false"); \
				return false; \
			} \
			else { \
				DBGLOG("user", "failed to resolve " # name); \
				patcher->clearError(); \
				/* Not an error, may be missing */ \
			} \
		}

	solveone(1, _current_map);
	solveone(1, _get_map_min);
	solveone(1, _get_task_map);
	solveone(0, _vm_map_switch_protect);
	solveone(1, _vm_map_check_protection);
	solveone(1, _vm_map_read_user);
	solveone(1, _vm_map_write_user);
	solveone(1, _vm_map_lookup_entry);
	#undef solveone

	// On 10.12.1 b4 Apple decided not to let current_map point to the current process
	// For this reason we have to obtain the map with the other methods
	if (getKernelVersion() >= KernelVersion::Sierra) {
		KernelPatcher::RouteRequest request {"_task_set_main_thread_qos", taskSetMainThreadQos, orgTaskSetMainThreadQos};
		if (!patcher->routeMultiple(KernelPatcher::KernelID, &request, 1, 0, 0, true, false)) {
			DBGLOG("user", "failed to hook _task_set_main_thread_qos");
			// This is not an error, early 10.12 versions have no such function
		}
	}

	if (getKernelVersion() >= KernelVersion::BigSur) {
		KernelPatcher::RouteRequest request {"_vm_page_validate_cs_mapped", wrap_vm_page_validate_cs_mapped, org_vm_page_validate_cs_mapped};
		if (!patcher->routeMultiple(KernelPatcher::KernelID, &request, 1, 0, 0, true, false)) {
			DBGLOG("user", "failed to hook _vm_page_validate_cs_mapped");
		}
	}

	if (getKernelVersion() >= KernelVersion::Mojave) {
		KernelPatcher::RouteRequest request {"_vm_page_validate_cs_mapped_slow", wrap_vm_page_validate_cs_mapped_slow, org_vm_page_validate_cs_mapped_slow};
		if (!patcher->routeMultiple(KernelPatcher::KernelID, &request, 1, 0, 0, true, false)) {
			DBGLOG("user", "failed to hook _vm_page_validate_cs_mapped_slow");
		}
	}

	if (patchDyldSharedCache) {

		KernelPatcher::RouteRequest mapRoute =
			/**/ getKernelVersion() >= KernelVersion::BigSur    ? KernelPatcher::RouteRequest("_vm_shared_region_map_file", vmSharedRegionMapFileBigSur   , orgVmSharedRegionMapFile) // 11
			:    getKernelVersion() >= KernelVersion::Mavericks ? KernelPatcher::RouteRequest("_vm_shared_region_map_file", vmSharedRegionMapFileMavericks, orgVmSharedRegionMapFile) // 10.9, 10.10, 10.11, 10.12, 10.13, 10.14, 10.15
			:    getKernelVersion() >= KernelVersion::Lion      ? KernelPatcher::RouteRequest("_vm_shared_region_map_file", vmSharedRegionMapFileLion     , orgVmSharedRegionMapFile) // 10.7, 10.8
			:    getKernelVersion() >= KernelVersion::Leopard   ? KernelPatcher::RouteRequest("_vm_shared_region_map_file", vmSharedRegionMapFileLeopard  , orgVmSharedRegionMapFile) // 10.5, 10.6
			:                                                     KernelPatcher::RouteRequest(NULL, NULL);
		if (mapRoute.symbol && !patcher->routeMultipleLong(KernelPatcher::KernelID, &mapRoute, 1)) {
			SYSLOG("user", "failed to hook _vm_shared_region_map_file");
			DBGLOG("user", "] UserPatcher::hookMemoryAccess false");
			return false;
		}

		KernelPatcher::RouteRequest sharedRegionRoute =
			/**/ getKernelVersion() >= KernelVersion::BigSur    ? KernelPatcher::RouteRequest("_vm_shared_region_slide", vmSharedRegionSlideBigSur   , orgVmSharedRegionSlide) // 11
			:    getKernelVersion() >= KernelVersion::Mojave    ? KernelPatcher::RouteRequest("_vm_shared_region_slide", vmSharedRegionSlideMojave   , orgVmSharedRegionSlide) // 10.14, 10.15
			:    getKernelVersion() >= KernelVersion::Mavericks ? KernelPatcher::RouteRequest("_vm_shared_region_slide", vmSharedRegionSlideMavericks, orgVmSharedRegionSlide) // 10.9, 10.10, 10.11, 10.12, 10.13
			:    getKernelVersion() >= KernelVersion::Lion      ? KernelPatcher::RouteRequest("_vm_shared_region_slide", vmSharedRegionSlideLion     , orgVmSharedRegionSlide) // 10.7, 10.8
			:                                                     KernelPatcher::RouteRequest(NULL, NULL);
		if (sharedRegionRoute.symbol && !patcher->routeMultipleLong(KernelPatcher::KernelID, &sharedRegionRoute, 1)) {
			SYSLOG("user", "failed to hook _vm_shared_region_slide");
			DBGLOG("user", "] UserPatcher::hookMemoryAccess false");
			return false;
		}

	}

	DBGLOG("user", "] UserPatcher::hookMemoryAccess true");
	return true;
}

void UserPatcher::activate() {
	atomic_store_explicit(&activated, true, memory_order_relaxed);
}

const char *UserPatcher::getSharedCachePath() {
	bool isHaswell = BaseDeviceInfo::get().cpuHasAvx2;
	if (getKernelVersion() >= KernelVersion::Ventura)
		return isHaswell ? venturaSharedCacheHaswell : venturaSharedCacheLegacy;
	else if (getKernelVersion() >= KernelVersion::BigSur)
		return isHaswell ? bigSurSharedCacheHaswell : bigSurSharedCacheLegacy;
	return isHaswell ? sharedCacheHaswell : sharedCacheLegacy;
}

bool UserPatcher::matchSharedCachePath(const char *path) {
	#ifdef DEBUG
	const char *pathstart = path;
	#endif
	if (getKernelVersion() >= KernelVersion::BigSur) {
		auto dyld_path = getKernelVersion() >= KernelVersion::Ventura ? venturaSharedCacheLegacy : bigSurSharedCacheLegacy;
		auto len = strlen(dyld_path);
		if (strncmp(path, dyld_path, len) != 0)
			return false;
		path += len;
	} else {
		auto len = strlen(sharedCacheLegacy);
		if (strncmp(path, sharedCacheLegacy, len) != 0)
			return false;
		path += len;
	}

	// Allow non-haswell cache on haswell, but not otherwise.
	if (BaseDeviceInfo::get().cpuHasAvx2 && path[0] == 'h')
		path++;

	// Skip suffix matching on macOS 12 and newer
	if (getKernelVersion() >= KernelVersion::Monterey) {
		if (path[0] == '.')
			path += 1;
		if (getKernelVersion() >= KernelVersion::Ventura && path[0] == '0')
			path += 1;
		if (path[0] >= '1' && path[0] <= '9')
			path += 1;
	}


	if (path[0] == '\0') {
		return true;
	}

	DBGLOG("user", "matchSharedCachePath unexpected path %s", pathstart);
	return false;
}
