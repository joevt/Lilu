//
//  kern_api.cpp
//  Lilu
//
//  Copyright © 2016-2017 vit9696. All rights reserved.
//

#include <libkern/c++/OSObject.h>

#include <Headers/kern_config.hpp>
#include <PrivateHeaders/kern_config.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_devinfo.hpp>

#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>

LiluAPI lilu;

void LiluAPI::init() {
	DBGLOG("api", "[ LiluAPI::init");
	access = IOLockAlloc();

	if (ADDPR(config).installOrRecovery)
		currentRunMode |= RunningInstallerRecovery;
	else if (ADDPR(config).safeMode)
		currentRunMode |= RunningSafeMode;
	else
		currentRunMode |= RunningNormal;
	DBGLOG("api", "] LiluAPI::init");
}

void LiluAPI::deinit() {
	DBGLOG("api", "[ LiluAPI::deinit");
	if (access) {
		IOLockFree(access);
		access = nullptr;
	}
	DBGLOG("api", "] LiluAPI::deinit");
}

LiluAPI::Error LiluAPI::requestAccess(size_t version, bool check) {

	DBGLOG("api", "[ LiluAPI::requestAccess (%lu, %d)", version, check);

	if (!ADDPR(config).startSuccess) {
		DBGLOG("api", "] LiluAPI::requestAccess (%lu, %d) Offline", version, check);
		return Error::Offline;
	}

	constexpr size_t currversion = parseModuleVersion(xStringify(MODULE_VERSION));
	if (version > currversion) {
		DBGLOG("api", "] LiluAPI::requestAccess (%lu, %d) UnsupportedFeature", version, check);
		return Error::UnsupportedFeature;
	}

	if (check) {
		if (!IOLockTryLock(access)) {
			DBGLOG("api", "] LiluAPI::requestAccess (%lu, %d) LockError", version, check);
			return Error::LockError;
		}
	} else {
		IOLockLock(access);
	}

	if (apiRequestsOver) {
		IOLockUnlock(access);
		DBGLOG("api", "] LiluAPI::requestAccess (%lu, %d) TooLate", version, check);
		return Error::TooLate;
	}

	DBGLOG("api", "] LiluAPI::requestAccess (%lu, %d) NoError", version, check);
	return Error::NoError;
}

LiluAPI::Error LiluAPI::releaseAccess() {
	IOLockUnlock(access);
	return Error::NoError;
}

LiluAPI::Error LiluAPI::shouldLoad(const char *product, size_t version, uint32_t runmode, const char **disableArg, size_t disableArgNum, const char **debugArg, size_t debugArgNum, const char **betaArg, size_t betaArgNum, KernelVersion min, KernelVersion max, bool &printDebug) {

	DBGLOG("api", "got load request from %s (%lu)", product, version);

	printDebug = false;

	if (!(runmode & currentRunMode))
		return Error::Disabled;

	for (size_t i = 0; i < disableArgNum; i++) {
		if (checkKernelArgument(disableArg[i]))
			return Error::Disabled;
	}

	if (!KernelPatcher::compatibleKernel(min, max)) {
		bool beta = ADDPR(config).betaForAll;

		for (size_t i = 0; i < betaArgNum && !beta; i++) {
			if (checkKernelArgument(betaArg[i]))
				beta = true;
		}

		if (!beta) {
			SYSLOG("api", "automatically disabling %s (%lu) on an unsupported operating system", product, version);
			return Error::IncompatibleOS;
		} else {
			SYSLOG("api", "force enabling %s (%lu) on an unsupported operating system due to beta flag", product, version);
		}
	}

	if (ADDPR(config).debugForAll) {
		printDebug = true;
	} else {
		for (size_t i = 0; i < debugArgNum; i++) {
			if (checkKernelArgument(debugArg[i])) {
				printDebug = true;
				break;
			}
		}
	}

	return Error::NoError;
}

LiluAPI::Error LiluAPI::onPatcherLoad(t_patcherLoaded callback, void *user) {
	auto *pcall = stored_pair<t_patcherLoaded>::create();

	if (!pcall) {
		SYSLOG("api", "failed to allocate memory for stored_pair<t_patcherLoaded>");
		return Error::MemoryError;
	}

	pcall->first = callback;
	pcall->second = user;

	if (!patcherLoadedCallbacks.push_back<2>(pcall)) {
		SYSLOG("api", "failed to store stored_pair<t_patcherLoaded>");
		stored_pair<t_patcherLoaded>::deleter(pcall);
		return Error::MemoryError;
	}

	return Error::NoError;
}

LiluAPI::Error LiluAPI::onKextLoad(KernelPatcher::KextInfo *infos, size_t num, t_kextLoaded callback, void *user) {
	// Store the callbacks first
	if (callback) {
		auto *pcall = stored_pair<t_kextLoaded>::create();

		if (!pcall) {
			SYSLOG("api", "failed to allocate memory for stored_pair<t_kextLoaded>");
			return Error::MemoryError;
		}

		pcall->first = callback;
		pcall->second = user;

		if (!kextLoadedCallbacks.push_back<4>(pcall)) {
			SYSLOG("api", "failed to store stored_pair<t_kextLoaded>");
			stored_pair<t_kextLoaded>::deleter(pcall);
			return Error::MemoryError;
		}
	}

	// Store the kexts next
	if (infos) {
		auto *pkext = stored_pair<KernelPatcher::KextInfo *, size_t>::create();

		if (!pkext) {
			SYSLOG("api", "failed to allocate memory for stored_pair<KextInfo>");
			return Error::MemoryError;
		}

		pkext->first = infos;
		pkext->second = num;

		if (!storedKexts.push_back<4>(pkext)) {
			SYSLOG("api", "failed to store stored_pair<KextInfo>");
			stored_pair<KernelPatcher::KextInfo *, size_t>::deleter(pkext);
			return Error::MemoryError;
		}
	}

	return Error::NoError;
}

LiluAPI::Error LiluAPI::onProcLoad(UserPatcher::ProcInfo *infos, size_t num, UserPatcher::t_BinaryLoaded callback, void *user, UserPatcher::BinaryModInfo *mods, size_t modnum) {
	// We do not officially support user patcher prior to 10.9, yet it seems to partially work

	DBGLOG("api", "[ LiluAPI::onProcLoad");
	// Store the callbacks
	if (callback) {
		auto *pcall = stored_pair<UserPatcher::t_BinaryLoaded>::create();

		if (!pcall) {
			SYSLOG("api", "failed to allocate memory for stored_pair<t_binaryLoaded>");
			DBGLOG("api", "] LiluAPI::onProcLoad MemoryError");
			return Error::MemoryError;
		}

		pcall->first = callback;
		pcall->second = user;

		if (!binaryLoadedCallbacks.push_back<2>(pcall)) {
			SYSLOG("api", "failed to store stored_pair<t_binaryLoaded>");
			stored_pair<UserPatcher::t_BinaryLoaded>::deleter(pcall);
			DBGLOG("api", "] LiluAPI::onProcLoad MemoryError");
			return Error::MemoryError;
		}
		else {
			DBGLOG("api", "stored callback");
		}
	}

	// Filter disabled processes right away and store the rest
	for (size_t i = 0; i < num; i++) {
		if (infos[i].section != UserPatcher::ProcInfo::SectionDisabled) {
			if (!storedProcs.push_back<2>(&infos[i])) {
				SYSLOG("api", "failed to store ProcInfo");
				DBGLOG("api", "] LiluAPI::onProcLoad MemoryError");
				return Error::MemoryError;
			}
			else {
				DBGLOG("api", "stored ProcInfo[%d]: path:\"%s\"", (int)i, infos[i].path);
			}
		}
	}

	// Store all the binary mods
	for (size_t i = 0; i < modnum; i++) {
		if (!storedBinaryMods.push_back<2>(&mods[i])) {
			SYSLOG("api", "failed to store BinaryModInfo");
			DBGLOG("api", "] LiluAPI::onProcLoad MemoryError");
			return Error::MemoryError;
		}
		else {
			DBGLOG("api", "stored BinaryModInfo[%d]: path:\"%s\"", (int)i, mods[i].path);
		}
	}

	DBGLOG("api", "] LiluAPI::onProcLoad NoError");
	return Error::NoError;
}

LiluAPI::Error LiluAPI::onEntitlementRequest(t_entitlementRequested callback, void *user) {
	auto *ecall = stored_pair<t_entitlementRequested>::create();

	if (!ecall) {
		SYSLOG("api", "failed to allocate memory for stored_pair<t_entitlementRequested>");
		return Error::MemoryError;
	}

	ecall->first = callback;
	ecall->second = user;

	if (!entitlementRequestedCallbacks.push_back<2>(ecall)) {
		SYSLOG("api", "failed to store stored_pair<t_entitlementRequested>");
		stored_pair<t_entitlementRequested>::deleter(ecall);
		return Error::MemoryError;
	}

	return Error::NoError;
}

void LiluAPI::finaliseRequests() {
	// Block any new requests
	DBGLOG("api", "[ LiluAPI::finaliseRequests");

	IOLockLock(access);
	apiRequestsOver = true;
	DBGLOG("api", "LiluAPI::finaliseRequests apiRequestsOver = true");
	IOLockUnlock(access);
	DBGLOG("api", "] LiluAPI::finaliseRequests");
}

void LiluAPI::processPatcherLoadCallbacks(KernelPatcher &patcher) {
	DBGLOG("api", "[ LiluAPI::processPatcherLoadCallbacks 0x%llX", (uint64_t)&patcher);
	// Process the callbacks
	for (size_t i = 0; i < patcherLoadedCallbacks.size(); i++) {
		auto p = patcherLoadedCallbacks[i];
		p->first(p->second, patcher);
	}

	if (entitlementRequestedCallbacks.size() > 0) {
		KernelPatcher::RouteRequest req{"__ZN12IOUserClient21copyClientEntitlementEP4taskPKc", copyClientEntitlement, orgCopyClientEntitlement};
		if (!patcher.routeMultiple(KernelPatcher::KernelID, &req, 1))
			SYSLOG("api", "failed to hook copy user entitlement");
	}

#ifdef LILU_KEXTPATCH_SUPPORT
	// Queue the kexts we are in need of waiting
	for (size_t i = 0; i < storedKexts.size(); i++) {
		auto stored = storedKexts[i];
		for (size_t j = 0; j < stored->second; j++) {
			if (stored->first[j].sys[KernelPatcher::KextInfo::Disabled])
				continue;

			if (stored->first[j].sys[KernelPatcher::KextInfo::FSOnly] && stored->first[j].pathNum == 0) {
				SYSLOG("api", "improper request with 0 paths for %s kext", stored->first[j].id);
				continue;
			}

			patcher.loadKinfo(&stored->first[j]);
			auto error = patcher.getError();
			if (error != KernelPatcher::Error::NoError) {
				patcher.clearError();
				if (error == KernelPatcher::Error::AlreadyDone) {
					if (stored->first[j].sys[KernelPatcher::KextInfo::Loaded] ||
						stored->first[j].sys[KernelPatcher::KextInfo::Reloadable]) {
						DBGLOG("api", "updating new kext handler features");
						patcher.updateKextHandlerFeatures(&stored->first[j]);
					}
				} else if (error != KernelPatcher::Error::Unsupported) {
					SYSLOG_COND(ADDPR(debugEnabled), "api", "failed to load %s kext file", stored->first[j].id);
				}

				// Depending on a system some kexts may actually not exist
				continue;
			}

			patcher.setupKextListening();

			if (patcher.getError() != KernelPatcher::Error::NoError) {
				SYSLOG("api", "failed to setup kext hooking");
				patcher.clearError();
				i = storedKexts.size();
				break;
			}

			auto handler = KernelPatcher::KextHandler::create(stored->first[j].id, stored->first[j].loadIndex,
			[](KernelPatcher::KextHandler *h) {
				if (h)
					lilu.processKextLoadCallbacks(*static_cast<KernelPatcher *>(h->self), h->index, h->address, h->size, h->reloadable);
				else
					SYSLOG("api", "kext notification callback arrived at nowhere");
			}, stored->first[j].sys[KernelPatcher::KextInfo::Loaded], stored->first[j].sys[KernelPatcher::KextInfo::Reloadable]);

			if (!handler) {
				SYSLOG("api", "failed to allocate KextHandler for %s", stored->first[j].id);
				i = storedKexts.size();
				break;
			}

			handler->self = &patcher;

			patcher.waitOnKext(handler);

			if (patcher.getError() != KernelPatcher::Error::NoError) {
				SYSLOG("api", "failed to wait on kext %s", stored->first[j].id);
				patcher.clearError();
				KernelPatcher::KextHandler::deleter(handler);
				i = storedKexts.size();
				break;
			}
		}
	}
#endif

	// We no longer need to load kexts, forget about prelinked
	patcher.freeFileBufferResources();

	DBGLOG("api", "] LiluAPI::processPatcherLoadCallbacks");
}

void LiluAPI::processKextLoadCallbacks(KernelPatcher &patcher, size_t id, mach_vm_address_t slide, size_t size, bool reloadable) {
	// Update running info
	DBGLOG("api", "[ LiluAPI::processKextLoadCallbacks");
	size = patcher.updateRunningInfo(id, slide, size, reloadable);

	// Process the callbacks
	for (size_t i = 0; i < kextLoadedCallbacks.size(); i++) {
		auto p = kextLoadedCallbacks[i];
		p->first(p->second, patcher, id, slide, size);
	}
	DBGLOG("api", "] LiluAPI::processKextLoadCallbacks");
}

void LiluAPI::processUserLoadCallbacks(UserPatcher &patcher) {
	DBGLOG("api", "[ LiluAPI::processUserLoadCallbacks");
	if (storedProcs.size() == 0 && storedBinaryMods.size() == 0) {
		DBGLOG("api", "] LiluAPI::processUserLoadCallbacks (no storedProcs)");
		return;
	}

	size_t i = 0;
	while (i < storedProcs.size()) {
		if (storedProcs[i]->section == UserPatcher::ProcInfo::SectionDisabled)
			storedProcs.erase(i);
		else
			i++;
	}

	if (!patcher.registerPatches(storedProcs.data(), storedProcs.size(), storedBinaryMods.data(), storedBinaryMods.size(),
		[](void *user, UserPatcher &patcher, vm_map_t map, const char *path, size_t len) {
			auto api = static_cast<LiluAPI *>(user);
			api->processBinaryLoadCallbacks(patcher, map, path, len);
		}, this)) {
		SYSLOG("api", "failed to register user patches");
	}
	DBGLOG("api", "] LiluAPI::processUserLoadCallbacks");
}

void LiluAPI::processBinaryLoadCallbacks(UserPatcher &patcher, vm_map_t map, const char *path, size_t len) {
	// Process the callbacks
	DBGLOG("api", "[ LiluAPI::processBinaryLoadCallbacks");
	for (size_t i = 0; i < binaryLoadedCallbacks.size(); i++) {
		auto p = binaryLoadedCallbacks[i];
		p->first(p->second, patcher, map, path, len);
	}
	DBGLOG("api", "] LiluAPI::processBinaryLoadCallbacks");
}

OSObject *LiluAPI::copyClientEntitlement(task_t task, const char *entitlement) {
	if (lilu.orgCopyClientEntitlement) {
		auto obj = lilu.orgCopyClientEntitlement(task, entitlement);
		auto &callbacks = lilu.entitlementRequestedCallbacks;
		for (size_t i = 0, sz = callbacks.size(); i < sz; i++)
			callbacks[i]->first(callbacks[i]->second, task, entitlement, obj);
		return obj;
	}

	SYSLOG("api", "copy client entitlement arrived at nowhere");
	return nullptr;
}

void LiluAPI::activate(KernelPatcher &kpatcher, UserPatcher &upatcher) {
	kpatcher.activate();
	upatcher.activate();
}
