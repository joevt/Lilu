//
//  kern_start.cpp
//  Lilu
//
//  Copyright © 2016-2017 vit9696. All rights reserved.
//

#include <Headers/kern_config.hpp>
#include <PrivateHeaders/kern_config.hpp>
#include <PrivateHeaders/kern_start.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_efi.hpp>
#include <Headers/kern_devinfo.hpp>
#include <Headers/kern_cpu.hpp>
#include <Headers/kern_file.hpp>
#include <Headers/kern_time.hpp>
#include <Headers/kern_version.hpp>

#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>

#include <mach/mach_types.h>

OSDefineMetaClassAndStructors(PRODUCT_NAME, IOService)

#if defined(__i386__)
kauth_listener_t kauth_listener_vnode;
extern "C" int kauth_callback(kauth_cred_t credential, void *idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
	kauth_unlisten_scope(kauth_listener_vnode);
	ADDPR(config).policyInit("kauth_listen: " KAUTH_SCOPE_VNODE);
	
	return KAUTH_RESULT_ALLOW;
}
#endif

IOService *PRODUCT_NAME::probe(IOService *provider, SInt32 *score) {
	DBGLOG("init", "[ %s::probe", xStringify(PRODUCT_NAME));
	setProperty("VersionInfo", kextVersion);
	auto service = IOService::probe(provider, score);
	IOService *result = ADDPR(config).startSuccess ? service : nullptr;
	DBGLOG("init", "] %s::probe result:0x%llX", xStringify(PRODUCT_NAME), (uint64_t)result);
	return result;
}

bool PRODUCT_NAME::start(IOService *provider) {
	DBGLOG("init", "[ %s::start", xStringify(PRODUCT_NAME));
	if (!IOService::start(provider)) {
		SYSLOG("init", "failed to start the parent");
		DBGLOG("init", "] %s::start result:%d", xStringify(PRODUCT_NAME), false);
		return false;
	}
	
#if defined(__i386__)
	// Use a kauth listener on 32-bit platforms to detect root mount.
	if (ADDPR(config).startSuccess) {
		kauth_listener_vnode = kauth_listen_scope(KAUTH_SCOPE_VNODE, kauth_callback, NULL);
		if (!kauth_listener_vnode) {
			SYSLOG("init", "failed to register kauth listener");
			DBGLOG("init", "] %s::start result:%d", xStringify(PRODUCT_NAME), false);
			return false;
		}
	}
#endif

	DBGLOG("init", "] %s::start result:%d", xStringify(PRODUCT_NAME), ADDPR(config).startSuccess);
	return ADDPR(config).startSuccess;
}

void PRODUCT_NAME::stop(IOService *provider) {
	IOService::stop(provider);
}

Configuration ADDPR(config);


static bool * disable_serial_output = NULL;
static bool * disable_iolog_serial_output = NULL;
static unsigned int * debug_boot_arg = NULL;

static bool log_PE_parse_boot_argn = false;
static int log_to_kprintf = 0;

bool Configuration::performEarlyInit() {
	DBGLOG("config", "[ Configuration::performEarlyInit");
	kernelPatcher.init();

	if (kernelPatcher.getError() != KernelPatcher::Error::NoError) {
		DBGLOG("config", "failed to initialise kernel patcher");
		kernelPatcher.deinit();
		kernelPatcher.clearError();
		DBGLOG("config", "] Configuration::performEarlyInit false");
		return false;
	}
	if (!debug_boot_arg)              debug_boot_arg              = reinterpret_cast<unsigned int *>(kernelPatcher.solveSymbol(kernelPatcher.KernelID, "_debug_boot_arg"              ));
	if (!disable_serial_output)       disable_serial_output       = reinterpret_cast<        bool *>(kernelPatcher.solveSymbol(kernelPatcher.KernelID, "_disable_serial_output"       ));
	if (!disable_iolog_serial_output) disable_iolog_serial_output = reinterpret_cast<        bool *>(kernelPatcher.solveSymbol(kernelPatcher.KernelID, "_disable_iolog_serial_output" ));

	DBGLOG("config", "debug_boot_arg:0x%x%s disable_serial_output:%s disable_iolog_serial_output:%s",
		debug_boot_arg ? *debug_boot_arg : 0,
		debug_boot_arg ? "" : " = NULL",
		disable_serial_output ? *disable_serial_output ? "true" : "false" : "NULL",
		disable_iolog_serial_output ? *disable_iolog_serial_output ? "true" : "false" : "NULL"
	);
	
	log_PE_parse_boot_argn = checkKernelArgument("-logbootarg");
	lilu_get_boot_args("logtokprintf", &log_to_kprintf, sizeof(log_to_kprintf));
	
	KernelPatcher::RouteRequest requests[] = {
		{"_PE_initialize_console", wrap_PE_initialize_console, org_PE_initialize_console},
		{"_PE_parse_boot_argn", wrap_PE_parse_boot_argn, org_PE_parse_boot_argn},
		{"_serial_init", wrap_serial_init, org_serial_init},
		{"_console_write", wrap_console_write, org_console_write},
		{"_console_printbuf_putc", wrap_console_printbuf_putc, org_console_printbuf_putc},
	};
	
	if (!kernelPatcher.routeMultiple(KernelPatcher::KernelID, requests, arrsize(requests), 0, 0, true, false)) {
		SYSLOG("config", "failed to initialise through console routing");
		kernelPatcher.deinit();
		kernelPatcher.clearError();
		DBGLOG("config", "] Configuration::performEarlyInit false");
		return false;
	}

	if (org_serial_init) {
		wrap_serial_init();
	}
	
	DBGLOG("config", "] Configuration::performEarlyInit true");
	return true;
}

int Configuration::wrap_PE_initialize_console(PE_Video *info, int op) {
	DBGLOG("config", "PE_initialize_console %d", op);
	if (op == kPEEnableScreen && !atomic_load_explicit(&ADDPR(config).initialised, memory_order_relaxed)) {
		IOLockLock(ADDPR(config).policyLock);
		if (!atomic_load_explicit(&ADDPR(config).initialised, memory_order_relaxed)) {
			DBGLOG("config", "[ Configuration::wrap_PE_initialize_console %d performing init", op);

			// Complete plugin registration and mark ourselves as loaded ahead of time to avoid race conditions.
			lilu.finaliseRequests();
			atomic_store_explicit(&ADDPR(config).initialised, true, memory_order_relaxed);

			// Fire plugin init in the thread to avoid colliding with PCI configuration.
			auto thread = thread_call_allocate([](thread_call_param_t, thread_call_param_t thread) {
				ADDPR(config).performCommonInit();
				thread_call_free(static_cast<thread_call_t>(thread));
			}, nullptr);
			if (thread)
				thread_call_enter1(thread, thread);

			DBGLOG("config", "] Configuration::wrap_PE_initialize_console");
		}
		IOLockUnlock(ADDPR(config).policyLock);
	}
	return FunctionCast(wrap_PE_initialize_console, ADDPR(config).org_PE_initialize_console)(info, op);
}

boolean_t Configuration::wrap_PE_parse_boot_argn(const char *arg_string, void *arg_ptr, int max_arg) {
	boolean_t result = FunctionCast(wrap_PE_parse_boot_argn, ADDPR(config).org_PE_parse_boot_argn)(arg_string, arg_ptr, max_arg);
	if (log_PE_parse_boot_argn && arg_string && strcmp("ioimageloader.logging", arg_string)) {
		DBGLOG("config", "PE_parse_boot_argn \"%s\" size:%d result:%s", arg_string, max_arg, result ? "true" : "false");
	}
	return result;
}

int Configuration::wrap_serial_init( void ) {
	int result = FunctionCast(wrap_serial_init, ADDPR(config).org_serial_init)();
	DBGLOG("config", "[] serial_init result:%d", result);
	return result;
}

void Configuration::wrap_console_write(char *str, int size) {
	FunctionCast(wrap_console_write, ADDPR(config).org_console_write)(str, size);
	if (log_to_kprintf == 1)
		kprintf("%.*s", size, str);
}

void Configuration::wrap_console_printbuf_putc(int ch, void * arg) {
	FunctionCast(wrap_console_printbuf_putc, ADDPR(config).org_console_printbuf_putc)(ch, arg);
	if (log_to_kprintf == 2 && PE_kputc)
		PE_kputc(ch);
}

/*
We can affect the start time of Lilu::start by changing IOResourceMatch in Info.plist.
- Sometimes UserPatcher::loadFilesForPatching (started by kern_start below) happens too early and a panic occurs: "thread wants credential but has no BSD process"
- IOResourceMatch "IOBSD" is too early to have rootvnode (required for UserPatcher::loadFilesForPatching)
- IOResourceMatch "boot-uuid-media" is also too early
- IOResourceMatch "IOConsoleUsers" is too late - WindowServer has already loaded
To solve this, we trap serial_keyboard_init or graftdmg in performCommonInit - it happens very early but not too early; rootvnode will have been initialized by bsd_init by that time.
*/

static bool userReady = false;
static bool userActivated = false;
static void ** rootvnodePtr = NULL; // set before wrap_serial_keyboard_init is called; don't use "extern struct vnode *rootvnode" because it is not exported by any dependencies listed in Info.plist

void Configuration::wrap_serial_keyboard_init(void) {
	DBGLOG("config", "[ Configuration::wrap_serial_keyboard_init");
	FunctionCast(wrap_serial_keyboard_init, ADDPR(config).org_serial_keyboard_init)();
	
	if (!ADDPR(config).org_graftdmg) {
		IOLockLock(ADDPR(config).policyLock);
		ADDPR(config).processUserLoadCallbacks();
		IOLockUnlock(ADDPR(config).policyLock);
	}
	
	DBGLOG("config", "] Configuration::wrap_serial_keyboard_init");
}

int Configuration::wrap_graftdmg(proc_t p, struct graftdmg_args* uap, int32_t* retval) {
	DBGLOG("config", "[ Configuration::wrap_graftdmg");
	int result = FunctionCast(wrap_graftdmg, ADDPR(config).org_graftdmg)(p, uap, retval);

	IOLockLock(ADDPR(config).policyLock);
	ADDPR(config).processUserLoadCallbacks();
	IOLockUnlock(ADDPR(config).policyLock);

	DBGLOG("config", "] Configuration::wrap_graftdmg result:%d", result);
	return result;
}

void Configuration::processUserLoadCallbacks() {
	// given: we have policyLock
	if (userReady && !userActivated) {
		if (!rootvnodePtr) {
			rootvnodePtr = reinterpret_cast<void **>(kernelPatcher.solveSymbol(kernelPatcher.KernelID, "_rootvnode" ));
		}
		if (rootvnodePtr && *rootvnodePtr) {
			userActivated = true;
			lilu.processUserLoadCallbacks(userPatcher);
			userPatcher.activate();
		}
	}
}

bool Configuration::performCommonInit() {
	DBGLOG("config", "[ Configuration::performCommonInit");

	{
		KernelPatcher::RouteRequest requests[] = {
			{"_serial_keyboard_init", wrap_serial_keyboard_init, org_serial_keyboard_init},
		};
		if (!kernelPatcher.routeMultiple(KernelPatcher::KernelID, requests, arrsize(requests), 0, 0, true, false)) {
			SYSLOG("config", "failed to patch serial_keyboard_init for user patching");
			kernelPatcher.clearError();
		}
	}

	{
		KernelPatcher::RouteRequest requests[] = {
			{"_graftdmg", wrap_graftdmg, org_graftdmg}
		};
		if (!kernelPatcher.routeMultiple(KernelPatcher::KernelID, requests, arrsize(requests), 0, 0, true, false)) {
			SYSLOG("config", "failed to patch graftdmg for user patching");
			kernelPatcher.clearError();
		}
	}

	DeviceInfo::createCached();

	lilu.processPatcherLoadCallbacks(kernelPatcher);

	bool ok = userPatcher.init(kernelPatcher, preferSlowMode);
	if (ok) {
		// We are safely locked, just need to ensure atomicity
		atomic_store_explicit(&initialised, true, memory_order_relaxed);
	} else {
		DBGLOG("config", "initialisation failed");
		userPatcher.deinit();
		kernelPatcher.deinit();
		kernelPatcher.clearError();
		DBGLOG("config", "] Configuration::performCommonInit false");
		return false;
	}

	kernelPatcher.activate();

	userReady = true;
	processUserLoadCallbacks();

	DBGLOG("config", "] Configuration::performCommonInit true");
	return true;
}

bool Configuration::performInit() {
	DBGLOG("config", "[ Configuration::performInit");
	kernelPatcher.init();

	if (kernelPatcher.getError() != KernelPatcher::Error::NoError) {
		DBGLOG("config", "failed to initialise kernel patcher");
		kernelPatcher.deinit();
		kernelPatcher.clearError();
		DBGLOG("config", "] Configuration::performInit false");
		return false;
	}

	lilu.finaliseRequests();

	bool result = performCommonInit();
	DBGLOG("config", "] Configuration::performInit %d", result);
	return result;
}

#if defined(__x86_64__)
int Configuration::policyCheckRemount(kauth_cred_t, mount *, label *) {
	DBGLOG("config", "Configuration::policyCheckRemount");
	ADDPR(config).policyInit("mac_mount_check_remount");
	return 0;
}

int Configuration::policyCredCheckLabelUpdateExecve(kauth_cred_t, vnode_t, ...) {
	//DBGLOG("config", "Configuration::policyCredCheckLabelUpdateExecve"); // this is called too often in Catalina
	ADDPR(config).policyInit("mac_cred_check_label_update_execve");
	return 0;
}

void Configuration::policyInitBSD(mac_policy_conf *conf) {
	DBGLOG("config", "Configuration::policyInitBSD kernelVersion:%u installOrRecovery:%d", getKernelVersion(), ADDPR(config).installOrRecovery);
	if (getKernelVersion() >= KernelVersion::BigSur)
		ADDPR(config).policyInit("init bsd");
}
#endif

#ifdef DEBUG

void Configuration::initCustomDebugSupport() {
	if (debugDumpTimeout == 0)
		return;

	if (!debugBuffer)
		debugBuffer = Buffer::create<uint8_t>(MaxDebugBufferSize);

	if (!debugLock)
		debugLock = IOSimpleLockAlloc();

	if (debugBuffer && debugLock) {
		if (debugDumpCall) {
			while (!thread_call_free(debugDumpCall))
				thread_call_cancel(debugDumpCall);
			debugDumpCall = nullptr;
		}

		debugDumpCall = thread_call_allocate(saveCustomDebugOnDisk, nullptr);
		if (debugDumpCall) {
			uint64_t deadlineNs = convertScToNs(debugDumpTimeout);
			uint64_t deadlineAbs = 0;
			nanoseconds_to_absolutetime(deadlineNs, &deadlineAbs);
			thread_call_enter_delayed(debugDumpCall, mach_absolute_time() + deadlineAbs);
			return;
		}
	}

	if (debugBuffer) {
		Buffer::deleter(debugBuffer);
		debugBuffer = nullptr;
	}

	if (debugLock) {
		IOSimpleLockFree(debugLock);
		debugLock = nullptr;
	}
}

void Configuration::saveCustomDebugOnDisk(thread_call_param_t, thread_call_param_t) {
	UserPatcher::dumpCounters();
	if (ADDPR(config).debugLock && ADDPR(config).debugBuffer) {
		auto logBuf = Buffer::create<uint8_t>(MaxDebugBufferSize);
		if (logBuf) {
			size_t logBufSize = 0;
			IOSimpleLockLock(ADDPR(config).debugLock);
			logBufSize = ADDPR(config).debugBufferLength;
			if (logBufSize > 0)
				lilu_os_memcpy(logBuf, ADDPR(config).debugBuffer, logBufSize);
			IOSimpleLockUnlock(ADDPR(config).debugLock);

			if (logBufSize > 0) {
				char name[64];
				snprintf(name, sizeof(name), "/var/log/Lilu_" xStringify(MODULE_VERSION) "_%d.%d.txt", getKernelVersion(), getKernelMinorVersion());
				FileIO::writeBufferToFile(name, logBuf, logBufSize);
			}

			Buffer::deleter(logBuf);
		}
	}

	thread_call_free(ADDPR(config).debugDumpCall);
	ADDPR(config).debugDumpCall = nullptr;
}

#endif

bool Configuration::getBootArguments() {
	DBGLOG("config", "[ Configuration::getBootArguments disabled:%d", isDisabled);
	if (readArguments) {
		DBGLOG("config", "] Configuration::getBootArguments result:%d", !isDisabled);
		return !isDisabled;
	}

	isDisabled = false;

	betaForAll = checkKernelArgument(bootargBetaAll);
	debugForAll = checkKernelArgument(bootargDebugAll);
	isUserDisabled = checkKernelArgument(bootargUserOff) ||
		getKernelVersion() <= KernelVersion::SnowLeopard; // || getKernelVersion() >= KernelVersion::BigSur;

	lilu_get_boot_args(bootargDelay, &ADDPR(debugPrintDelay), sizeof(ADDPR(debugPrintDelay)));

#ifdef DEBUG
	lilu_get_boot_args(bootargDump, &debugDumpTimeout, sizeof(debugDumpTimeout));
	// Slightly out of place, but we need to do that as early as possible.
	initCustomDebugSupport();
#endif

	isDisabled |= checkKernelArgument(bootargOff);
	if (!checkKernelArgument(bootargForce)) {
		isDisabled |= checkKernelArgument("-s");

		if (!KernelPatcher::compatibleKernel(minKernel, maxKernel)) {
			if (!betaForAll && !checkKernelArgument(bootargBeta)) {
				SYSLOG("config", "automatically disabling on an unsupported operating system");
				isDisabled = true;
			} else if (!isDisabled) {
				SYSLOG("config", "force enabling on an unsupported operating system due to beta flag");
			}
		}
	} else if (!isDisabled) {
		SYSLOG("config", "force enabling due to force flag");
	}

	ADDPR(debugEnabled) = debugForAll;
	ADDPR(debugEnabled) |= checkKernelArgument(bootargDebug);
	DBGLOG("config", "%s set to %d", xStringify(ADDPR(debugEnabled)), ADDPR(debugEnabled));

	allowDecompress = !checkKernelArgument(bootargLowMem);

	auto entry = IORegistryEntry::fromPath("/chosen", gIODTPlane);
	if (entry) {
		installOrRecovery = entry->getProperty("boot-ramdmg-extents") != nullptr;
		entry->release();
	}
	
	if (!installOrRecovery) {
		installOrRecovery |= checkKernelArgument("rp0");
		installOrRecovery |= checkKernelArgument("rp");
		installOrRecovery |= checkKernelArgument("container-dmg");
		installOrRecovery |= checkKernelArgument("root-dmg");
		installOrRecovery |= checkKernelArgument("auth-root-dmg");
	}

	safeMode = checkKernelArgument("-x");

	preferSlowMode = getKernelVersion() <= KernelVersion::Mavericks || installOrRecovery;

	if (checkKernelArgument(bootargSlow)) {
		preferSlowMode = true;
	} else if (checkKernelArgument(bootargFast)) {
		preferSlowMode = false;
	}

	if (!preferSlowMode && getKernelVersion() <= KernelVersion::Mavericks) {
		// Since vm_shared_region_map_file interface is a little different
		if (!isDisabled) SYSLOG("config", "enforcing -liluslow on Mavericks and lower");
		preferSlowMode = true;
	}

	if (!preferSlowMode && installOrRecovery) {
		// Since vdyld shared cache is not available
		if (!isDisabled) SYSLOG("config", "enforcing -liluslow in installer or recovery");
		preferSlowMode = true;
	}

	readArguments = true;

	DBGLOG("config", "version %s (%s), args: disabled %d, debug %d, slow %d, decompress %d",
		   kextVersion, currentArch, isDisabled, ADDPR(debugEnabled), preferSlowMode, allowDecompress);

	if (isDisabled) {
		SYSLOG("config", "found a disabling argument or no arguments, exiting");
	} else {
#if defined(__x86_64__)
		// Decide on booter
		if (!preferSlowMode) {
			policyOps.mpo_cred_check_label_update_execve = reinterpret_cast<mpo_cred_check_label_update_execve_t *>(policyCredCheckLabelUpdateExecve);
		} else {
			policyOps.mpo_mount_check_remount = policyCheckRemount;
		}
#endif
	}

	DBGLOG("config", "] Configuration::getBootArguments result:%d", !isDisabled);
	return !isDisabled;
}

bool Configuration::registerPolicy() {
	DBGLOG("config", "[ Configuration::registerPolicy");

	policyLock = IOLockAlloc();

	if (policyLock == nullptr) {
		SYSLOG("config", "failed to alloc policy lock");
		DBGLOG("config", "] Configuration::registerPolicy false");
		return false;
	}

#if defined(__x86_64__)
	if (getKernelVersion() >= KernelVersion::BigSur) {
		if (performEarlyInit()) {
			startSuccess = true;
			DBGLOG("config", "] Configuration::registerPolicy true");
			return true;
		} else {
			SYSLOG("config", "failed to perform early init");
		}
	}

	if (!policy.registerPolicy()) {
		SYSLOG("config", "failed to register the policy");
		IOLockFree(policyLock);
		policyLock = nullptr;
		DBGLOG("config", "] Configuration::registerPolicy false");
		return false;
	}
#endif

	startSuccess = true;

	DBGLOG("config", "] Configuration::registerPolicy true");
	return true;
}

extern "C" kern_return_t ADDPR(kern_start)(kmod_info_t *, void *) {
	DBGLOG("init", "[ %s", xStringify(ADDPR(kern_start)));
	if (ADDPR(config).getBootArguments()) {
		// Make EFI runtime services available now, since they are standalone.
		EfiRuntimeServices::activate();
		// Init basic device information.
		BaseDeviceInfo::init();
		// Init Lilu API.
		lilu.init();

		ADDPR(config).registerPolicy();
	}

	DBGLOG("init", "] %s", xStringify(ADDPR(kern_start)));
	return KERN_SUCCESS;
}

extern "C" kern_return_t ADDPR(kern_stop)(kmod_info_t *, void *) {
	return ADDPR(config).startSuccess ? KERN_FAILURE : KERN_SUCCESS;
}
