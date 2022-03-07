//
//  plugin_start.cpp
//  Lilu
//
//  Copyright © 2016-2017 vit9696. All rights reserved.
//

#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_version.hpp>

#ifndef LILU_CUSTOM_KMOD_INIT
bool ADDPR(startSuccess) = false;
#else
// Workaround custom kmod code and enable by default
bool ADDPR(startSuccess) = true;
#endif /* LILU_CUSTOM_KMOD_INIT */

bool ADDPR(debugEnabled) = false;
uint32_t ADDPR(debugPrintDelay) = 0;

#ifndef LILU_CUSTOM_IOKIT_INIT

OSDefineMetaClassAndStructors(PRODUCT_NAME, IOService)

PRODUCT_NAME *ADDPR(selfInstance) = nullptr;

IOService *PRODUCT_NAME::probe(IOService *provider, SInt32 *score) {
	DBGLOG("init", "[ %s::probe", xStringify(PRODUCT_NAME));
	ADDPR(selfInstance) = this;
	setProperty("VersionInfo", kextVersion);
	auto service = IOService::probe(provider, score);
	IOService *result = ADDPR(startSuccess) ? service : nullptr;
	DBGLOG("init", "] %s::probe result:%llx", xStringify(PRODUCT_NAME), (uint64_t)result);
	return result;
}

bool PRODUCT_NAME::start(IOService *provider) {
	DBGLOG("init", "[ %s::start", xStringify(PRODUCT_NAME));
	ADDPR(selfInstance) = this;
	if (!IOService::start(provider)) {
		SYSLOG("init", "failed to start the parent");
		DBGLOG("init", "] %s::start result:false", xStringify(PRODUCT_NAME));
		return false;
	}

	DBGLOG("init", "] %s::start result:%d", xStringify(PRODUCT_NAME), ADDPR(startSuccess));
	return ADDPR(startSuccess);
}

void PRODUCT_NAME::stop(IOService *provider) {
	ADDPR(selfInstance) = nullptr;
	IOService::stop(provider);
}

#endif /* LILU_CUSTOM_IOKIT_INIT */

#ifndef LILU_CUSTOM_KMOD_INIT

EXPORT extern "C" kern_return_t ADDPR(kern_start)(kmod_info_t *, void *) {
	// This is an ugly hack necessary on some systems where buffering kills most of debug output.

	DBGLOG("init", "[ %s", xStringify(ADDPR(kern_start)));

	lilu_get_boot_args("liludelay", &ADDPR(debugPrintDelay), sizeof(ADDPR(debugPrintDelay)));

	auto error = lilu.requestAccess();
	if (error == LiluAPI::Error::NoError) {
		error = lilu.shouldLoad(ADDPR(config).product, ADDPR(config).version, ADDPR(config).runmode, ADDPR(config).disableArg, ADDPR(config).disableArgNum,
								ADDPR(config).debugArg, ADDPR(config).debugArgNum, ADDPR(config).betaArg, ADDPR(config).betaArgNum, ADDPR(config).minKernel,
								ADDPR(config).maxKernel, ADDPR(debugEnabled));

		if (error == LiluAPI::Error::NoError) {
			SYSLOG("init", "%s bootstrap %s", xStringify(PRODUCT_NAME), kextVersion);
			(void)kextVersion;
			ADDPR(startSuccess) = true;
			ADDPR(config).pluginStart();
		} else {
			SYSLOG("init", "parent said we should not continue %d", error);
		}

		lilu.releaseAccess();
	} else {
		SYSLOG("init", "failed to call parent %d", error);
	}
	
	for (size_t i = 0; i < ADDPR(config).debugArgNum; i++) {
		if (checkKernelArgument(ADDPR(config).debugArg[i])) {
			DBGLOG("config", "%s set to %d because checkKernelArgument", xStringify(ADDPR(debugEnabled)), ADDPR(debugEnabled));
			ADDPR(debugEnabled) = true;
			break;
		}
	}

	if (checkKernelArgument("-liludbgall")) {
		ADDPR(debugEnabled) = true;
		DBGLOG("config", "%s set to %d because -liludbgall", xStringify(ADDPR(debugEnabled)), ADDPR(debugEnabled));
	}

	// Report success but actually do not start and let I/O Kit unload us.
	// This works better and increases boot speed in some cases.
	DBGLOG("init", "] %s KERN_SUCCESS", xStringify(ADDPR(kern_start)));
	return KERN_SUCCESS;
}

EXPORT extern "C" kern_return_t ADDPR(kern_stop)(kmod_info_t *, void *) {
	// It is not safe to unload Lilu plugins unless they were disabled!
	return ADDPR(startSuccess) ? KERN_FAILURE : KERN_SUCCESS;
}

#endif /* LILU_CUSTOM_KMOD_INIT */
