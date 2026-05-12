//
//  Jailbreaker.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOJailbreaker.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOUIManager.h"
#import <sys/stat.h>
#import <compression.h>
#import <xpf/xpf.h>
#import <dlfcn.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/primitives_IOSurface.h>
#import <libjailbreak/physrw_pte.h>
#import <libjailbreak/physrw.h>
#import <libjailbreak/translation.h>
#import <libjailbreak/kernel.h>
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/trustcache.h>
#import <libjailbreak/kalloc_pt.h>
#import <libjailbreak/jbserver_boomerang.h>
#import <libjailbreak/signatures.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/jbclient_mach.h>
#import <libjailbreak/kcall_arm64.h>
#import <libjailbreak/basebin_gen.h>
#import <CoreServices/LSApplicationProxy.h>
#import <sys/utsname.h>
// 增加了 wait
#import <sys/wait.h>
#import "spawn.h"

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

#define kCFPreferencesNoContainer CFSTR("kCFPreferencesNoContainer")
void _CFPreferencesSetValueWithContainer(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);

//char *_dirhelper(int a, char *dst, size_t size);

NSString *const JBErrorDomain = @"JBErrorDomain";
typedef NS_ENUM(NSInteger, JBErrorCode) {
    JBErrorCodeFailedToFindKernel            = -1,
    JBErrorCodeFailedKernelPatchfinding      = -2,
    JBErrorCodeFailedLoadingExploit          = -3,
    JBErrorCodeFailedExploitation            = -4,
    JBErrorCodeFailedBuildingPhysRW          = -5,
    JBErrorCodeFailedCleanup                 = -6,
    JBErrorCodeFailedGetRoot                 = -7,
    JBErrorCodeFailedUnsandbox               = -8,
    JBErrorCodeFailedPlatformize             = -9,
    JBErrorCodeFailedBasebinTrustcache       = -10,
    JBErrorCodeFailedLaunchdInjection        = -11,
    JBErrorCodeFailedInitProtection          = -12,
    JBErrorCodeFailedInitFakeLib             = -13,
    JBErrorCodeFailedDuplicateApps           = -14,
};

@implementation DOJailbreaker

- (NSError *)gatherSystemInformation
{
    NSString *kernelPath = [[DOEnvironmentManager sharedManager] accessibleKernelPath];
    if (!kernelPath) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedToFindKernel userInfo:@{NSLocalizedDescriptionKey:@"Failed to find kernelcache. Ensure your device is properly connected to the internet. If it still does not work, try installing Dopamine via TrollStore instead."}];
    NSLog(@"Kernel at %s", kernelPath.UTF8String);

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Patchfinding") debug:NO];

    int r = xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation);
    if (r == 0) {
        char *sets[99] = {
            "translation",
            "trustcache",
            "sandbox",
            "physmap",
            "struct",
            "physrw",
            "perfkrw",
            NULL,
            NULL,
            NULL,
            NULL,
        };

        uint32_t idx = 7;
        if (xpf_set_is_supported("devmode")) {
            sets[idx++] = "devmode";
        }
        if (xpf_set_is_supported("badRecovery")) {
            sets[idx++] = "badRecovery";
        }
        if (xpf_set_is_supported("arm64kcall")) {
            sets[idx++] = "arm64kcall";
        }


/********************** roothide *************************/
sets[idx++] = "namecache";

if (xpf_set_is_supported("amfi_oids")) {
    sets[idx++] = "amfi_oids";
}

sets[idx] = NULL;
/********************** roothide *************************/


        _systemInfoXdict = xpf_construct_offset_dictionary((const char **)sets);
        if (_systemInfoXdict) {
            xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticBase", gXPF.kernelBase);
            printf("System Info:\n");
            xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
                if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
                return true;
            });
        }
        if (!_systemInfoXdict) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF failed with error: (%s)", xpf_get_error()]}];
        }
        xpf_stop();
    }
    else {
        NSError *error = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF start failed with error: (%s)", xpf_get_error()]}];
        xpf_stop();
        return error;
    }

    jbinfo_initialize_dynamic_offsets(_systemInfoXdict);
    jbinfo_initialize_hardcoded_offsets();
    _systemInfoXdict = jbinfo_get_serialized();

    if (_systemInfoXdict) {
        printf("System Info libjailbreak:\n");
        xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
            if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                if (xpc_uint64_get_value(value)) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
            }
            return true;
        });
    }

    return nil;
}

- (NSError *)doExploitation
{
    DOExploit *kernelExploit = [DOExploitManager sharedManager].selectedKernelExploit;
    DOExploit *pacBypass = [DOExploitManager sharedManager].selectedPACBypass;
    DOExploit *pplBypass = [DOExploitManager sharedManager].selectedPPLBypass;
    if (!kernelExploit) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Kernel exploit is required but we did not find any"}];
    }
    if (!pacBypass && [DOEnvironmentManager sharedManager].isPACBypassRequired) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PAC bypass is required but we did not find any"}];
    }
    if (!pplBypass && [DOEnvironmentManager sharedManager].isPPLBypassRequired) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PPL bypass is required but we did not find any"}];
    }

    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Exploiting Kernel (%@)"), kernelExploit.name] debug:NO];
    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load kernel exploit: %s", dlerror()]}];
    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to exploit kernel"}];

    jbinfo_initialize_boot_constants();
    libjailbreak_translation_init();
    libjailbreak_IOSurface_primitives_init();

    if (pacBypass) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PAC (%@)"), pacBypass.name] debug:NO];
        if ([pacBypass load] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PAC bypass: %s", dlerror()]}];};
        if ([pacBypass run] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PAC"}];}
        // At this point we presume the PAC bypass has given us stable kcall primitives
        gSystemInfo.jailbreakInfo.usesPACBypass = true;
    }

    if ([[DOEnvironmentManager sharedManager] isPPLBypassRequired]) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PPL (%@)"), pplBypass.name] debug:NO];
        if ([pplBypass load] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PPL bypass: %s", dlerror()]}];};
        if ([pplBypass run] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PPL"}];}
        // At this point we presume the PPL bypass gave us unrestricted phys write primitives
    }
    if (!gPrimitives.kalloc_global) {
        // IOSurface kallocs don't work on iOS 16+, use leaked page tables as allocations instead
        libjailbreak_kalloc_pt_init();
    }

    if (![DOEnvironmentManager sharedManager].isArm64e) {
        arm64_kcall_init();
    }

    return nil;
}

- (NSError *)buildPhysRWPrimitive
{
    int r = -1;
    if (device_supports_physrw_pte()) {
        r = libjailbreak_physrw_pte_init(false, 0);
    }
    else {
        r = libjailbreak_physrw_init(false);
    }
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBuildingPhysRW userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to build phys r/w primitive: %d", r]}];
    }
    return nil;
}

- (NSError *)cleanUpExploits
{
    int r = [[DOExploitManager sharedManager] cleanUpExploits];
    if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedCleanup userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to cleanup exploits: %d", r]}];
    return nil;
}

- (NSError *)elevatePrivileges
{
    uint64_t proc = proc_self();
    uint64_t ucred = proc_ucred(proc);

    // Get uid 0
    kwrite32(proc + koffsetof(proc, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, ruid), 0);
    kwrite32(ucred + koffsetof(ucred, uid), 0);

    // Get gid 0
    kwrite32(proc + koffsetof(proc, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, rgid), 0);
    kwrite32(ucred + koffsetof(ucred, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, groups), 0);

    // Add P_SUGID
    uint32_t flag = kread32(proc + koffsetof(proc, flag));
    if ((flag & P_SUGID) != 0) {
        flag &= P_SUGID;
        kwrite32(proc + koffsetof(proc, flag), flag);
    }

    if (getuid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, uid still %d", getuid()]}];
    if (getgid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, gid still %d", getgid()]}];

    // Unsandbox
    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    mac_label_set(label, 1, -1);
    NSError *error = nil;
    [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&error];
    if (error) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedUnsandbox userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to unsandbox, /var does not seem accessible (%s)", error.description.UTF8String]}];
    setenv("HOME", "/var/root", true);
    setenv("CFFIXED_USER_HOME", "/var/root", true);
    setenv("TMPDIR", "/var/tmp", true);

    // FUCKING dirhelper caches the temporary path
    // So we have to do userland patchfinding to find the fucking string and overwrite it
    /*char **pain = NULL;
    uint32_t *dirhelperData = (uint32_t *)_dirhelper;
    for (int i = 0; i < 100; i++) {
        arm64_register destinationReg;
        uint64_t imm = 0;
        if (arm64_dec_ldr_imm(dirhelperData[i], &destinationReg, NULL, &imm, NULL, NULL) == 0) {
            if (ARM64_REG_GET_NUM(destinationReg) == 1) {
                uint32_t *adrpAddr = &dirhelperData[i - 1];
                uint64_t adrpTarget = 0;
                uint32_t adrpInst = *adrpAddr;
                if (arm64_dec_adr_p(adrpInst, (uint64_t)adrpAddr, &adrpTarget, NULL, NULL) == 0) {
                    pain = (char **)(uint64_t)(adrpTarget + imm);
                    break;
                }
            }
        }
    }
    *pain = strdup("/var/tmp");*/

    // Get CS_PLATFORM_BINARY
    proc_csflags_set(proc, CS_PLATFORM_BINARY);
    uint32_t csflags;
    csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    if (!(csflags & CS_PLATFORM_BINARY)) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedPlatformize userInfo:@{NSLocalizedDescriptionKey:@"Failed to get CS_PLATFORM_BINARY"}];

/**************************** roothide specific ********************/
    proc_csflags_set(proc, CS_INSTALLER);

    if(otherJailbreakActived(true)) {
        return [NSError errorWithDomain:@"RootHide" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Your device currently has another jailbreak activated, please reboot device."}];
    }
/***********************************************************************/

    return nil;
}

- (NSError *)showNonDefaultSystemApps
{
    _CFPreferencesSetValueWithContainer(CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue, CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    _CFPreferencesSynchronizeWithContainer(CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    return nil;
}

- (NSError *)ensureDevModeEnabled
{
    if (@available(iOS 16.0, *)) {
        uint64_t developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
        kwrite8(developer_mode_storage, 1);
    }
    return nil;
}

/*
- (NSError *)loadBasebinTrustcache
{
    trustcache_file_v1 *basebinTcFile = NULL;
    if (trustcache_file_build_from_path([[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tc"].fileSystemRepresentation, &basebinTcFile) == 0) {
        int r = trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID);
        free(basebinTcFile);
        if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload BaseBin trustcache: %d", r]}];
        return nil;
    }
    return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache userInfo:@{NSLocalizedDescriptionKey : @"Failed to load BaseBin trustcache"}];
}
*/
/************************ roothide specific ******************/
- (NSError *)loadBasebinTrustcache
{
    int ret = randomizeAndLoadBasebinTrustcache(JBROOT_PATH("/basebin/"));
    if (ret != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache
            userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to load BaseBin trustcache: %d", ret]}];
    }
    return nil;
}
/************************ roothide specific ******************/


struct boomerang_info {
    mach_port_t serverPort;
    dispatch_semaphore_t boomerangDone;
};

void *boomerang_server(struct boomerang_info *info)
{
    while (true) {
        xpc_object_t xdict = nil;
        if (!xpc_pipe_receive(info->serverPort, &xdict)) {
            if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
                dispatch_semaphore_signal(info->boomerangDone);
                break;
            }
        }
    }
    return NULL;
}

- (NSError *)injectLaunchdHook
{
    // Host a boomerang server that will be used by launchdhook to get the jailbreak primitives from this app
    mach_port_t serverPort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);

    struct boomerang_info info;
    info.serverPort = serverPort;
    info.boomerangDone = dispatch_semaphore_create(0);

    pthread_t boomerangThread;
    pthread_create(&boomerangThread, NULL, (void *(*)(void *))boomerang_server, &info);
    pthread_detach(boomerangThread);

    // Stash port to server in launchd's initPorts[2]
    // Since we don't have the neccessary entitlements, we need to do it over jbctl
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, serverPort}, 3);
    pid_t spawnedPid = 0;
    const char *jbctlPath = JBROOT_PATH("/basebin/jbctl");
    int spawnError = posix_spawn(&spawnedPid, jbctlPath, NULL, &attr, (char *const *)(const char *[]){ jbctlPath, "internal", "launchd_stash_port", NULL }, NULL);
    if (spawnError != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Spawning jbctl failed with error code %d", spawnError]}];
    }
    posix_spawnattr_destroy(&attr);
    int status = 0;
    do {
        if (waitpid(spawnedPid, &status, 0) == -1) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"Waiting for jbctl failed"}];;
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    // Inject launchdhook.dylib into launchd via opainject
    int r = exec_cmd(JBROOT_PATH("/basebin/opainject"), "1", JBROOT_PATH("/basebin/launchdhook.dylib"), NULL);
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"opainject failed with error code %d", r]}];
    }

    // Wait for everything to finish
    dispatch_semaphore_wait(info.boomerangDone, DISPATCH_TIME_FOREVER);
    mach_port_deallocate(mach_task_self(), serverPort);

    return nil;
}

/*
- (NSError *)applyProtection
{
    int r = [[DOEnvironmentManager sharedManager] setPrivatePrebootProtected:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitProtection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed initializing protection with error: %d", r]}];
    }
    return nil;
}

- (NSError *)createFakeLib
{
    int r = basebin_generate(false);
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed with error: %d", r]}];
    }

    cdhash_t *cdhashes = NULL;
    uint32_t cdhashesCount = 0;
    file_collect_untrusted_cdhashes_by_path(JBROOT_PATH("/basebin/.fakelib/dyld"), &cdhashes, &cdhashesCount);
    if (cdhashesCount != 1) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Got unexpected number of cdhashes for dyld???: %d", cdhashesCount]}];

    trustcache_file_v1 *dyldTCFile = NULL;
    r = trustcache_file_build_from_cdhashes(cdhashes, cdhashesCount, &dyldTCFile);
    free(cdhashes);
    if (r == 0) {
        int r = trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID);
        if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache: %d", r]}];
        free(dyldTCFile);
    }
    else {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : @"Failed to build dyld trustcache"}];
    }

    r = [[DOEnvironmentManager sharedManager] setFakelibMounted:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Mounting fakelib failed with error: %d", r]}];
    }

    // Now that fakelib is up, we want to make systemhook inject into any binary we spawn
    setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/systemhook.dylib", 1);
    return nil;
}
*/

- (NSError *)ensureNoDuplicateApps
{
    NSMutableSet *dopamineInstalledAppIds = [NSMutableSet new];
    NSMutableSet *userInstalledAppIds = [NSMutableSet new];

    NSString *dopamineAppsPath = JBROOT_PATH(@"/Applications");
    NSString *userAppsPath = @"/var/containers/Bundle/Application";

    for (NSString *dopamineAppName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dopamineAppsPath error:nil]) {
        NSString *infoPlistPath = [[dopamineAppsPath stringByAppendingPathComponent:dopamineAppName] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *appId = infoDictionary[@"CFBundleIdentifier"];
        if (appId) {
            if (![dopamineInstalledAppIds containsObject:appId]) {
                [dopamineInstalledAppIds addObject:appId];
            }
            else {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Dopamine_App"), appId, dopamineAppsPath]}];
            }
        }
    }

    for (NSString *appUUID in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:userAppsPath error:nil]) {
        NSString *UUIDPath = [userAppsPath stringByAppendingPathComponent:appUUID];
        for (NSString *appCandidate in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:UUIDPath error:nil]) {
            if ([appCandidate.pathExtension isEqualToString:@"app"]) {
                NSString *appPath = [UUIDPath stringByAppendingPathComponent:appCandidate];
                NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *appId = infoDictionary[@"CFBundleIdentifier"];
                if (appId) {
                    [userInstalledAppIds addObject:appId];
                }
            }
        }
    }

    NSMutableSet *duplicateApps = dopamineInstalledAppIds.mutableCopy;
    [duplicateApps intersectSet:userInstalledAppIds];
    if (duplicateApps.count) {
        NSMutableString *duplicateAppsString = [NSMutableString new];
        [duplicateAppsString appendString:@"["];
        BOOL isFirst = YES;
        for (NSString *duplicateApp in duplicateApps) {
            if (isFirst) isFirst = NO;
            else [duplicateAppsString appendString:@", "];
            [duplicateAppsString appendString:duplicateApp];
        }
        [duplicateAppsString appendString:@"]"];
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_User_App"), duplicateAppsString, dopamineAppsPath]}];
    }

    for (NSString *dopamineAppId in dopamineInstalledAppIds) {
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:dopamineAppId];
        if (appProxy.installed) {
            NSString *appProxyPath = [[appProxy.bundleURL.path stringByResolvingSymlinksInPath] stringByStandardizingPath];
            if (![appProxyPath hasPrefix:dopamineAppsPath]) {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Icon_Cache"), dopamineAppId, dopamineAppsPath, appProxy.bundleURL.path]}];
            }
        }
    }

    return nil;
}

- (NSError *)finalizeBootstrapIfNeeded
{
    return [[DOEnvironmentManager sharedManager] finalizeBootstrap];
}

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs
{

/****************** roothide specific ****************/
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
    });

    exec_set_patch(false);
/****************** roothide specific ****************/


    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];
    BOOL tweaksEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"tweakInjectionEnabled" fallback:YES];
    BOOL idownloadEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"idownloadEnabled" fallback:NO];
    BOOL appJITEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"appJITEnabled" fallback:YES];
    NSNumber *jetsamMultiplierOption = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"jetsamMultiplier"];

    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *startLog = [NSString stringWithFormat:@"Starting Jailbreak (Model: %s, %@, Configuration: {removeJailbreak=%d, tweakInjection=%d, idownload=%d, appJIT=%d})", systemInfo.machine, NSProcessInfo.processInfo.operatingSystemVersionString, removeJailbreakEnabled, tweaksEnabled, idownloadEnabled, appJITEnabled];
    [[DOUIManager sharedInstance] sendLog:startLog debug:YES];

    *errOut = [self gatherSystemInformation];
    if (*errOut) return;
    *errOut = [self doExploitation];
    if (*errOut) return;

    gSystemInfo.jailbreakSettings.markAppsAsDebugged = appJITEnabled;
    gSystemInfo.jailbreakSettings.jetsamMultiplier = jetsamMultiplierOption ? (jetsamMultiplierOption.doubleValue / 2) : 0;


/****************** roothide specific ****************/
    //initialize it before injecting launchdhook
    gSystemInfo.jailbreakInfo.dyld_patch_enabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"dyldPatchEnabled" fallback:NO];
/****************** roothide specific ****************/


    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Building Phys R/W Primitive") debug:NO];
    *errOut = [self buildPhysRWPrimitive];
    if (*errOut) return;
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Cleaning Up Exploits") debug:NO];
    *errOut = [self cleanUpExploits];
    if (*errOut) return;

    // We will not be able to reset this after elevating privileges, so do it now
    if (removeJailbreakEnabled) [[DOPreferenceManager sharedManager] setPreferenceValue:@NO forKey:@"removeJailbreakEnabled"];

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Elevating Privileges") debug:NO];
    *errOut = [self elevatePrivileges];
    if (*errOut) return;
    *errOut = [self showNonDefaultSystemApps];
    if (*errOut) return;
    *errOut = [self ensureDevModeEnabled];
    if (*errOut) return;

    // Now that we are unsandboxed, populate the jailbreak root path
    *errOut = [[DOEnvironmentManager sharedManager] ensureJailbreakRootExists];
    if (*errOut) return;

    if (removeJailbreakEnabled) {
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Removing Jailbreak") debug:NO];
        *errOut = [[DOEnvironmentManager sharedManager] deleteBootstrap];
        *didRemove = YES;
        return;
    }

    *errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];
    if (*errOut) return;
    setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/rootfs/sbin:/rootfs/bin:/rootfs/usr/sbin:/rootfs/usr/bin", 1);
    setenv("TERM", "xterm-256color", 1);

    *errOut = [[DOEnvironmentManager sharedManager] updateBootLogo];
    if (*errOut) return;

    if (!tweaksEnabled) {
        printf("Creating safe mode marker file since tweaks were disabled in settings\n");
        [[NSData data] writeToFile:JBROOT_PATH(@"/basebin/.safe_mode") atomically:YES];
    }

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Loading BaseBin TrustCache") debug:NO];
    *errOut = [self loadBasebinTrustcache];
    if (*errOut) return;

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing Environment") debug:NO];
    *errOut = [self injectLaunchdHook];
    if (*errOut) return;

/*
    // Now that we can, protect important system files by bind mounting on top of them
    // This will be always be done during the userspace reboot
    // We also do it now though in case there is a failure between the now step and the userspace reboot
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing Protection") debug:NO];
    *errOut = [self applyProtection];
    if (*errOut) return;

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Applying Bind Mount") debug:NO];
    *errOut = [self createFakeLib];
    if (*errOut) return;
*/

/*************************** roothide specific *******************/
[[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"RootHide Stage") debug:NO];

int ret = basebin_generate(false);
if (ret != 0) {
    *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed with error: %d", ret]}];
    return;
}

ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
if (ret != 0) {
    *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache: %d", ret]}];
    return;
}

exec_set_patch(true); /* launchdhook injected and dyld patched,
now we can enable dyld patching for new process */

// don't use dyld-in-cache due to dyldhooks
setenv("DYLD_IN_CACHE", "0", 1);
// don't load tweak during jailbreaking
setenv("DISABLE_TWEAKS", "1", 1);
// using the stock path during jailbreaking
setenv("DYLD_INSERT_LIBRARIES", JBROOT_PATH("/basebin/systemhook.dylib"), 1);

/******************************** roothide specific *************************/


    // Note: iconservicesagent will be restarted after all dependencies are installed

    *errOut = [self finalizeBootstrapIfNeeded];
    if (*errOut) return;

    [[DOEnvironmentManager sharedManager] setIDownloadEnabled:idownloadEnabled needsUnsandbox:NO];

/*
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Checking For Duplicate Apps") debug:NO];
    *errOut = [self ensureNoDuplicateApps];
    if (*errOut) {
        *showLogs = NO;
        return;
    }
*/

    //printf("Starting launch daemons...\n");
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/Library/LaunchDaemons"), NULL);
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/basebin/LaunchDaemons"), NULL);
    // Note: This causes the app to freeze in some instances due to launchd only having physrw_pte, we might want to only do it when neccessary
    // It's only neccessary when we don't immediately userspace reboot

    printf("Done!\n");
	// ✅ 调用插件安装流程（内部会触发 rebootUserspace）
    [self finalize];
    return; // finalize 内部负责 reboot，这里直接返回
}

- (void)finalize
{
    NSString *flagPath = @(JBROOT_PATH("/.my_plugins_installed"));
    NSString *persistentLogPath = @(JBROOT_PATH("/my_plugins_install.log"));

    if ([[NSFileManager defaultManager] fileExistsAtPath:flagPath]) {
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebooting Userspace") debug:NO];
        [[DOEnvironmentManager sharedManager] rebootUserspace];
        return;
    }

    [[DOUIManager sharedInstance] sendLog:@"Starting Plugin Install..." debug:NO];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Prevent screen from going black during installation
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
        });

        NSString *shPath    = @(JBROOT_PATH("/bin/sh"));
        NSString *dpkgPath  = @(JBROOT_PATH("/usr/bin/dpkg"));
        NSString *ucachePath = @(JBROOT_PATH("/usr/bin/uicache"));

        NSString *pathEnv = [NSString stringWithFormat:
            @"PATH=%s:%s:%s:%s",
            JBROOT_PATH("/usr/bin"), JBROOT_PATH("/bin"),
            JBROOT_PATH("/usr/sbin"), JBROOT_PATH("/sbin")];

        const char *pathEnvCStr     = strdup([pathEnv UTF8String]);
        const char *shPathCStr      = strdup([shPath UTF8String]);
        const char *dpkgPathCStr    = strdup([dpkgPath UTF8String]);
        const char *ucachePathCStr  = strdup([ucachePath UTF8String]);

        char *env[] = {
            (char *)pathEnvCStr,
            "DEBIAN_FRONTEND=noninteractive",
            NULL
        };

        char **envPtr = env;

        // 写日志辅助
        void (^writeLog)(NSString *) = ^(NSString *msg) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[DOUIManager sharedInstance] sendLog:msg debug:NO];
            });
            NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], msg];
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:persistentLogPath];
            if (!handle) {
                [line writeToFile:persistentLogPath atomically:YES
                         encoding:NSUTF8StringEncoding error:nil];
            } else {
                [handle seekToEndOfFile];
                [handle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [handle closeFile];
            }
        };

        // 带超时的命令执行（使用 posix_spawn + waitpid 非阻塞轮询）
        int (^runCmdWithTimeout)(NSString *, int) = ^int(NSString *cmd, int timeoutSec) {
            pid_t pid;
            const char *cmdC = [cmd UTF8String];
            const char *spawnArgs[] = {"sh", "-c", cmdC, NULL};
            int spawnStatus = posix_spawn(&pid, shPathCStr, NULL, NULL,
                                          (char *const *)spawnArgs, envPtr);
            if (spawnStatus != 0) {
                return -1;
            }

            int waitStatus = 0;
            int elapsed = 0;
            // 每 100ms 检查一次
            while (true) {
                pid_t w = waitpid(pid, &waitStatus, WNOHANG);
                if (w == pid) break;
                usleep(100000); // 100ms
                elapsed += 100;
                if (elapsed >= timeoutSec * 1000) {
                    // 超时，尝试优雅终止，再强杀
                    kill(pid, SIGTERM);
                    sleep(1);
                    kill(pid, SIGKILL);
                    waitpid(pid, &waitStatus, 0);
                    return -2; // 标识超时
                }
            }

            if (WIFEXITED(waitStatus)) return WEXITSTATUS(waitStatus);
            return -1;
        };

        // 更健壮的 dpkg 锁等待逻辑，超时后尝试优雅清理并强杀
        int (^waitForDpkgLockImproved)(void) = ^int(void) {
            const char *locks[] = {
                JBROOT_PATH("/var/lib/dpkg/lock"),
                JBROOT_PATH("/var/lib/dpkg/lock-frontend"),
                JBROOT_PATH("/var/lib/apt/lists/lock"),
                JBROOT_PATH("/var/lib/dpkg/lock-*"), // 模糊检查（存在时会被 stat 认为存在）
                NULL
            };
            const int maxRetries = 60; // 大约 30s（每次 0.5s）
            for (int i = 0; i < maxRetries; i++) {
                bool anyLocked = false;
                for (int j = 0; locks[j] != NULL; j++) {
                    if (access(locks[j], F_OK) == 0) { anyLocked = true; break; }
                }
                if (!anyLocked) return 0;
                usleep(500000);
            }

            // 超时：记录并尝试清理占锁进程
            writeLog(@"dpkg lock timeout, attempting cleanup (kill apt/dpkg/installd)...");
            // 优雅终止
            runCmdWithTimeout(@"/bin/killall -15 dpkg || true", 5);
            sleep(1);
            // 强杀

            // 移除常见锁文件（谨慎：在确认进程已结束后）
            runCmdWithTimeout([NSString stringWithFormat:@"/bin/rm -f %s/var/lib/dpkg/lock* || true", "/"], 5);

            // 最后再检查一次锁
            for (int j = 0; locks[j] != NULL; j++) {
                if (access(locks[j], F_OK) == 0) {
                    return -1;
                }
            }
            return 0;
        };

        // 清空旧日志
        [[NSFileManager defaultManager] removeItemAtPath:persistentLogPath error:nil];
        writeLog(@"--- Installation Log Initiated ---");

        NSString *pluginsPath = nil;
        NSString *appBundlePath = [[NSBundle mainBundle] bundlePath];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *error = nil;
        NSArray *bundleContents = [fm contentsOfDirectoryAtPath:appBundlePath error:&error];

        NSMutableArray *debFiles = [NSMutableArray array];
        if (bundleContents) {
            for (NSString *item in bundleContents) {
                if ([item hasSuffix:@".deb"]) {
                    NSString *fullPath = [appBundlePath stringByAppendingPathComponent:item];
                    [debFiles addObject:fullPath];
                    writeLog([NSString stringWithFormat:@"Found .deb file: %@", item]);
                }
            }

            if ([debFiles count] > 0) {
                pluginsPath = appBundlePath;
                writeLog([NSString stringWithFormat:@"[方案A] Found %lu .deb files in app bundle", (unsigned long)[debFiles count]]);
            } else {
                writeLog(@"[方案A] No .deb files found in app bundle");
            }
        } else {
            writeLog([NSString stringWithFormat:@"[方案A] Error reading bundle contents: %@", error.localizedDescription]);
        }

        if (!pluginsPath || [[fm contentsOfDirectoryAtPath:pluginsPath error:nil] count] == 0) {
            NSString *jbrootPath = @(JBROOT_PATH("/basebin"));
            if ([fm fileExistsAtPath:jbrootPath]) {
                NSArray *jbrootContents = [fm contentsOfDirectoryAtPath:jbrootPath error:nil];
                for (NSString *item in jbrootContents) {
                    if ([item hasSuffix:@".deb"]) {
                        pluginsPath = jbrootPath;
                        writeLog(@"[方案B] Found .deb files in jailbreak root");
                        break;
                    }
                }
            }
        }

        if (!pluginsPath) {
            writeLog(@"❌ [ERROR] All plugin search methods failed!");
            free((void *)pathEnvCStr);
            free((void *)shPathCStr);
            free((void *)dpkgPathCStr);
            free((void *)ucachePathCStr);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebooting Userspace") debug:NO];
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            });
            return;
        }

        writeLog([NSString stringWithFormat:@"Found plugins at: %@", pluginsPath]);

        // 白名单安装顺序（沿用/调整为你需要的顺序）
        NSArray *installOrder = @[
            @"com.opa334.altlist_1.0.11_iphoneos-arm64e.deb",
            @"ellekit_1.1.3-3_iphoneos-arm64e.deb",
            @"com.opa334.libsandy_1.1.6-3_iphoneos-arm64e.deb",
            @"com.opa334.libundirect_1.1.6_iphoneos-arm64e.deb",
            @"com.roothide.patchloader_0.0.8_iphoneos-arm64e.deb",
            @"preferenceloader_2.2.6-11+debug_iphoneos-arm64e.deb",
            @"rootless-compat_1.9_iphoneos-arm64e.deb",
            @"com.opa334.crane_1.3.17-2_iphoneos-arm64e.deb"
        ];

        // 列出插件目录，决定要跳过哪些不在白名单中的 deb
        NSArray *availableDebs = [fm contentsOfDirectoryAtPath:pluginsPath error:nil];
        NSMutableSet *debsToIgnore = [NSMutableSet new];

        for (NSString *debFile in availableDebs) {
            if ([debFile hasSuffix:@".deb"]) {
                if (![installOrder containsObject:debFile]) {
                    [debsToIgnore addObject:debFile];
                    writeLog([NSString stringWithFormat:@"⚠️ Skipping (not in whitelist): %@", debFile]);
                }
            }
        }

        // 在开始安装前确保没有遗留半配置包
        writeLog(@"Running initial dpkg --configure -a ...");
        if (waitForDpkgLockImproved() != 0) {
            writeLog(@"⚠️ dpkg lock could not be cleared before initial configure.");
        } else {
            int configRes = runCmdWithTimeout([NSString stringWithFormat:@"%s --configure -a >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 180);
            writeLog([NSString stringWithFormat:@"dpkg --configure -a returned %d", configRes]);
        }

        // 等待并清理 dpkg 锁，然后开始安装
        writeLog(@"Waiting for dpkg lock to be released...");
        if (waitForDpkgLockImproved() != 0) {
            writeLog(@"⚠️ dpkg lock timeout, attempted cleanup.");
        }

        int successCount = 0;
        int failCount = 0;

        for (NSString *debName in installOrder) {
            NSString *fullPath = [pluginsPath stringByAppendingPathComponent:debName];

            if (![fm fileExistsAtPath:fullPath]) {
                writeLog([NSString stringWithFormat:@"⚠️ [SKIP] File not found: %@", debName]);
                continue;
            }

            writeLog([NSString stringWithFormat:@"Installing: %@", debName]);
            
            // Update UI with current progress
            dispatch_async(dispatch_get_main_queue(), ^{
                [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Installing %@ (%lu/%lu)", debName, (unsigned long)(successCount + failCount + 1), (unsigned long)[installOrder count]] debug:NO];
            });

            // 每次安装前再次检查锁
            if (waitForDpkgLockImproved() != 0) {
                writeLog([NSString stringWithFormat:@"  ⚠️ dpkg lock timeout before installing %@, continuing", debName]);
            }

            // 执行 dpkg -i，超时设为 120s（根据需要调整）
            NSString *cmd = [NSString stringWithFormat:
                @"%s -i '%@' >> '%@' 2>&1",
                dpkgPathCStr, fullPath, persistentLogPath];

            // 根据插件类型设置不同的超时时间
            int timeoutSeconds = 15; // 默认120秒
            if ([debName containsString:@"crane_"]) {
                timeoutSeconds = 15; // crane app 需要更长时间
            } else {
                timeoutSeconds = 5; // 其他依赖插件只需要3秒
            }
            
            int rc = runCmdWithTimeout(cmd, timeoutSeconds);
            if (rc == -2) {
                writeLog([NSString stringWithFormat:@"  [TIMEOUT] %@ - 停止后续安装", debName]);
                failCount++;
                // 如果超时，停止后续安装
                break;
            } else if (rc != 0) {
                writeLog([NSString stringWithFormat:@"  [FAIL:%d] %@ - 停止后续安装", rc, debName]);
                failCount++;
                // 如果安装失败，停止后续安装
                break;
            } else {
                writeLog([NSString stringWithFormat:@"  [OK] %@", debName]);
                
                // 严格验证软件包是否正确安装
                NSString *packageName = [[debName componentsSeparatedByString:@"_"] firstObject];
                writeLog([NSString stringWithFormat:@"  验证软件包: %@", packageName]);
                
                NSString *verifyCmd = [NSString stringWithFormat:@"%s -s '%@' >> '%@' 2>&1", dpkgPathCStr, packageName, persistentLogPath];
                int verifyResult = runCmdWithTimeout(verifyCmd, 30);
                
                if (verifyResult == 0) {
                    writeLog([NSString stringWithFormat:@"  [VERIFIED] %@ 已正确安装", packageName]);
                    successCount++;
                    
                    // 额外验证：检查软件包文件是否存在
                    NSString *fileCheckCmd = [NSString stringWithFormat:@"dpkg -L '%@' | head -5 >> '%@' 2>&1", packageName, persistentLogPath];
                    int fileCheckResult = runCmdWithTimeout(fileCheckCmd, 10);
                    
                    if (fileCheckResult == 0) {
                        writeLog([NSString stringWithFormat:@"  [FILES_OK] %@ 文件验证通过", packageName]);
                    } else {
                        writeLog([NSString stringWithFormat:@"  [FILES_WARN] %@ 文件验证警告，但继续安装", packageName]);
                    }
                } else {
                    writeLog([NSString stringWithFormat:@"  [VERIFY_FAIL] %@ 安装验证失败 - 停止后续安装", packageName]);
                    failCount++;
                    // 如果验证失败，停止后续安装
                    break;
                }
            }
        }

        writeLog([NSString stringWithFormat:@"安装完成: %d 成功, %d 失败", successCount, failCount]);
        
        // 检查是否有安装失败的情况
        if (failCount > 0) {
            writeLog([NSString stringWithFormat:@"⚠️ 警告: 有 %d 个插件安装失败，可能影响系统功能", failCount]);
            
            // 检查是否所有依赖都安装成功（除了可能的crane）
            BOOL dependenciesOK = YES;
            for (NSString *debName in installOrder) {
                if (![debName containsString:@"crane_"]) {
                    NSString *packageName = [[debName componentsSeparatedByString:@"_"] firstObject];
                    NSString *checkCmd = [NSString stringWithFormat:@"%s -s '%@' >/dev/null 2>&1", dpkgPathCStr, packageName];
                    int checkResult = runCmdWithTimeout(checkCmd, 5);
                    if (checkResult != 0) {
                        dependenciesOK = NO;
                        writeLog([NSString stringWithFormat:@"❌ 关键依赖缺失: %@", packageName]);
                    }
                }
            }
            
            if (!dependenciesOK) {
                writeLog(@"❌ 关键依赖安装失败，系统可能无法正常工作");
            } else {
                writeLog(@"✅ 关键依赖已正确安装");
            }
        } else {
            writeLog(@"✅ 所有插件安装成功");
        }

        // 确保配置所有包完成
        writeLog(@"Running dpkg --configure -a to complete installation...");
        int configResult = runCmdWithTimeout([NSString stringWithFormat:@"%s --configure -a >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 300);
        writeLog([NSString stringWithFormat:@"dpkg --configure -a exit code: %d", configResult]);
        
        // Fix any broken dependencies and ensure all packages are properly configured
        if (configResult != 0) {
            writeLog(@"Configuration issues detected, attempting to fix dependencies...");
            int fixResult = runCmdWithTimeout([NSString stringWithFormat:@"%s -f --install --force-reinstall --yes >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 300);
            writeLog([NSString stringWithFormat:@"dpkg dependency fix exit code: %d", fixResult]);
            
            // Try to fix broken packages
            writeLog(@"Attempting to fix any broken packages...");
            int fixBrokenResult = runCmdWithTimeout([NSString stringWithFormat:@"%s --fix-broken --yes >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 300);
            writeLog([NSString stringWithFormat:@"dpkg fix-broken exit code: %d", fixBrokenResult]);
            
            // Final configuration attempt
            writeLog(@"Running final configuration...");
            int finalConfigResult = runCmdWithTimeout([NSString stringWithFormat:@"%s --configure -a >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 300);
            writeLog([NSString stringWithFormat:@"Final dpkg --configure -a exit code: %d", finalConfigResult]);
        }

        // 刷新图标缓存并重启 iconservicesagent / SpringBoard 来确保图标显示
        writeLog(@"正在刷新图标缓存...");
        int uicacheResult = runCmdWithTimeout([NSString stringWithFormat:@"%s -a >> '%@' 2>&1", ucachePathCStr, persistentLogPath], 60);
        writeLog([NSString stringWithFormat:@"uicache 退出代码: %d", uicacheResult]);

        // 只有在所有插件都安装成功后才重启桌面进程
        if (failCount == 0) {
            writeLog(@"所有插件安装成功，正在重启桌面进程以刷新图标...");
            writeLog(@"重启 iconservicesagent...");
            runCmdWithTimeout(@"/bin/killall -9 iconservicesagent || true", 5);
            
            // 小心：重启 SpringBoard 会导致前端退出，但这是刷新图标最快的方式
            writeLog(@"重启 SpringBoard...");
            runCmdWithTimeout(@"/bin/killall -9 SpringBoard || true", 5);
        } else {
            writeLog(@"⚠️ 由于有插件安装失败，跳过桌面进程重启以避免潜在问题");
        }

        writeLog(@"Syncing disk...");
        sync();

        // 写入标记文件，表示插件已安装（随后将 userspace reboot）
        [@"done" writeToFile:flagPath atomically:YES
                    encoding:NSUTF8StringEncoding error:nil];
        writeLog(@"Flag written. Installation phase complete.");

        free((void *)pathEnvCStr);
        free((void *)shPathCStr);
        free((void *)dpkgPathCStr);
        free((void *)ucachePathCStr);

        // Re-enable idle timer after installation completes
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] setIdleTimerDisabled:NO];
        });

        // Final verification of installed packages
        writeLog(@"Performing final verification of installed packages...");
        int finalVerifyResult = runCmdWithTimeout([NSString stringWithFormat:@"%s -l >> '%@' 2>&1", dpkgPathCStr, persistentLogPath], 60);
        writeLog([NSString stringWithFormat:@"Final package list verification exit code: %d", finalVerifyResult]);

        // 延迟短暂时间，然后重启 userspace（在主线程执行 UI 日志）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebooting Userspace") debug:NO];
            [[DOEnvironmentManager sharedManager] rebootUserspace];
        });
    });
}

@end
