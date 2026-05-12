//
//  Jailbreaker.m
//  Dopamine
//  Created by Lars Fröder on 10.01.24.

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
#import <sys/wait.h>
#import <spawn.h>
#import <signal.h>
#import <time.h>

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

#define kCFPreferencesNoContainer CFSTR("kCFPreferencesNoContainer")
void _CFPreferencesSetValueWithContainer(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);

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
    if (!kernelPath) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedToFindKernel userInfo:@{NSLocalizedDescriptionKey:@"Failed to find kernelcache. Ensure your device is properly [...]
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
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF failed with error: (%s)", [...]
        }
        xpf_stop();
    }
    else {
        NSError *error = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF start failed with er[...]
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
    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to l[...]
    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to exploit kernel"}];

    jbinfo_initialize_boot_constants();
    libjailbreak_translation_init();
    libjailbreak_IOSurface_primitives_init();

    if (pacBypass) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PAC (%@)"), pacBypass.name] debug:NO];
        if ([pacBypass load] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stri[...]
        if ([pacBypass run] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypas[...]
        // At this point we presume the PAC bypass has given us stable kcall primitives
        gSystemInfo.jailbreakInfo.usesPACBypass = true;
    }

    if ([[DOEnvironmentManager sharedManager] isPPLBypassRequired]) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PPL (%@)"), pplBypass.name] debug:NO];
        if ([pplBypass load] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescript[...]
        if ([pplBypass run] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescription[...]
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
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBuildingPhysRW userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to build phys r/w primitive: %d[...]
    }
    return nil;
}

- (NSError *)cleanUpExploits
{
    int r = [[DOExploitManager sharedManager] cleanUpExploits];
    if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedCleanup userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to cleanup exploits: %d", r]}][...]
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

    if (getuid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, uid still [...]
    if (getgid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, gid still [...]

    // Unsandbox
    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    mac_label_set(label, 1, -1);
    NSError *error = nil;
    [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&error];
    if (error) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedUnsandbox userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to unsandbox, /var does not s[...]
    setenv("HOME", "/var/root", true);
    setenv("CFFIXED_USER_HOME", "/var/root", true);
    setenv("TMPDIR", "/var/tmp", true);

    // Get CS_PLATFORM_BINARY
    proc_csflags_set(proc, CS_PLATFORM_BINARY);
    uint32_t csflags;
    csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    if (!(csflags & CS_PLATFORM_BINARY)) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedPlatformize userInfo:@{NSLocalizedDescriptionKey:@"Failed to get CS_PLATFORM_BINARY"}][...]

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
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Spawning jbctl failed with error c[...]
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
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"opainject failed with error code %[...]
    }

    // Wait for everything to finish
    dispatch_semaphore_wait(info.boomerangDone, DISPATCH_TIME_FOREVER);
    mach_port_deallocate(mach_task_self(), serverPort);

    return nil;
}

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
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_[...]
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
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Err[...]
    }

    for (NSString *dopamineAppId in dopamineInstalledAppIds) {
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:dopamineAppId];
        if (appProxy.installed) {
            NSString *appProxyPath = [[appProxy.bundleURL.path stringByResolvingSymlinksInPath] stringByStandardizingPath];
            if (![appProxyPath hasPrefix:dopamineAppsPath]) {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_[...]
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
    NSString *startLog = [NSString stringWithFormat:@"Starting Jailbreak (Model: %s, %@, Configuration: {removeJailbreak=%d, tweakInjection=%d, idownload=%d, appJIT=%d})", systemInfo.machine, NSP[...]
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

/*************************** roothide specific *******************/
[[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"RootHide Stage") debug:NO];

int ret = basebin_generate(false);
if (ret != 0) {
    *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed with error: %d",[...]
    return;
}

ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
if (ret != 0) {
    *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache: %d", r[...]
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

    printf("Done!\n");
	// ✅ 调用插件安装流程（内部会触发 rebootUserspace）
    [self finalize];
    return; // finalize 内部负责 reboot，这里直接返回
}

/**
 * 使用 posix_spawn 执行命令（替代 NSTask）
 * @param cmd 要执行的命令
 * @param logPath 日志输出文件路径
 * @param env 环境变量字典
 * @param timeoutSecs 超时时间（秒）
 * @param writeLog 日志回调函数
 * @return 进程退出码
 */
static int posix_spawn_cmd(NSString *cmd, NSString *logPath, NSDictionary *env,
                           int timeoutSecs, void(^writeLog)(NSString *))
{
    // 打开日志文件
    int logFd = open([logPath UTF8String], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logFd < 0) {
        writeLog([NSString stringWithFormat:@"[posix_spawn] Failed to open log file: %s", strerror(errno)]);
        return -1;
    }

    // 设置文件操作
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, logFd, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, logFd, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, logFd);

    // 设置 spawn 属性
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);

    // 构建环境变量数组
    NSMutableArray *envArray = [NSMutableArray array];
    for (NSString *key in env) {
        NSString *envStr = [NSString stringWithFormat:@"%@=%@", key, env[key]];
        [envArray addObject:envStr];
    }
    
    // 转换为 C 字符串数组
    const char **envp = (const char **)malloc((envArray.count + 1) * sizeof(char *));
    for (NSUInteger i = 0; i < envArray.count; i++) {
        envp[i] = [envArray[i] UTF8String];
    }
    envp[envArray.count] = NULL;

    // 构建命令行参数
    const char *argv[] = { "/bin/sh", "-c", [cmd UTF8String], NULL };

    // 执行 posix_spawn
    pid_t pid = 0;
    int spawnErr = posix_spawn(&pid, "/bin/sh", &actions, &attr,
                               (char * const *)argv, (char * const *)envp);

    // 清理资源
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    close(logFd);
    free(envp);

    if (spawnErr != 0) {
        writeLog([NSString stringWithFormat:@"[posix_spawn] spawn failed: %s", strerror(spawnErr)]);
        return -1;
    }

    // 带超时的进程等待
    time_t deadline = time(NULL) + timeoutSecs;
    int status = 0;
    pid_t waitRet = 0;

    while ((waitRet = waitpid(pid, &status, WNOHANG)) == 0) {
        if (time(NULL) > deadline) {
            writeLog([NSString stringWithFormat:@"[posix_spawn] timeout after %ds, killing process %d", timeoutSecs, pid]);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -2; // 超时
        }
        usleep(100000); // 100ms
    }

    if (waitRet < 0) {
        writeLog([NSString stringWithFormat:@"[posix_spawn] waitpid failed: %s", strerror(errno)]);
        return -1;
    }

    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (exitCode != 0) {
        writeLog([NSString stringWithFormat:@"[posix_spawn] process exited with code %d", exitCode]);
    }

    return exitCode;
}

- (void)finalize
{
    NSString *doneFlagPath      = @(JBROOT_PATH("/.my_plugins_installed"));
    NSString *pendingFlagPath   = @(JBROOT_PATH("/.my_plugins_pending"));
    NSString *persistentLogPath = @(JBROOT_PATH("/my_plugins_install.log"));
    NSFileManager *fm = [NSFileManager defaultManager];

    // 已完成安装，直接重启
    if ([fm fileExistsAtPath:doneFlagPath]) {
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Environment Ready. Rebooting Userspace...") debug:NO];
        [[DOEnvironmentManager sharedManager] rebootUserspace];
        return;
    }

    BOOL isPendingStage = [fm fileExistsAtPath:pendingFlagPath];

    if (!isPendingStage) {
        // --- 阶段一：仅写入标记并重启，不做任何安装 ---
        [[DOUIManager sharedInstance] sendLog:@"[Phase 1] Preparing base environment..." debug:NO];

        NSError *writeErr = nil;
        [@"pending" writeToFile:pendingFlagPath
                     atomically:YES
                       encoding:NSUTF8StringEncoding
                          error:&writeErr];
        if (writeErr) {
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:
                @"[Phase 1] Failed to write pending flag: %@", writeErr.localizedDescription]
                debug:NO];
            return;
        }

        [[DOUIManager sharedInstance] sendLog:@"[Phase 1] Flag written. Rebooting to activate base environment..." debug:NO];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[DOEnvironmentManager sharedManager] rebootUserspace];
        });
        return;
    }

    // --- 阶段二：重启后正式安装 ---
    [[DOUIManager sharedInstance] sendLog:@"[Phase 2] Base environment active. Starting installation..." debug:NO];

    NSString *dpkgPath    = @(JBROOT_PATH("/usr/bin/dpkg"));
    NSString *uicachePath = @(JBROOT_PATH("/usr/bin/uicache"));
    
    // 构建环境变量
    NSString *jbrootBin     = @(JBROOT_PATH("/bin"));
    NSString *jbrootUsrBin  = @(JBROOT_PATH("/usr/bin"));
    NSString *jbrootSbin    = @(JBROOT_PATH("/sbin"));
    NSString *jbrootUsrSbin = @(JBROOT_PATH("/usr/sbin"));
    
    NSDictionary *taskEnv = @{
        @"PATH": [NSString stringWithFormat:@"%@:%@:%@:%@:/bin:/sbin:/usr/bin:/usr/sbin",
                  jbrootUsrBin, jbrootBin, jbrootUsrSbin, jbrootSbin],
        @"DEBIAN_FRONTEND": @"noninteractive",
        @"HOME": @(JBROOT_PATH("/var/root")),
        @"TMPDIR": @(JBROOT_PATH("/tmp"))
    };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
        });

        // ================================================================
        // 日志助手
        // ================================================================
        void (^writeLog)(NSString *) = ^(NSString *msg) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[DOUIManager sharedInstance] sendLog:msg debug:NO];
            });
            NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], msg];
            NSData   *data = [line dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:persistentLogPath];
            if (!handle) {
                [data writeToFile:persistentLogPath atomically:YES];
            } else {
                [handle seekToEndOfFile];
                [handle writeData:data];
                [handle closeFile];
            }
        };

        // ================================================================
        // 扫描 Bundle 内符合白名单的 .deb 文件
        // ================================================================
        NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
        NSArray  *allFiles   = [fm contentsOfDirectoryAtPath:bundlePath error:nil];
        NSArray  *prefixes   = @[
            @"ellekit_",
            @"preferenceloader_",
            @"com.roothide.patchloader_",
            @"com.opa334.altlist_",
            @"rootless-compat_",
            @"com.opa334.crane_",
            @"libsandy_",
            @"libundirect_"
        ];

        NSMutableArray *debsToInstall = [NSMutableArray array];
        for (NSString *file in allFiles) {
            if (![file hasSuffix:@".deb"]) continue;
            for (NSString *pre in prefixes) {
                if ([file hasPrefix:pre]) {
                    [debsToInstall addObject:[bundlePath stringByAppendingPathComponent:file]];
                    break;
                }
            }
        }

        // ================================================================
        // 安装流程
        // ================================================================
        if (debsToInstall.count == 0) {
            writeLog(@"❌ No matching .deb files found in bundle.");
        } else {
            [fm removeItemAtPath:persistentLogPath error:nil];
            writeLog([NSString stringWithFormat:@"--- Starting Batch Installation (%lu packages) ---",
                      (unsigned long)debsToInstall.count]);
            for (NSString *p in debsToInstall) {
                writeLog([NSString stringWithFormat:@"  • %@", [p lastPathComponent]]);
            }

            // 1. 清理残留锁
            writeLog(@"[Installer] Pre-cleanup...");
            posix_spawn_cmd([NSString stringWithFormat:@"%@/killall -9 dpkg apt 2>/dev/null || true", jbrootUsrBin],
                           persistentLogPath, taskEnv, 5, writeLog);
            posix_spawn_cmd([NSString stringWithFormat:@"%@ --configure -a 2>&1", dpkgPath],
                           persistentLogPath, taskEnv, 60, writeLog);

            // 2. 构造批量参数
            NSMutableString *batchArgs = [NSMutableString string];
            for (NSString *path in debsToInstall) {
                [batchArgs appendFormat:@" '%@'", path];
            }

            // 3. Unpack
            writeLog([NSString stringWithFormat:@"[Installer] Unpacking %lu packages...",
                      (unsigned long)debsToInstall.count]);
            int unpackRes = posix_spawn_cmd([NSString stringWithFormat:@"%@ --unpack%@ 2>&1",
                                            dpkgPath, batchArgs],
                                           persistentLogPath, taskEnv, 180, writeLog);
            if (unpackRes != 0) {
                writeLog([NSString stringWithFormat:@"⚠️ Unpack exited with code %d, continuing...", unpackRes]);
            }

            // 4. Configure
            writeLog(@"[Installer] Configuring packages...");
            int configRes = posix_spawn_cmd([NSString stringWithFormat:@"%@ --configure -a 2>&1", dpkgPath],
                                           persistentLogPath, taskEnv, 300, writeLog);

            if (configRes == 0) {
                writeLog(@"✅ All plugins installed successfully.");
                NSError *flagErr = nil;
                [@"done" writeToFile:doneFlagPath
                          atomically:YES
                            encoding:NSUTF8StringEncoding
                               error:&flagErr];
                if (flagErr) {
                    writeLog([NSString stringWithFormat:@"⚠️ Failed to write done flag: %@",
                              flagErr.localizedDescription]);
                }
                [fm removeItemAtPath:pendingFlagPath error:nil];
            } else {
                writeLog([NSString stringWithFormat:
                          @"⚠️ dpkg configure returned %d. Check: %@", configRes, persistentLogPath]);
            }
        }

        // 5. 刷新图标缓存
        writeLog(@"[Installer] Refreshing UI cache...");
        posix_spawn_cmd([NSString stringWithFormat:@"%@ -a 2>&1", uicachePath],
                       persistentLogPath, taskEnv, 60, writeLog);

        sync();

        // 6. 重启
        dispatch_async(dispatch_get_main_queue(), ^{
            [[UIApplication sharedApplication] setIdleTimerDisabled:NO];
            [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Installation Finished. Final Reboot...") debug:NO];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            });
        });
    });
}

@end
