/**
 * Human-readable descriptions for the reason codes native detectors emit.
 * Codes are the stable, machine-readable contract (log and alert on them);
 * these strings are for display and may change between releases.
 * `reasons.test.ts` fails if a native code is missing here.
 */
export const REASON_DESCRIPTIONS: Readonly<Record<string, string>> = {
  // Root (Android)
  SU_BINARY_FOUND: 'An `su` binary is present on the device',
  SU_BINARY_FOUND_NATIVE:
    'An `su` binary is present (found by a raw system call that bypasses hooks)',
  TEST_KEYS_BUILD:
    'The OS build is signed with test keys (custom or developer ROM)',
  DANGEROUS_BUILD_PROPS:
    'System properties ro.debuggable=1 or ro.secure=0 are set',
  ROOT_MANAGER_APP: 'A root-management app is installed',
  SYSTEM_WRITABLE: 'The /system partition is writable',
  SELINUX_PERMISSIVE: 'SELinux is in permissive mode',
  SYSTEM_MOUNTED_RW: 'A system partition is mounted read-write',
  MAGISK_APP: 'The Magisk app is installed',
  MAGISK_FILES: 'Magisk files are present on the device',
  MAGISK_BINARY: 'The magisk binary is present',
  MAGISK_MOUNTS: "Magisk's mounts are visible in the app's mount table",
  BUSYBOX_BINARY: 'A BusyBox binary is present',

  // Jailbreak (iOS)
  JAILBREAK_FILES: 'Jailbreak-associated files are present',
  JAILBREAK_URL_SCHEME:
    'A jailbreak package manager or tool is installed (its URL scheme opens)',
  SYMLINKED_SYSTEM_DIRECTORY:
    'A system directory has been replaced with a symlink',
  SANDBOX_WRITE_ESCAPE: 'The app can write outside its sandbox',
  TWEAK_INJECTOR_DYLIB:
    'A jailbreak tweak injector library is loaded in the app',
  DYLD_INSERT_LIBRARIES_SET: 'DYLD_INSERT_LIBRARIES is set for the app process',
  PROCESS_SPAWN_ALLOWED:
    'The app can spawn processes (sandbox restriction lifted)',

  // Emulator / simulator
  EMULATOR_BUILD_FINGERPRINT: 'Device build properties match an emulator',
  EMULATOR_QEMU_FILES: 'QEMU emulator files are present',
  EMULATOR_APP: 'An emulator platform app is installed',
  EMULATOR_TELEPHONY: 'Telephony reports emulator placeholder values',
  SIMULATOR: 'Running in the iOS Simulator',

  // Developer / debug state
  DEVELOPER_OPTIONS_ENABLED: 'Developer options are enabled',
  EMBEDDED_PROVISIONING_PROFILE:
    'The app is a development, ad-hoc or enterprise build',
  ADB_ENABLED: 'USB debugging (ADB) is enabled',
  JDWP_DEBUGGER_ATTACHED: 'A Java debugger is attached to the app',
  PTRACE_TRACED: 'A debugger is attached to the app process',
  PARENT_NOT_LAUNCHD:
    'The app was launched by a debugger or tool rather than the home screen',
  TRACER_PID_ATTACHED:
    'A native debugger or ptrace-based tool is attached to the app process',
  MOCK_LOCATION_APPOP: 'This app is set as the mock-location provider',
  MOCK_LOCATION_APP_INSTALLED: 'A fake-GPS app is installed',
  SIMULATED_LOCATION: 'The last location fix was simulated by software',

  // Network
  VPN_TRANSPORT: 'The active network is a VPN',
  VPN_INTERFACE: 'A VPN tunnel interface is up',
  VPN_SCOPED_INTERFACE: 'A VPN tunnel interface is configured',
  SYSTEM_PROXY_PROPERTY: 'A JVM HTTP proxy is configured',
  NETWORK_PROXY: 'The network has a proxy configured',
  HTTP_PROXY: 'An HTTP proxy is configured',
  HTTPS_PROXY: 'An HTTPS proxy is configured',
  PAC_PROXY: 'A proxy auto-config (PAC) file is configured',

  // Screen / overlay
  PRESENTATION_DISPLAY:
    'A secondary presentation display is attached (possible mirroring)',
  SCREEN_CAPTURED: 'The screen is being recorded or mirrored',
  SCREEN_RECORDING_VISIBLE: 'The app is visible in an active screen recording',
  SCREENSHOT_RECENT: 'A screenshot was taken in the last few seconds',
  OVERLAY_PERMISSION_GRANTED: 'This app can draw over other apps',
  OVERLAY_ABUSE_APP: 'An app known to abuse screen overlays is installed',

  // Hooking frameworks
  FRIDA_IN_MEMORY_MAPS: 'Frida libraries are mapped into the app',
  FRIDA_THREAD: 'A Frida thread is running in the app',
  FRIDA_GLIB_THREAD: 'GLib threads typical of Frida are running in the app',
  FRIDA_FILE_DESCRIPTOR: 'The app holds a Frida pipe or socket open',
  FILE_API_HOOKED:
    'File APIs are hooked to hide root or instrumentation files from the app',
  FRIDA_PORT_OPEN: "Something is listening on Frida's default port",
  FRIDA_DYLIB: 'A Frida library is loaded in the app',
  FRIDA_SYMBOL: 'Frida agent code is loaded in the app',
  FRIDA_DYLD_INSERT: 'Frida is being injected via DYLD_INSERT_LIBRARIES',
  HOOKING_FRAMEWORK_DYLIB: 'A function-hooking framework is loaded in the app',
  XPOSED_BRIDGE_CLASS: 'Xposed classes are loaded in the app',
  XPOSED_FRAMEWORK_FILE: 'The Xposed framework is installed in /system',
  XPOSED_MANAGER_APP: 'An Xposed manager app is installed',
  LSPOSED_CLASS: 'LSPosed classes are loaded in the app',
  LSPOSED_MANAGER_APP: 'The LSPosed manager app is installed',
  LSPOSED_FILES: 'LSPosed files are present on the device',
  SUBSTRATE_APP: 'Cydia Substrate is installed',
  SUBSTRATE_FILES: 'Cydia Substrate files are present',
  RIRU_FILES: 'Riru (Zygote injection) files are present',
  SUBSTRATE_IN_MEMORY_MAPS: 'Cydia Substrate is mapped into the app',

  // Integrity
  DEBUG_BUILD: 'Not evaluated in debug builds',
  DEBUGGABLE_RELEASE_BUILD:
    'A release build is marked debuggable (likely repackaged)',
  NO_INSTALLER_RECORDED: 'The app was sideloaded (no installer recorded)',
  DEVELOPMENT_SIGNED_RELEASE:
    'A release build is signed with a development profile (likely re-signed)',
  SIGNATURE_MISMATCH: "The app's signer doesn't match any expected signer",
  SIGNATURE_HASH_NOT_CONFIGURED: 'No expected signers are configured',
  APK_HASH_MISMATCH: "The APK's SHA-256 doesn't match the expected hash",
  APK_HASH_NOT_CONFIGURED: 'No expected APK hash was provided',
};

/** Human-readable text for a reason code; unknown codes are returned as-is. */
export function describeReason(code: string): string {
  return REASON_DESCRIPTIONS[code] ?? code;
}
