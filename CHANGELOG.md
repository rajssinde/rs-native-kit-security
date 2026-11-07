# Changelog

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/); see [docs/MIGRATION.md](docs/MIGRATION.md#version-policy) for the versioning policy.

## [0.1.0]

Initial implementation of the enterprise security SDK.

### Added

- Full TypeScript-first public API: `Security.scan()`, per-category checks (`isRooted`, `isJailbroken`, `isEmulator`, `isDeveloperModeEnabled`, `isUsbDebuggingEnabled`, `isDebuggerAttached`, `isMockLocationEnabled`, `isVpnConnected`, `isProxyEnabled`, `hasOverlayPermission`, `isScreenRecording`, `isScreenCaptured`, `isHookDetected`, `isFridaDetected`, `isXposedDetected`, `isLSPosedDetected`, `isTampered`, `getAppSignatureHash`, `verifyAppSignature`, `verifyApkIntegrity`, `isSslPinningSupported`).
- Configurable, JS-side device risk engine (`configureRiskEngine`/`resetRiskEngine`) producing `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` classifications.
- Real-time event system (`addListener`/`removeListener`/`removeAllListeners`) covering `ROOT_DETECTED`, `JAILBREAK_DETECTED`, `VPN_CONNECTED`, `PROXY_ENABLED`, `SCREENSHOT`, `SCREEN_RECORDING`, `HOOK_DETECTED`, `DEBUGGER`, `TAMPER`, `SIGNATURE_INVALID`.
- SSL pinning helper utilities (`buildCertificatePin`, `isValidPinFormat`, `isValidPinSet`, `hasExpiredPins`).
- Full Android (Kotlin) native implementation: root/Magisk/BusyBox detection, emulator detection, Frida/Xposed/LSPosed/Substrate/Riru hook detection, developer-mode/USB-debugging/mock-location/debugger detection, VPN/proxy monitoring, screen recording/screenshot monitoring, overlay exposure, signature/APK integrity, tamper heuristics.
- Full iOS (Swift) native implementation: jailbreak detection, Simulator detection, Frida hook detection, debugger/mock-location detection, VPN/proxy monitoring, screen recording/screenshot monitoring (via `UIScreen.isCaptured` and screenshot notifications), signature-fingerprint/tamper heuristics.
- Enterprise dashboard example app (security score, per-check grid, live event log, refresh button).
- Full documentation set: Installation, API Reference, Examples, Migration Guide, Security Notes, FAQ, Troubleshooting, Best Practices.

## Detailed notes for the first automated release

### Added

- Platform attestation: Play Integrity Standard requests on Android (`prepareIntegrityToken`, `requestIntegrityToken`) and App Attest on iOS (`isAppAttestSupported`, `generateAppAttestKey`, `attestAppAttestKey`, `generateAppAttestAssertion`). Tokens are bound to a server challenge and the request via SHA-256 of the data you pass.
- `@rs-native-kit/security-server` (`server/`): zero-dependency Node 20+ verifier. App Attest attestation and assertion verification against the pinned Apple root (chain, nonce, key ID, App ID, counter, environment); Play Integrity decoding via a service account and policy evaluation with per-requirement failure codes; single-use challenge store. Tested against real OpenSSL-built certificate chains and ECDSA signatures, plus mutation checks.
- [Attestation guide](docs/ATTESTATION.md).

- Hook-resistant probes: raw-syscall file checks and `/proc` reads (Android arm64 `svc`, C++/JNI; iOS arm64 `svc #0x80`) that bypass Java/FileManager and libc hooks, plus `FILE_API_HOOKED` when they disagree with the regular APIs.
- Android debugger detection via `/proc/self/status` `TracerPid` (native debuggers, ptrace tools); iOS via parent process (`PARENT_NOT_LAUNCHD`).
- Frida: open pipe/socket scan (Android), thread names and agent symbols (iOS).
- iOS rootless jailbreaks (Dopamine, palera1n: `/var/jb`, `/cores/binpack`, ...), symlinked system directories, more package-manager URL schemes, and jailbreak-hiding tweak libraries (Shadow, A-Bypass, FlyJB, ...).
- `setScreenCaptureProtection()` (Android `FLAG_SECURE`; iOS cover while captured / in app switcher) and `setOverlayProtection()` (Android overlay hiding + touch filtering).
- Android 14+ screenshot callbacks and Android 15+ screen-recording callbacks; `SCREEN_RECORDING` events on Android.

- `enableSslPinning()`: enforced public-key pinning on React Native networking — Android via OkHttp `CertificatePinner` on RN's client factory, iOS via a TLS-challenge handler on RN's `RCTHTTPRequestHandler` with SPKI hashing (no third-party dependency). Requires a backup pin per host; skips expired hosts with a warning. Verified on device emulators/simulators: correct pin → 200, wrong pin → blocked, unpinned host unaffected.

- Android Key Attestation: `requestKeyAttestation(challenge)` returns the certificate chain of a throwaway TEE/StrongBox key bound to the challenge. The server's `verifyKeyAttestation()` checks the chain against Google's two pinned hardware roots and its revocation list (`fetchKeyAttestationRevocations()`), rejects leaves forged with a genuine device key, and reports the hardware-signed bootloader-lock and verified-boot state, which root-hiding tools can't change. Tested with OpenSSL-built chains and a real emulator KeyMint chain.
- Root detection for kernel-level root and systemless modules: KernelSU, KernelSU Next, SukiSU Ultra and APatch manager apps; `BOOTLOADER_UNLOCKED` from boot properties read natively (no `getprop` process; `ro.debuggable`/`ro.secure` now read the same way); `SYSTEM_FILE_FROM_DATA` (module files bind-mounted over system files) and `SYSTEM_OVERLAY_MOUNT` (overlayfs over system partitions). The two mount checks don't depend on tool names.
- Deeper debugger, proxy and tamper checks: iOS `CODE_SIGNING_DEBUGGED` (the kernel's `CS_DEBUGGED` flag via a raw `csops` syscall, which stays set after a debugger detaches); Android proxy now also covers `https.proxyHost`/`socksProxyHost` and PAC (`PAC_PROXY`); Android `LSPATCH_REPACKAGED` (LSPatch's component factory or `assets/lspatch/`, which works without root); iOS `SIGNER_IDENTITY_KEY` (cracking-tool Info.plist marker) and `DECRYPTED_APP_STORE_BINARY` (no provisioning profile and `cryptid` 0, e.g. a dumped app reinstalled with TrollStore).
- iOS `JAILBREAK_ROOT_IMAGE`: any library loaded from a jailbreak root (`/var/jb`, or roothide's randomised `.jbroot-*`, which has no fixed path to probe), whatever its name.

- Works with `react-native-nitro-modules` **0.32.0 and newer** (previously only 0.36.x). Ships bindings generated for both sides of Nitro 0.35's breaking change (`nitrogen/generated` for 0.35+, `nitrogen/generated-legacy` from nitrogen 0.34.1 for 0.32 – 0.34); Gradle and the podspec pick the right one from the app's installed version, fail clearly below 0.32, and warn above the newest tested version (`nitro-compat.json`). CI builds every supported Nitro minor plus the newest npm release.

### Fixed (pre-existing)

- Android: older-Android `SCREENSHOT` events fired for every new image (camera photos, downloads); they now require a confirmed screenshot.
- Android: the library ran React Native codegen over the repo's `node_modules/react-native`, compiling RN core specs into the library and breaking release builds with duplicate classes; codegen is now scoped to `src/`.

### Changed (breaking, before first release)

- Every check returns a `DetectionResult` (`status`: `detected` / `not_detected` / `unsupported` / `not_configured` / `error`, plus reason codes and confidence) instead of a boolean. A check that fails to run, doesn't apply to the platform, or has nothing configured to verify against can no longer read as clean. Methods are renamed `isX()` → `checkX()` so old boolean call sites fail to compile instead of silently misbehaving.
- `scan()` reports `detected`, `failed`, `notConfigured` and `complete`; `secure` additionally requires every check to have run. Reasons are machine-readable codes (`describeReason()` for display text) and are no longer duplicated.
- Signature verification is configured once via `configure({ expectedSigners })` and checked by `scan()`; `checks.signature` is `not_configured` until then (previously it always claimed a valid signature). Replaces `verifyAppSignature`/`getAppSignatureHash` with `checkSignature`/`getSigningIdentity`.
- iOS signature verification compares the Team ID read from the app's own code signature, replacing the hash of the provisioning profile / `CodeResources`, which changed on every profile renewal or build.
- Android signature verification uses the current signer, so apps that rotated their signing key no longer read as mismatched; hashes are accepted as hex, `:`-separated hex or base64.
- Risk engine: failed checks fail closed (`failedCheckPenalty`, default 1); related checks (`hooks`/`frida`/`xposed`/`lsposed`, `root`/`magisk`/`busybox`) are grouped so one finding isn't counted twice.
- Unknown native event types are dropped instead of being reported as `TAMPER`.
- Removed `isSslPinningSupported()` (always `true`) and `compareAppSignature()`.
- Android: `su` is no longer executed during root detection — it popped a superuser prompt on rooted devices.
- iOS: proxy detection includes PAC (auto-config) proxies; `DYLD_INSERT_LIBRARIES` is ignored in debug builds, where Xcode sets it itself.

### Fixed

- Android: `isRooted()` reported `true` on almost every device — shell probes like `which su` now count as failed when the command exits non-zero. Shell output is also drained concurrently, so long output (e.g. `getprop`) no longer stalls a check until it times out.
- Android: the read-write mount check flagged legitimately writable mounts such as `/mnt/vendor/persist`; it now matches the exact `/system`, `/vendor`, `/product` and `/system_ext` mount points.
- Android 11+: every installed-app check (root managers, Magisk, Xposed/LSPosed/Substrate, emulators, mock-location and overlay apps) silently reported "not installed" because of package visibility filtering. The library manifest now declares these packages under `<queries>`.
- Android: added a Magisk mount-table signal (`/debug_ramdisk`, `magisk` tmpfs), because SELinux blocks a normal app from the `/data/adb` paths the detector relied on.
- iOS: `isVpnConnected()` reported `true` on almost every device because iOS always keeps system `utun` interfaces up; it now checks the scoped system network settings instead.
- `isTampered()` reported `true` on every debug build (both platforms); its heuristics now run in release builds only.

### Notes

- Built on [Nitro Modules](https://nitro.margelo.com/) (New Architecture only) rather than hand-written TurboModules — see [README Architecture](README.md#architecture) for rationale.
- See [Security Notes](docs/SECURITY_NOTES.md#verification-status-of-this-implementation) for what has and hasn't been empirically validated pre-release.
