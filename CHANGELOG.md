# Changelog

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/); see [docs/MIGRATION.md](docs/MIGRATION.md#version-policy) for the versioning policy.

## [0.1.0] - Unreleased

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
