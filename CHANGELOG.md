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

### Notes

- Built on [Nitro Modules](https://nitro.margelo.com/) (New Architecture only) rather than hand-written TurboModules — see [README Architecture](README.md#architecture) for rationale.
- See [Security Notes](docs/SECURITY_NOTES.md#verification-status-of-this-implementation) for what has and hasn't been empirically validated pre-release.
