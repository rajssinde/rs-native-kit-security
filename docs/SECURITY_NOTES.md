# Security Notes

Read this before shipping to a banking, fintech, healthcare, or government app. **No on-device SDK — this one included — is a substitute for server-side verification.** Anything running inside the app process can, in principle, be inspected or patched by an attacker who controls the device. This SDK raises the cost of tampering and gives you real, actionable signal; it does not make bypass impossible.

## Threat model

This SDK is designed to detect **opportunistic and semi-sophisticated** threats:

- A user's own rooted/jailbroken device (most fraud rings run on cheap, rooted farms of real or emulated devices).
- Off-the-shelf instrumentation (Frida, Xposed/LSPosed) used to automate credential stuffing, coupon abuse, or replay attacks.
- Basic repackaging (a modified APK/IPA redistributed through a third-party store).
- Casual observation (VPN/proxy MITM setups, screen recording of sensitive screens).

It is **not** designed to stop a well-resourced, targeted attacker who statically patches the app binary to always return "not detected" — no client-side check can, because the attacker controls the exact process running the check. For that threat class, use:

- **Server-side attestation**: [Android Play Integrity API](https://developer.android.com/google/play/integrity) and [Apple App Attest](https://developer.apple.com/documentation/devicecheck)/DeviceCheck. These are cryptographically anchored to the OS/hardware and cannot be spoofed by patching your app — they're the correct tool for a hard guarantee, and this SDK is complementary to them, not a replacement.
- **Certificate/public-key pinning** enforced in your networking layer (this SDK's `ssl/` helpers assist with building the pin config, but the actual enforcement must live in OkHttp/`URLSession`).
- **Server-side risk scoring** that combines this SDK's client-reported signal with request-pattern anomaly detection, device fingerprinting, and behavioral signals you can't get from any client SDK.

## What "zero-config" checks can and can't tell you

- `scan()`'s `signatureValid` is always `true` in the default, zero-config call — there is no "known good" hash to compare against without you supplying one. **Call `verifyAppSignature(expectedHash)` with a hash you pin at build time for an authoritative signature check.**
- `isTampered()` is a heuristic (a debuggable, sideloaded, or development-signed *release* build; always `false` in debug builds), not a cryptographic guarantee. It will not catch a competently repackaged app re-signed with a valid certificate — see [Integrity checks](#integrity-checks) below.

## Integrity checks

- **Android** reads the real signing certificate via `PackageManager` (`GET_SIGNING_CERTIFICATES`), so `getAppSignatureHash()`/`verifyAppSignature()` are a genuine cryptographic fingerprint of the installed APK's signer.
- **iOS has no equivalent runtime API.** Apple's Code Signing Services (`SecStaticCodeCheckValidity` and friends) are **macOS-only** — they don't exist in the iOS SDK at all, and there's no other public API to read your own signing certificate from inside a running iOS app (by design — the OS enforces code signing before your code ever executes, so it doesn't need to expose a re-verification API to you). This SDK's iOS `getAppSignatureHash()` hashes the embedded provisioning profile (Development/Ad Hoc/Enterprise builds) or the bundle's `CodeResources` manifest (App Store builds) as a practical fingerprint of "did this exact build's signing identity change" — it is **not** cryptographic proof of signature validity the way the Android check is. For a hard iOS integrity guarantee, use App Attest.

## Event system: push vs. poll

Real OS push sources (accurate, event-driven, no polling latency):

| Event | Android | iOS |
|---|---|---|
| `SCREENSHOT` | `MediaStore` `ContentObserver` | `UIApplication.userDidTakeScreenshotNotification` |
| `SCREEN_RECORDING` | — (polled) | `UIScreen.capturedDidChangeNotification` |
| `VPN_CONNECTED` / `PROXY_ENABLED` | `ConnectivityManager.NetworkCallback` | — (polled) |

Everything else (`ROOT_DETECTED`, `JAILBREAK_DETECTED`, `HOOK_DETECTED`, `DEBUGGER`, `TAMPER`) is re-evaluated on a ~4-second poll and only emitted on a false→true transition, because Android/iOS don't expose a push API for "root state changed" or "a debugger just attached." A 4-second detection latency is the tradeoff for not running detection logic continuously on a tight loop (battery/CPU).

## Platform asymmetry is intentional, not a bug

Several checks are meaningful on one platform and hard-coded `false`/`true` on the other (`isRooted`/`isJailbroken`, `hasOverlayPermission`, `isXposedDetected`, etc. — see the [API reference](API.md) table). This SDK never fabricates a plausible-looking answer for a concept that doesn't exist on a platform; it reports the honest "not applicable" value instead of guessing.

## Web/unsupported platforms

If this package is somehow loaded on a platform Nitro doesn't support (e.g. bundled for `react-native-web`), every detection method **throws `SecurityUnsupportedPlatformError`** rather than silently returning `false`/"secure." A security SDK reporting a false negative is worse than it crashing loudly. Handle this explicitly if your app has a web target (see the example app's error-state UI for a pattern).

## Verification status of this implementation

Everything in this SDK compiles and links into a real, running app on both platforms (verified via full Android APK builds and full iOS simulator + device builds during development). What has **not** been empirically validated in this environment: detection *accuracy* against an actual rooted/jailbroken device, an actual Frida-attached process, or an actual repackaged/tampered build — that requires physical compromised test devices and a live pentest, which is outside what a development sandbox can provide. **Before shipping to production, especially for a regulated app, commission a penetration test against real compromised devices and Frida/Xposed/LSPosed-instrumented processes.**
