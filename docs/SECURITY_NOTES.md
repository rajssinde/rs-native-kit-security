# Security Notes

Read this before shipping to a banking, fintech, healthcare, or government app. **No on-device SDK — this one included — is a substitute for server-side verification.** Anything running inside the app process can, in principle, be inspected or patched by an attacker who controls the device. This SDK raises the cost of tampering and gives you real, actionable signal; it does not make bypass impossible.

## Threat model

This SDK is designed to detect **opportunistic and semi-sophisticated** threats:

- A user's own rooted/jailbroken device (most fraud rings run on cheap, rooted farms of real or emulated devices).
- Off-the-shelf instrumentation (Frida, Xposed/LSPosed) used to automate credential stuffing, coupon abuse, or replay attacks.
- Basic repackaging (a modified APK/IPA redistributed through a third-party store).
- Casual observation (VPN/proxy MITM setups, screen recording of sensitive screens).

It is **not** designed to stop a well-resourced, targeted attacker who statically patches the app binary to always return "not detected" — no client-side check can, because the attacker controls the exact process running the check. For that threat class, use:

- **Server-side attestation** — built in: see [Attestation](ATTESTATION.md) and the [`server/`](../server/README.md) verifier. [Android Play Integrity API](https://developer.android.com/google/play/integrity) and [Apple App Attest](https://developer.apple.com/documentation/devicecheck)/DeviceCheck. These are cryptographically anchored to the OS/hardware and cannot be spoofed by patching your app — they're the correct tool for a hard guarantee, and this SDK is complementary to them, not a replacement.
- **Certificate/public-key pinning** enforced in your networking layer (this SDK's `ssl/` helpers assist with building the pin config, but the actual enforcement must live in OkHttp/`URLSession`).
- **Server-side risk scoring** that combines this SDK's client-reported signal with request-pattern anomaly detection, device fingerprinting, and behavioral signals you can't get from any client SDK.

## What "zero-config" checks can and can't tell you

- Without `configure({ expectedSigners })`, `scan()` reports `checks.signature` as `not_configured` and lists it in `report.notConfigured` — it never claims a signature it didn't verify is valid. **Configure expected signers for every production build.**
- A check that fails to run reports `status: 'error'`. `scan()` lists it in `failed`, sets `complete: false`, makes `secure` false, and by default scores it like a detection (`failedCheckPenalty`, fail closed).
- `not_detected` is at most `medium` confidence: on-device checks can be hidden from. Treat it as absence of evidence, not evidence of safety.
- `checkTampering()` is a heuristic (a debuggable, sideloaded, or development-signed *release* build; `unsupported` in debug builds), not a cryptographic guarantee. It will not catch a competently repackaged app re-signed with a valid certificate — see [Integrity checks](#integrity-checks) below.

## Integrity checks

- **Android** reads the current signing certificate via `PackageManager` (`GET_SIGNING_CERTIFICATES`, current signers, so key rotation is handled), so `checkSignature()` compares a genuine fingerprint of the installed APK's signer. With Play App Signing, the expected value is Google's app-signing key from the Play Console, not your upload key.
- **iOS has no API for an app to read its own signing certificate**, and App Store binaries are re-signed with Apple's certificate, so a certificate hash would be identical for every App Store app. What does identify who built the app is the **Team ID** in the signed entitlements of the app's own code signature (`application-identifier` = `TEAMID.bundle.id`) — re-signing an IPA under another account changes it. `checkSignature()` parses that from the app binary's `LC_CODE_SIGNATURE` and compares it to the Team IDs you configure. It's a strong local signal, but an attacker who patches the comparison defeats it; for a guarantee the device can't fake, use App Attest.

## Event system: push vs. poll

Real OS push sources (accurate, event-driven, no polling latency):

| Event | Android | iOS |
|---|---|---|
| `SCREENSHOT` | `MediaStore` `ContentObserver` | `UIApplication.userDidTakeScreenshotNotification` |
| `SCREEN_RECORDING` | — (polled) | `UIScreen.capturedDidChangeNotification` |
| `VPN_CONNECTED` / `PROXY_ENABLED` | `ConnectivityManager.NetworkCallback` | — (polled) |

Everything else (`ROOT_DETECTED`, `JAILBREAK_DETECTED`, `HOOK_DETECTED`, `DEBUGGER`, `TAMPER`) is re-evaluated on a ~4-second poll and only emitted on a false→true transition, because Android/iOS don't expose a push API for "root state changed" or "a debugger just attached." A 4-second detection latency is the tradeoff for not running detection logic continuously on a tight loop (battery/CPU).

## Platform asymmetry is intentional, not a bug

Several checks are meaningful on only one platform (`checkRoot`/`checkJailbreak`, `checkOverlay`, `checkXposed`, etc. — see the [API reference](API.md) table). On the other platform they report `status: 'unsupported'` rather than a plausible-looking `false`, and never add to the risk score.

## Web/unsupported platforms

If this package is somehow loaded on a platform Nitro doesn't support (e.g. bundled for `react-native-web`), every detection method **throws `SecurityUnsupportedPlatformError`** rather than silently returning `false`/"secure." A security SDK reporting a false negative is worse than it crashing loudly. Handle this explicitly if your app has a web target (see the example app's error-state UI for a pattern).

## Verification status of this implementation

Everything in this SDK compiles and links into a real, running app on both platforms (verified via full Android APK builds and full iOS simulator + device builds during development). What has **not** been empirically validated in this environment: detection *accuracy* against an actual rooted/jailbroken device, an actual Frida-attached process, or an actual repackaged/tampered build — that requires physical compromised test devices and a live pentest, which is outside what a development sandbox can provide. **Before shipping to production, especially for a regulated app, commission a penetration test against real compromised devices and Frida/Xposed/LSPosed-instrumented processes.**
