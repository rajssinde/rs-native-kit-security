# FAQ

### Why Nitro Modules instead of TurboModules?

Nitro is JSI-based and New-Architecture-only: synchronous-capable calls, strong TypeScript-to-native type generation, and no bridge serialization overhead — meaningfully faster for a module that may run a dozen small checks per `scan()` call. For a module with no native UI component, it's a strict upgrade over hand-written TurboModule codegen; Fabric (the renderer) doesn't apply here either way, since there's nothing to render. See [Architecture](../README.md#architecture).

### Does this work on the Old Architecture?

No. Nitro Modules requires the New Architecture. [Migrate to the New Architecture](https://reactnative.dev/docs/new-architecture-intro) first — it's been the RN default since 0.76.

### Can I run this in the web preview?

The example app's `yarn example web` target exists to preview the **dashboard UI** with `react-native-web`/Vite — it is not a supported detection target. Every detection method throws `SecurityUnsupportedPlatformError` on web rather than pretending the device is secure (see [Security Notes](SECURITY_NOTES.md#web-unsupported-platforms)). Only Android and iOS are real targets.

### Why does `isTampered()` return `true` on my debug build?

That's correct/expected — `isTampered()`'s zero-config heuristic includes "this is a debug/development-signed build" (Android: `FLAG_DEBUGGABLE`; iOS: `get-task-allow` entitlement in the provisioning profile), which is true for every local dev build by design. It should read `false` on a properly signed release/App Store build. If you need a stronger, non-heuristic check, use `verifyAppSignature()`/`verifyApkIntegrity()` with a hash you pin at build time.

### Why is `isRooted()` always `false` on iOS (and `isJailbroken()` always `false` on Android)?

Root and jailbreak are platform-specific concepts. Rather than mapping one onto the other (which every "cross-platform" library that exposes a single `isCompromised()` boolean effectively does, hiding which check actually ran), this SDK keeps them honest and separate. Use `scan()`'s `checks.root`/`checks.jailbreak` if you want a single object to inspect regardless of platform.

### How accurate is emulator detection?

100% on iOS (`targetEnvironment(simulator)` is a compile-time flag baked into the correct binary slice — there's no way for it to be wrong). On Android, it's signal-based (build fingerprint, known emulator packages, QEMU artifacts) and can theoretically be spoofed by a sufficiently customized emulator build, though this covers the common ones (stock AVD, Genymotion, BlueStacks, Nox, MEmu, LDPlayer) reliably.

### Does this intercept my network requests for SSL pinning?

No. `ssl/` ships typed helpers for building/validating a pin set (`buildCertificatePin`, `isValidPinSet`, `hasExpiredPins`) — you still enforce pinning in your networking layer (OkHttp `CertificatePinner` on Android, `URLSessionDelegate` trust evaluation on iOS). See [API Reference](API.md#ssl-pinning-helpers).

### Can I customize which checks contribute to the risk score?

Yes — `Security.configureRiskEngine({ weights, thresholds })`. The engine runs entirely in JS, so this doesn't require a native rebuild. See [Examples](EXAMPLES.md#custom-risk-weighting-for-a-fintech-app).

### Will this get my app rejected from the App Store / Play Store?

No API used here is private or against store policy — root/jailbreak/hook detection, network interface introspection, and provisioning-profile inspection are all standard techniques used by shipped banking/fintech apps. The one behavior worth knowing about: the jailbreak `fork()`/spawn probe (iOS) briefly spawns and immediately terminates a child process as a sandbox-restriction signal — this uses `posix_spawn`, not the raw (Swift-unavailable) `fork()` syscall, and is a well-established technique in shipped App Store apps.

### Does this replace Play Integrity API / App Attest?

No — it complements them. See [Security Notes](SECURITY_NOTES.md#threat-model) for why client-side detection alone can't provide the same guarantee as OS/hardware-anchored attestation, and why you should use both.
