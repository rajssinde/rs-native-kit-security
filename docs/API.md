# API Reference

```ts
import Security from '@rs-native-kit/security';
// or named imports:
import { scan, checkRoot, addListener } from '@rs-native-kit/security';
```

## Results, not booleans

Every check resolves to a `DetectionResult`. A check that couldn't run never looks clean:

```ts
interface DetectionResult {
  status: 'detected' | 'not_detected' | 'unsupported' | 'not_configured' | 'error';
  reasons: string[];          // reason codes, e.g. ['SU_BINARY_FOUND', 'MAGISK_MOUNTS']
  confidence: 'low' | 'medium' | 'high';
  error?: string;             // why signals failed to run
}
```

| Status | Meaning |
|---|---|
| `detected` | At least one signal fired. `reasons` says which; `confidence` is the strongest fired signal's. |
| `not_detected` | Every signal ran and none fired. **Not proof of safety** — a capable attacker can hide from on-device checks, so this is at most `medium` confidence, and `low` if some signals failed to run (see `error`). |
| `unsupported` | The concept doesn't exist on this platform (e.g. root on iOS). |
| `not_configured` | The check needs configuration you haven't provided (e.g. expected signers), so nothing was verified. |
| `error` | The check failed to run. Its outcome is unknown. |

```ts
const root = await Security.checkRoot();
if (root.status === 'detected') {
  console.log(root.reasons.map(Security.describeReason));
}
// shorthand:
if (Security.isDetected(root)) { /* ... */ }
```

Reason codes are a stable contract — log and alert on them. `describeReason(code)` gives display text (it may change between releases); `REASON_DESCRIPTIONS` has the full catalogue.

All checks run off the JS thread (Kotlin/Swift `Promise.parallel`). An individual `checkX()` rejects only when the platform itself is unsupported (e.g. web); detection failures come back as `status: 'error'`.

## Individual checks

| Method | Android | iOS | Notes |
|---|---|---|---|
| `checkRoot()` | ✅ | `unsupported` | `su` binary, root-manager apps, build props, SELinux, writable/remounted system partitions |
| `checkMagisk()` | ✅ | `unsupported` | App, files, binary, mount-table traces. DenyList/Zygisk hiding can defeat it |
| `checkBusyBox()` | ✅ | `unsupported` | |
| `checkJailbreak()` | `unsupported` | ✅ | Files, Cydia URL scheme, sandbox escape, tweak injectors, process spawn |
| `checkEmulator()` | ✅ | ✅ (Simulator) | Exact on iOS (compile-time flag); signal-based on Android |
| `checkDeveloperMode()` | ✅ | low confidence | iOS: embedded provisioning profile presence |
| `checkUsbDebugging()` | ✅ | `unsupported` | No iOS equivalent |
| `checkDebugger()` | ✅ (Java/JDWP) | ✅ (`P_TRACED`) | Independent of the JS debugger |
| `checkMockLocation()` | ✅ | best-effort | iOS needs location permission and a cached fix; otherwise `not_detected` at `low` confidence |
| `checkVpn()` | ✅ | ✅ | No VPN entitlement required |
| `checkProxy()` | ✅ | ✅ | iOS includes PAC (auto-config) proxies |
| `checkScreenRecording()` | low confidence | ✅ | iOS: `UIScreen.isCaptured`. Android has no equivalent API |
| `checkScreenCapture()` | ✅ | ✅ | Screenshot in the last ~5 s. Only observed while an `addListener()` subscription is active |
| `checkOverlay()` | low confidence | `unsupported` | |
| `checkHooks()` | ✅ | ✅ | Umbrella: Frida + Xposed/LSPosed/Substrate/Riru (Android) or hooking-framework dylibs (iOS) |
| `checkFrida()` | ✅ | ✅ | |
| `checkXposed()` | ✅ | `unsupported` | |
| `checkLSPosed()` | ✅ | `unsupported` | |
| `checkTampering()` | ✅ | ✅ | Release builds only — `unsupported` (`DEBUG_BUILD`) in debug builds. See [Security Notes](SECURITY_NOTES.md) |
| `checkSignature(expectedSigners?)` | ✅ | ✅ | `detected` = signer mismatch. Uses `configure()` signers when called without arguments |
| `checkApkIntegrity(sha256)` | ✅ | `unsupported` | Self-distributed APKs only — Play re-signs and splits uploads |
| `getSigningIdentity()` | cert SHA-256 | Team ID | Resolves `Promise<string>`; use it to find the value to configure |

## Configuration

```ts
Security.configure({
  expectedSigners: {
    android: ['AB:CD:…:EF'],   // signing-certificate SHA-256: hex, ":"-separated hex, or base64
    ios: ['AB12CD34EF'],       // Apple Team ID
  },
});
```

Several entries per platform support key rotation and per-environment builds. `configure()` throws `SecurityConfigError` on malformed values, so a typo can't silently disable the check. Without signers, `checks.signature` is `not_configured` and the report lists it in `notConfigured`.

To find the values, log `await Security.getSigningIdentity()` from a **release** build on each platform (for Play App Signing, use the app-signing key from the Play Console, not your upload key).

## `scan()`

```ts
const report: SecurityReport = await Security.scan();
```

```ts
interface SecurityReport {
  platform: 'android' | 'ios';
  secure: boolean;            // riskLevel === 'LOW' && complete
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score: number;              // 0–100
  checks: Record<SecurityCheckKey, DetectionResult>;
  detected: SecurityCheckKey[];
  failed: SecurityCheckKey[];        // status 'error' — outcome unknown
  notConfigured: SecurityCheckKey[]; // nothing was verified
  complete: boolean;                 // no check failed
  reasons: string[];                 // reason codes of detected checks, de-duplicated
  durationMs: number;
  timestamp: number;
}
```

`scan()` runs every check once on a background thread and returns one consistent snapshot — prefer it over calling each check yourself. It never rejects because a single check failed; that check is listed in `failed`.

## Risk engine

```ts
Security.configureRiskEngine({
  weights: { frida: 80, root: 40 },     // merge-overrides specific weights
  thresholds: { medium: 20, high: 40, critical: 60 },
  failedCheckPenalty: 1,                // 0–1, default 1
});

Security.resetRiskEngine(); // back to library defaults
```

- Each `detected` check adds its weight. See [`DEFAULT_RISK_WEIGHTS`](../src/risk/weights.ts).
- **Failed checks fail closed:** a check with status `error` adds `weight × failedCheckPenalty` (default: its full weight), and any failed check makes `secure` false regardless of score.
- `unsupported` and `not_configured` checks never add to the score.
- **No double counting:** checks reporting the same threat are grouped (`RISK_GROUPS`) — `hooks`/`frida`/`xposed`/`lsposed`, and `root`/`magisk`/`busybox`. A group contributes only its highest triggered weight, so one Frida detection scores 50, not 100.

The engine is pure TypeScript, so you can retune it per environment without a native rebuild. It runs on the device, so a compromised client can tamper with it — never let your server trust a client-reported score on its own (see [Security Notes](SECURITY_NOTES.md)).

## Event system

```ts
const unsubscribe = Security.addListener((event: SecurityEvent) => {
  console.log(event.type, event.message, event.timestamp);
});

// later
unsubscribe();
// or
Security.removeListener(listener);
Security.removeAllListeners();
```

```ts
type SecurityEventType =
  | 'ROOT_DETECTED' | 'JAILBREAK_DETECTED'
  | 'VPN_CONNECTED' | 'PROXY_ENABLED'
  | 'SCREENSHOT' | 'SCREEN_RECORDING'
  | 'HOOK_DETECTED' | 'DEBUGGER'
  | 'TAMPER' | 'SIGNATURE_INVALID';
```

Native monitoring starts on the first `addListener()` call and stops automatically once the last listener unsubscribes. `SCREENSHOT`/`SCREEN_RECORDING`/`VPN_CONNECTED` (and more) are driven by real OS push notifications where the platform provides one; everything else is re-evaluated on a ~4s poll and only fires on a false→true transition (see [Security Notes](SECURITY_NOTES.md#event-system-push-vs-poll)). Unknown native event types are dropped, never remapped to another threat. `SIGNATURE_INVALID` is reserved and not emitted yet.

## Protection

| Method | Android | iOS |
|---|---|---|
| `setScreenCaptureProtection(enabled)` | `FLAG_SECURE` on every activity: screenshots/recordings black, hidden in recents | Covers the app while the screen is recorded/mirrored and in the app switcher (screenshots can't be blocked on iOS) |
| `setOverlayProtection(enabled)` | Hides other apps' overlays (12+) and drops touches through overlays | Resolves `false` — no overlays on iOS |

Both resolve whether protection is now active and stay applied, across activity recreation, until disabled.

## Attestation

| Method | Android | iOS | Notes |
|---|---|---|---|
| `prepareIntegrityToken(cloudProjectNumber)` | ✅ | rejects | Warm up once; takes a few seconds |
| `requestIntegrityToken(requestData)` | ✅ | rejects | Token's `requestHash` = hex SHA-256 of `requestData` |
| `isAppAttestSupported()` | `false` | ✅ | iOS 14+ physical device |
| `generateAppAttestKey()` | rejects | ✅ | Resolves `keyId`; persist it |
| `attestAppAttestKey(keyId, challenge)` | rejects | ✅ | Base64 attestation object; `clientDataHash` = SHA-256 of `challenge` |
| `generateAppAttestAssertion(keyId, clientData)` | rejects | ✅ | Base64 assertion; `clientDataHash` = SHA-256 of `clientData` |

These produce tokens for **your server** to verify with [`@rs-native-kit/security-server`](../server/README.md). See [Attestation](ATTESTATION.md) for the full flow.

## SSL pinning helpers

This SDK does not intercept network traffic — RN networking is owned by your app (OkHttp on Android, `URLSession` on iOS). These are typed helpers for assembling the pin config you hand to your networking layer:

```ts
import { buildCertificatePin, isValidPinFormat, isValidPinSet, hasExpiredPins } from '@rs-native-kit/security';

const pin = buildCertificatePin('api.example.com', ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='], Date.now() + 90 * 86_400_000);

if (hasExpiredPins([pin])) {
  // rotate before your pin set hard-fails all requests
}
```

## Types

All public types are exported from the package root: `SecurityReport`, `SecurityChecks`, `SecurityCheckKey`, `SECURITY_CHECK_KEYS`, `DetectionResult`, `DetectionStatus`, `Confidence`, `SecurityConfig`, `RiskLevel`, `RiskWeights`, `RiskThresholds`, `RiskEngineConfig`, `SecurityEvent`, `SecurityEventType`, `SecurityEventListener`, `CertificatePin`, `SecurityUnsupportedPlatformError`, `SecurityConfigError`.
