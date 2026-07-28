# API Reference

```ts
import Security from '@rs-native-kit/security';
// or, tree-shakeable named imports:
import { isRooted, scan, addListener } from '@rs-native-kit/security';
```

All detection methods are `async` and return `Promise<boolean>` (or `Promise<string>` for hashes). They run off the JS thread on both platforms (Kotlin `Promise.parallel` / Swift `Promise.parallel`), so they never block rendering.

## Individual checks

| Method | Android | iOS | Notes |
|---|---|---|---|
| `isRooted()` | ✅ | always `false` | Root is an Android-only concept |
| `isMagiskDetected()` | ✅ | always `false` | |
| `isBusyBoxDetected()` | ✅ | always `false` | |
| `isJailbroken()` | always `false` | ✅ | Jailbreak is an iOS-only concept |
| `isEmulator()` | ✅ | ✅ (Simulator) | 100% accurate on iOS (compile-time flag); heuristic on Android |
| `isDeveloperModeEnabled()` | ✅ | best-effort | iOS: embedded provisioning profile presence |
| `isUsbDebuggingEnabled()` | ✅ | always `false` | No iOS equivalent (Xcode uses a paired trust relationship, not a toggle) |
| `isDebuggerAttached()` | ✅ | ✅ | Native debugger attach, independent of the JS debugger |
| `isMockLocationEnabled()` | ✅ | best-effort | iOS: only detectable once a `CLLocation` fix with `sourceInformation` has been delivered |
| `isVpnConnected()` | ✅ | ✅ | Interface/transport scan — no VPN entitlement required |
| `isProxyEnabled()` | ✅ | ✅ | |
| `isScreenRecording()` | heuristic | ✅ (accurate) | iOS has a direct API (`UIScreen.isCaptured`); Android does not |
| `isScreenCaptured()` | ✅ | ✅ | "was a screenshot just taken" — true for ~5s after a screenshot event |
| `hasOverlayPermission()` | ✅ | always `false` | No overlay permission model on iOS |
| `isHookDetected()` | ✅ | ✅ | Umbrella: Frida + (Android) Xposed/LSPosed/Substrate/Riru |
| `isFridaDetected()` | ✅ | ✅ | |
| `isXposedDetected()` | ✅ | always `false` | Android-only framework |
| `isLSPosedDetected()` | ✅ | always `false` | Android-only framework |
| `isTampered()` | ✅ | ✅ | Zero-config heuristic — see [Security Notes](SECURITY_NOTES.md) |
| `getAppSignatureHash()` | ✅ | ✅ | Returns `Promise<string>` |
| `verifyAppSignature(hash)` | ✅ | ✅ | Compares against a hash you pin at build time |
| `verifyApkIntegrity(sha256)` | ✅ | always `true` | APK is an Android concept |
| `isSslPinningSupported()` | always `true` | always `true` | Informational — see [pinning helpers](#ssl-pinning-helpers) |

## `scan()`

```ts
const report: SecurityReport = await Security.scan();
```

```ts
interface SecurityReport {
  platform: 'android' | 'ios';
  secure: boolean;       // riskLevel === 'LOW'
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score: number;         // 0–100
  checks: SecurityChecks; // every individual boolean check, flattened
  reasons: string[];     // human-readable explanation per triggered check
  timestamp: number;
}
```

`scan()` runs every native check once and reuses the results — prefer it over calling every `isX()` individually when you want the full picture (fewer JSI round-trips, one consistent snapshot).

## Risk engine

```ts
import { configureRiskEngine, resetRiskEngine, DEFAULT_RISK_WEIGHTS, DEFAULT_RISK_THRESHOLDS } from '@rs-native-kit/security';

Security.configureRiskEngine({
  weights: { frida: 80, root: 40 },      // merge-overrides specific weights
  thresholds: { medium: 20, high: 40, critical: 60 },
});

Security.resetRiskEngine(); // back to library defaults
```

The engine is pure TypeScript (`src/risk/`) — it consumes the raw `checks`/`reasons` from native `scan()` and computes `score`/`riskLevel`/`secure`. This means you can retune scoring per-environment (e.g. stricter thresholds in a banking app vs. a loyalty app) without a native rebuild. See [DEFAULT_RISK_WEIGHTS](../src/risk/weights.ts) for the full default table.

`signatureValid` and `sslPinningSupported` are the two checks where `true` is the *good* outcome — the engine accounts for this automatically (risk is contributed when they're `false`, not `true`).

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

Native monitoring starts on the first `addListener()` call and stops automatically once the last listener unsubscribes — you don't need to manage lifecycle manually. `SCREENSHOT`/`SCREEN_RECORDING`/`VPN_CONNECTED` (and more) are driven by real OS push notifications where the platform provides one; everything else is re-evaluated on a ~4s poll and only fires on a false→true transition (see [Security Notes](SECURITY_NOTES.md#event-system-push-vs-poll) for exactly which is which).

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

All public types are exported from the package root: `SecurityReport`, `SecurityChecks`, `SecurityCheckKey`, `RiskLevel`, `SecurityEvent`, `SecurityEventType`, `SecurityEventListener`, `RiskWeights`, `RiskThresholds`, `RiskEngineConfig`, `CertificatePin`, `SecurityUnsupportedPlatformError`.
