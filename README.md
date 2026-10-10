# @rs-native-kit/security

[![npm version](https://img.shields.io/npm/v/@rs-native-kit/security.svg)](https://www.npmjs.com/package/@rs-native-kit/security)
[![npm downloads](https://img.shields.io/npm/dm/@rs-native-kit/security.svg)](https://www.npmjs.com/package/@rs-native-kit/security)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Platform: iOS | Android](https://img.shields.io/badge/platform-iOS%20%7C%20Android-lightgrey.svg)](#installation)

**Root detection, jailbreak detection, and mobile app security for React Native.** Enterprise-grade security SDK for Android and iOS — root/jailbreak/emulator/hook detection, tamper & signature integrity, VPN/proxy/screen monitoring, SSL pinning helpers, and a configurable device risk engine. Built on [Nitro Modules](https://nitro.margelo.com/) for the New Architecture: JSI-direct calls, no bridge serialization, thread-safe by design.

If you're evaluating a **React Native root detection library**, a **jailbreak detection SDK**, or an **RASP (runtime application self-protection)** solution for a banking, fintech, or otherwise security-sensitive app, this covers root/jailbreak, Frida/Xposed/Magisk hook detection, tamper/integrity checks, SSL pinning, and a scored device-risk engine in one package.

> **Status:** functional on Android (root/emulator/hook/network/screen/integrity — verified via real device+emulator builds) and iOS (jailbreak/simulator/hook/network/screen/integrity — verified via simulator+device builds). Read [Security Notes](docs/SECURITY_NOTES.md) before shipping to production, especially for regulated (banking/healthcare) apps — no on-device SDK is a substitute for server-side verification.

## Features

- **Root detection (Android):** su binary scan, BusyBox, Magisk, RW `/system`, dangerous build props, SELinux state, suspicious mounts, known root-manager apps.
- **Jailbreak detection (iOS):** suspicious file scan, Cydia URL scheme, sandbox-escape write test, loaded-dylib inspection, process-spawn probe, suspicious env vars.
- **Emulator / Simulator detection** on both platforms.
- **Hook detection:** Frida (both platforms), Xposed/LSPosed/EdXposed/Substrate/Riru (Android).
- **Developer/debug state:** developer mode, USB debugging, attached debugger, mock location.
- **Network monitoring:** VPN and proxy detection.
- **Screen monitoring:** screen recording/mirroring, screenshot detection.
- **Overlay exposure** (Android).
- **Integrity:** signer verification (Android signing-certificate SHA-256, iOS Team ID from the code signature), APK integrity (Android), tamper heuristics.
- **SSL pinning helpers:** typed certificate-pin builder/validator utilities.
- **Platform attestation:** Play Integrity (Android) and App Attest (iOS) client APIs, plus a zero-dependency Node verifier ([`server/`](server/README.md)) — the signal a compromised device can't fake.
- **Device risk engine:** configurable weighted scoring → `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`. Failed checks fail closed; related findings aren't double-counted.
- **Real-time event system:** subscribe to root/jailbreak/VPN/proxy/screenshot/hook/debugger/tamper events as they happen.

## Installation

```sh
npm install @rs-native-kit/security react-native-nitro-modules
```

`react-native-nitro-modules` is a required peer dependency — see [Installation](docs/INSTALLATION.md) for platform setup (Podfile, permissions, ProGuard/R8).

## Quick start

```ts
import Security from '@rs-native-kit/security';

Security.configure({
  expectedSigners: { android: ['<signing cert SHA-256>'], ios: ['<Team ID>'] },
});

const report = await Security.scan();
console.log(report.riskLevel, report.score, report.secure);
console.log(report.detected, report.reasons); // e.g. ['root'], ['SU_BINARY_FOUND']

const frida = await Security.checkFrida();
// { status: 'detected' | 'not_detected' | 'unsupported' | 'not_configured' | 'error', reasons, confidence }
```

Every check reports one of five statuses, so a check that couldn't run, or that has nothing configured to verify against, is never mistaken for a clean result.

```ts
const unsubscribe = Security.addListener((event) => {
  console.log(event.type, event.message);
});
```

See the [API reference](docs/API.md) for the full surface and [Examples](docs/EXAMPLES.md) for common integration patterns (login gating, risk-based step-up auth, dashboards).

## Documentation

- [Installation](docs/INSTALLATION.md)
- [API Reference](docs/API.md)
- [Examples](docs/EXAMPLES.md)
- [Migration Guide](docs/MIGRATION.md)
- [Attestation (Play Integrity & App Attest)](docs/ATTESTATION.md)
- [Security Notes](docs/SECURITY_NOTES.md)
- [FAQ](docs/FAQ.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Best Practices](docs/BEST_PRACTICES.md)

## Architecture

- **Nitro Modules, not hand-written TurboModules.** Nitro is a JSI-based, New-Architecture-only module system: synchronous-capable, strongly-typed, no bridge serialization. It satisfies the intent behind "TurboModules/Fabric support" better than a manual TurboModule codegen would for a module with no native UI component (Fabric doesn't apply here — there's nothing to render).
- **One native `Security` HybridObject**, composed internally from focused detector classes (`RootDetector`, `EmulatorDetector`, `HookDetector`, ... — see `android/src/main/java/.../detectors` and `ios/Detectors`), so the native code stays modular without multiplying JS↔native bridge objects.
- **The risk engine lives in TypeScript** (`src/risk/`), not native — native `scan()` returns raw `checks`/`reasons`, and the JS-side `RiskEngine` computes `score`/`riskLevel`/`secure` from configurable weights/thresholds. This lets you tune scoring without a native rebuild.
- **Every check is a named export** (`import { checkRoot } from '@rs-native-kit/security'`), organised by category under `src/{root,jailbreak,emulator,...}`.

## Example app

`example/` is a working dashboard (security score, per-check grid, live event log, refresh button) — see [Examples](docs/EXAMPLES.md#running-the-example-app) to run it.

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT
