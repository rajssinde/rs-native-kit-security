# @rs-native-kit/security

Enterprise-grade React Native security SDK for Android and iOS — root/jailbreak/emulator/hook detection, tamper & signature integrity, VPN/proxy/screen monitoring, SSL pinning helpers, and a configurable device risk engine. Built on [Nitro Modules](https://nitro.margelo.com/) for the New Architecture: JSI-direct calls, no bridge serialization, thread-safe by design.

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
- **Integrity:** app signature hash + verification, APK integrity (Android), tamper heuristics.
- **SSL pinning helpers:** typed certificate-pin builder/validator utilities.
- **Device risk engine:** configurable weighted scoring → `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.
- **Real-time event system:** subscribe to root/jailbreak/VPN/proxy/screenshot/hook/debugger/tamper events as they happen.

## Installation

```sh
npm install @rs-native-kit/security react-native-nitro-modules
```

`react-native-nitro-modules` is a required peer dependency — see [Installation](docs/INSTALLATION.md) for platform setup (Podfile, permissions, ProGuard/R8).

## Quick start

```ts
import Security from '@rs-native-kit/security';

const rooted = await Security.isRooted();
const jailbroken = await Security.isJailbroken();
const report = await Security.scan();

console.log(report.riskLevel, report.score, report.secure);
```

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
- [Security Notes](docs/SECURITY_NOTES.md)
- [FAQ](docs/FAQ.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Best Practices](docs/BEST_PRACTICES.md)

## Architecture

- **Nitro Modules, not hand-written TurboModules.** Nitro is a JSI-based, New-Architecture-only module system: synchronous-capable, strongly-typed, no bridge serialization. It satisfies the intent behind "TurboModules/Fabric support" better than a manual TurboModule codegen would for a module with no native UI component (Fabric doesn't apply here — there's nothing to render).
- **One native `Security` HybridObject**, composed internally from focused detector classes (`RootDetector`, `EmulatorDetector`, `HookDetector`, ... — see `android/src/main/java/.../detectors` and `ios/Detectors`), so the native code stays modular without multiplying JS↔native bridge objects.
- **The risk engine lives in TypeScript** (`src/risk/`), not native — native `scan()` returns raw `checks`/`reasons`, and the JS-side `RiskEngine` computes `score`/`riskLevel`/`secure` from configurable weights/thresholds. This lets you tune scoring without a native rebuild.
- **Every category is independently importable**: `import { isRooted } from '@rs-native-kit/security/root'`-style trees under `src/{root,jailbreak,emulator,...}`, so bundlers can tree-shake unused checks.

## Example app

`example/` is a working dashboard (security score, per-check grid, live event log, refresh button) — see [Examples](docs/EXAMPLES.md#running-the-example-app) to run it.

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
