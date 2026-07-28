# Migration Guide

## From other security libraries

### `jail-monkey`

| jail-monkey | @rs-native-kit/security |
|---|---|
| `JailMonkey.isJailBroken()` | `await Security.isRooted()` (Android) / `await Security.isJailbroken()` (iOS) |
| `JailMonkey.canMockLocation()` | `await Security.isMockLocationEnabled()` |
| `JailMonkey.trustFall()` | `await Security.isTampered()` |
| `JailMonkey.isOnExternalStorage()` | not covered — out of scope |
| `JailMonkey.hookDetected()` | `await Security.isHookDetected()` |

Key difference: jail-monkey's `isJailBroken()` is a single cross-platform boolean; this SDK splits root (Android) and jailbreak (iOS) into distinct, platform-honest methods so you're never asking an Android device "is this jailbroken."

### `react-native-root-detection` / `react-native-device-info` (root/emulator bits)

Both are single-purpose; this SDK is a superset. Swap direct calls 1:1:

```diff
- import { isRootedExperimentalAsync } from 'react-native-root-detection';
- const rooted = await isRootedExperimentalAsync();
+ import Security from '@rs-native-kit/security';
+ const rooted = await Security.isRooted();
```

```diff
- import DeviceInfo from 'react-native-device-info';
- const isEmulator = await DeviceInfo.isEmulator();
+ import Security from '@rs-native-kit/security';
+ const isEmulator = await Security.isEmulator();
```

You can run this SDK alongside either during a trial migration — they don't conflict (no shared native module names, no shared JS globals).

## Version policy

This package follows semantic versioning:

- **Patch** (`0.1.x`): bug fixes, detection accuracy improvements, doc updates. No API changes.
- **Minor** (`0.x.0`): new checks, new event types, new optional config — always additive, never breaking.
- **Major** (`x.0.0`): reserved for breaking changes (renamed methods, changed `SecurityReport` shape, changed default risk weights in a way that shifts existing `riskLevel` classifications). A dedicated "Migrating to vX" section will be added here for every major release, with a diff-style before/after for every breaking change.

Until `1.0.0`, treat the public API as stable but not yet permanently frozen — default risk *weights* (not the API shape) may be tuned based on real-world false-positive/negative reports.
