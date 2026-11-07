# Migration Guide

## From other security libraries

### `jail-monkey`

| jail-monkey | @rs-native-kit/security |
|---|---|
| `JailMonkey.isJailBroken()` | `(await Security.scan()).detected` includes `'root'` (Android) / `'jailbreak'` (iOS) |
| `JailMonkey.canMockLocation()` | `Security.isDetected(await Security.checkMockLocation())` |
| `JailMonkey.trustFall()` | `isJailBroken() \|\| canMockLocation()` — use `scan()` and decide on `riskLevel` |
| `JailMonkey.isOnExternalStorage()` | not covered — out of scope |
| `JailMonkey.hookDetected()` | `Security.isDetected(await Security.checkHooks())` |

Key difference: jail-monkey's `isJailBroken()` is a single cross-platform boolean; this SDK splits root (Android) and jailbreak (iOS) into distinct, platform-honest methods so you're never asking an Android device "is this jailbroken."

### `expo-device` / `react-native-device-info` (root/emulator bits)

Both are single-purpose; this SDK is a superset. Every check returns a result object rather than a boolean — use `isDetected()` where you need one:

```diff
- import { isRootedExperimentalAsync } from 'expo-device';
- const rooted = await isRootedExperimentalAsync();
+ import Security from '@rs-native-kit/security';
+ const rooted = Security.isDetected(await Security.checkRoot());
```

```diff
- import DeviceInfo from 'react-native-device-info';
- const isEmulator = await DeviceInfo.isEmulator();
+ import Security from '@rs-native-kit/security';
+ const isEmulator = Security.isDetected(await Security.checkEmulator());
```

`isDetected()` treats `error` as "not detected" — if a check failing to run matters to you, check `status` directly.

You can run this SDK alongside either during a trial migration — they don't conflict (no shared native module names, no shared JS globals).

## Version policy

This package follows semantic versioning:

- **Patch** (`0.1.x`): bug fixes, detection accuracy improvements, doc updates. No API changes.
- **Minor** (`0.x.0`): new checks, new event types, new optional config — always additive, never breaking.
- **Major** (`x.0.0`): reserved for breaking changes (renamed methods, changed `SecurityReport` shape, changed default risk weights in a way that shifts existing `riskLevel` classifications). A dedicated "Migrating to vX" section will be added here for every major release, with a diff-style before/after for every breaking change.

Until `1.0.0`, treat the public API as stable but not yet permanently frozen — default risk *weights* (not the API shape) may be tuned based on real-world false-positive/negative reports.
