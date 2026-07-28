# Installation

## Requirements

| | Minimum |
|---|---|
| React Native | 0.72 (New Architecture only — see [FAQ](FAQ.md#does-this-work-on-the-old-architecture)) |
| Android | API 24 (Android 7.0) |
| iOS | 15.1 |
| `react-native-nitro-modules` | ^0.36 |

## 1. Install the package

```sh
npm install @rs-native-kit/security react-native-nitro-modules
# or
yarn add @rs-native-kit/security react-native-nitro-modules
```

`react-native-nitro-modules` is a required **peer dependency** — this library's native module is built on it.

## 2. iOS

```sh
cd ios && pod install
```

No manual Info.plist changes are required for the core detection APIs. Two optional entries improve accuracy:

- **Cydia URL scheme detection** (one of several jailbreak signals): add `cydia` to `LSApplicationQueriesSchemes` in `Info.plist`. Without it, `canOpenURL` for `cydia://` always returns `false` (iOS 9+ policy), so this specific signal is silently skipped — the other jailbreak checks (file scan, sandbox-escape test, dylib inspection, process-spawn probe) still run.

  ```xml
  <key>LSApplicationQueriesSchemes</key>
  <array>
    <string>cydia</string>
  </array>
  ```

## 3. Android

Autolinking handles everything — no manual `MainApplication`/Gradle edits needed. The library declares two permissions in its own manifest, merged automatically into your app:

- `android.permission.INTERNET` — used only for a local loopback socket probe against Frida's default ports (`isFridaDetected`/`isHookDetected`). Nearly every RN app already has this permission for networking.
- `android.permission.ACCESS_NETWORK_STATE` — used for VPN/proxy transport checks.

### ProGuard / R8

If you enable code shrinking, no extra rules are needed for consumers — the native Kotlin classes are internal to the library and accessed only through the generated Nitro spec, which already ships the correct `@Keep`/`@DoNotStrip` annotations.

## 4. Verify

```ts
import Security from '@rs-native-kit/security';

Security.scan().then(console.log);
```

Run on a real device or emulator/simulator (see [FAQ](FAQ.md#can-i-run-this-in-the-web-preview) for why this doesn't work in the example app's web/vite preview).

## Old Architecture / bridge apps

Not supported. Nitro Modules requires the New Architecture (JSI). If you're on the old architecture, [migrate to the New Architecture](https://reactnative.dev/docs/new-architecture-intro) first — it's been the RN default since 0.76.
