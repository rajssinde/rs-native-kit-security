# Installation

## Requirements

| | Minimum |
|---|---|
| React Native | 0.72 (New Architecture only — see [FAQ](FAQ.md#does-this-work-on-the-old-architecture)) |
| Android | API 24 (Android 7.0) |
| iOS | 15.1 |
| `react-native-nitro-modules` | 0.32.0 or newer (tested up to 0.37) — see [Nitro version support](#nitro-version-support) |

## 1. Install the package

```sh
npm install @rs-native-kit/security react-native-nitro-modules
# or
yarn add @rs-native-kit/security react-native-nitro-modules
```

`react-native-nitro-modules` is a required **peer dependency** — this library's native module is built on it. Use whichever supported version the rest of your app already uses; you don't need to change it for this library.

### Nitro version support

Code generated for Nitro only compiles against a matching range of the `react-native-nitro-modules` runtime: Nitro 0.35 changed how Android native objects are built, so no single set of bindings covers both sides. This package ships two:

| Your `react-native-nitro-modules` | Bindings used |
|---|---|
| 0.35.0 and newer | `nitrogen/generated` |
| 0.32.0 – 0.34.x | `nitrogen/generated-legacy` |
| 0.31.x and older | not supported — the build stops with a message asking you to upgrade |

The right set is picked automatically at build time (Gradle and CocoaPods read your installed version); there's nothing to configure. Versions newer than the newest one tested (see [`nitro-compat.json`](../nitro-compat.json)) build with a warning. Every supported range is built in CI on each change, along with the newest release on npm.

## 2. iOS

```sh
cd ios && pod install
```

No manual Info.plist changes are required for the core detection APIs. One optional entry improves accuracy:

- **Jailbreak app URL schemes** (one of several jailbreak signals): list them under `LSApplicationQueriesSchemes`. Without it, `canOpenURL` always returns `false` for them (iOS 9+ policy), so this specific signal (`JAILBREAK_URL_SCHEME`) is silently skipped — the other jailbreak checks (file scans, symlink checks, sandbox-escape test, dylib inspection, process-spawn probe) still run.

  ```xml
  <key>LSApplicationQueriesSchemes</key>
  <array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
    <string>undecimus</string>
    <string>activator</string>
  </array>
  ```

For App Attest, add the **App Attest** capability — see [Attestation](ATTESTATION.md#ios-app-attest).

## 3. Android

Autolinking handles everything — no manual `MainApplication`/Gradle edits needed. The library declares two permissions in its own manifest, merged automatically into your app:

- `android.permission.INTERNET` — used only for a local loopback socket probe against Frida's default ports (`checkFrida`/`checkHooks`). Nearly every RN app already has this permission for networking.
- `android.permission.ACCESS_NETWORK_STATE` — used for VPN/proxy transport checks.
- `android.permission.DETECT_SCREEN_CAPTURE` (Android 14+) and `DETECT_SCREEN_RECORDING` (Android 15+) — the OS screenshot and screen-recording callbacks behind `SCREENSHOT`/`SCREEN_RECORDING` events.
- `android.permission.HIDE_OVERLAY_WINDOWS` (Android 12+) — used by `setOverlayProtection()`.

All of these are *normal* install-time permissions: no runtime prompt, and no Play policy declaration. Remove any you don't want with `tools:node="remove"` in your app manifest; the corresponding feature then degrades gracefully.

On Android 13 and below, `SCREENSHOT` events come from `MediaStore` and are only reported once the new image is confirmed to be a screenshot, which requires your app to hold media read permission (`READ_MEDIA_IMAGES` / `READ_EXTERNAL_STORAGE`). This SDK doesn't request it; without it, screenshots on those versions aren't reported (rather than reporting every new photo).

It also declares a `<queries>` block listing the specific root-manager, hooking-framework, emulator, mock-location and overlay apps it checks for. Android 11+ hides other installed apps unless they're declared this way. These are targeted `<package>` entries, not the restricted `QUERY_ALL_PACKAGES` permission, and they merge into your app's manifest automatically.

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
