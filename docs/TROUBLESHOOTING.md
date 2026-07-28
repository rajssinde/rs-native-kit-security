# Troubleshooting

## `SecurityUnsupportedPlatformError: "..." is not supported on this platform`

You're calling a detection method on a platform other than Android/iOS (most commonly: the `react-native-web`/Vite preview target). This is intentional — see [Security Notes](SECURITY_NOTES.md#web-unsupported-platforms). Guard the call:

```ts
import { Platform } from 'react-native';

if (Platform.OS === 'android' || Platform.OS === 'ios') {
  const report = await Security.scan();
}
```

## Build fails with "No such module 'NitroModules'" (iOS)

Run `pod install` after installing/upgrading the package — Nitro's generated Swift/C++ bridge files are wired through CocoaPods and won't exist until pods are installed:

```sh
cd ios && pod install
```

If you recently pulled changes that touched `src/Security.nitro.ts`, also regenerate the native glue:

```sh
yarn nitrogen
cd ios && pod install
```

## `NitroModules.createHybridObject` throws / native module not found at runtime

Almost always a stale build. Nitro's native glue is generated at build time, not runtime:

1. `yarn nitrogen` (regenerates `nitrogen/generated/`)
2. iOS: `cd ios && pod install`, then a clean rebuild (`Product > Clean Build Folder` in Xcode, or delete `ios/build`)
3. Android: `cd android && ./gradlew clean` (or delete `android/.cxx` and `android/build`), then rebuild

## Android build fails referencing `RsNativeKitSecurity` / `Security` C++ symbols

Make sure `yarn nitrogen` has been run after any change to `src/Security.nitro.ts` or `nitro.json`, and that you're not mixing a stale `nitrogen/generated/` directory from before an `iosModuleName`/`androidNamespace` change. Delete `nitrogen/generated/` and re-run `yarn nitrogen` if in doubt.

## `isFridaDetected()` / hook checks seem slow

The Frida port-scan check opens a loopback socket with a short (200ms) timeout per port — on a device with a strict firewall or unusual network stack, this can add up to ~400ms across both default Frida ports. This runs off the JS thread already (`Promise.parallel`), so it shouldn't cause UI jank, but if you're calling `scan()` synchronously before rendering a screen, show a loading state rather than blocking navigation.

## Screenshot/screen-recording events never fire

- **Android**: the `MediaStore` `ContentObserver` requires the OS to actually write a new row to `MediaStore.Images.Media` — some custom ROMs or third-party screenshot tools that bypass the standard screenshot path won't trigger it.
- **iOS**: `UIScreen.capturedDidChangeNotification`/`userDidTakeScreenshotNotification` only fire while your app is in the foreground, per Apple's documented behavior.
- Both: confirm you actually have an active listener — `addListener()` must be called (and its returned unsubscribe function *not* called) for native monitoring to be running at all; see [API Reference](API.md#event-system).

## `verifyAppSignature()` / `getAppSignatureHash()` throws on iOS

This is expected if the running bundle has neither an embedded provisioning profile nor a `_CodeSignature/CodeResources` file — e.g. certain ad-hoc test harnesses. On a normal Development, Ad Hoc, Enterprise, or App Store build, one of the two is always present. See [Security Notes](SECURITY_NOTES.md#integrity-checks) for why iOS signature verification works differently from Android's.

## Jest tests fail with "Cannot find module '@rs-native-kit/security'" in a consuming app

Make sure your Jest config's `moduleFileExtensions`/`transformIgnorePatterns` follow the standard React Native preset (`@react-native/jest-preset`), and that you're not accidentally resolving the package's TypeScript source instead of `lib/` outside of this repo's own test suite (the `rs-native-kit-security-source` custom export condition is only meant to be used inside this repo).

## Still stuck?

Open an issue with: RN version, `react-native-nitro-modules` version, platform + OS version, and the exact error/stack trace. See [CONTRIBUTING.md](../CONTRIBUTING.md).
