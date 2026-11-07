#!/usr/bin/env bash
# Builds the example app in Release, installs it on the emulator or simulator,
# and runs the Maestro flow for that platform.
#
#   scripts/e2e.sh android
#   scripts/e2e.sh ios        # run `pod install` in example/ios first
#
# Set SKIP_BUILD=1 to reuse the previous build.
set -euo pipefail

PLATFORM="${1:?usage: e2e.sh <android|ios>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${E2E_OUTPUT:-$ROOT/example/e2e/output}"
mkdir -p "$OUTPUT"
MAESTRO_DEVICE=()

case "$PLATFORM" in
  android)
    ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
    if [[ -z "${SKIP_BUILD:-}" ]]; then
      (cd "$ROOT/example/android" && ./gradlew :app:assembleRelease "-PreactNativeArchitectures=$ABI" --console=plain)
    fi
    adb install -r "$ROOT/example/android/app/build/outputs/apk/release/app-release.apk"
    ;;
  ios)
    DERIVED="${IOS_DERIVED_DATA:-$ROOT/example/ios/build/e2e}"
    if [[ -z "${SKIP_BUILD:-}" ]]; then
      (cd "$ROOT/example/ios" && xcodebuild -workspace SecurityExample.xcworkspace -scheme SecurityExample \
        -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$DERIVED" CODE_SIGNING_ALLOWED=NO -quiet build)
    fi
    DEVICE="$("$ROOT/scripts/ios-simulator.sh")"
    xcrun simctl bootstatus "$DEVICE" -b
    xcrun simctl install "$DEVICE" "$DERIVED/Build/Products/Release-iphonesimulator/SecurityExample.app"
    MAESTRO_DEVICE=(--udid "$DEVICE")
    ;;
  *)
    echo "Unknown platform: $PLATFORM" >&2
    exit 2
    ;;
esac

FLOW="${E2E_FLOW:-$ROOT/example/e2e/$PLATFORM.yaml}"
maestro "${MAESTRO_DEVICE[@]+"${MAESTRO_DEVICE[@]}"}" test "$FLOW" --format junit --output "$OUTPUT/$PLATFORM-junit.xml" --debug-output "$OUTPUT/$PLATFORM-debug"
