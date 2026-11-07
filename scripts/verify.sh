#!/usr/bin/env bash
# Runs the checks CI runs, locally.
#
#   scripts/verify.sh            # js: lint, typecheck, unit, server, package contents
#   scripts/verify.sh android    # js + native unit tests + Android build
#   scripts/verify.sh ios        # js + XCTests + iOS Release build
#   scripts/verify.sh e2e-android   # Maestro on the booted emulator
#   scripts/verify.sh e2e-ios       # Maestro on the booted simulator
#   scripts/verify.sh all        # everything above
#
# React Native's prebuilt core download fails during `pod install` when the path
# contains a space (iCloud Drive does), so iOS steps then run in a copy of the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-js}"

js() {
  cd "$ROOT"
  yarn lint
  yarn typecheck
  yarn test --maxWorkers=2
  node --test scripts/*.test.mjs
  (cd server && ../node_modules/.bin/tsc -p tsconfig.test.json && node --test test/*.test.mts)
  yarn prepare
  node scripts/check-package.mjs
}

android() {
  cd "$ROOT"
  yarn nitrogen
  (cd example/android && ./gradlew :rs-native-kit_security:testDebugUnitTest :app:assembleRelease \
    -PreactNativeArchitectures=arm64-v8a --console=plain)
}

# Prints the directory to run iOS steps in, syncing a copy when the path has a space.
ios_root() {
  if [[ "$ROOT" != *" "* ]]; then
    echo "$ROOT"
    return
  fi
  local copy="${TMPDIR:-/tmp}/rs-security-ios-verify"
  rsync -a --delete --exclude '/.git' --exclude '/lib' --exclude '/coverage' --exclude '/.claude' \
    --exclude '/example/ios/Pods' --exclude '/example/ios/build' --exclude '/example/android' \
    --exclude '/example/ios/.xcode.env.local' "$ROOT/" "$copy/" >&2
  echo "$copy"
}

pods() {
  (cd "$1/example" && bundle install --quiet && bundle exec pod install --project-directory=ios)
}

ios() {
  cd "$ROOT"
  yarn nitrogen
  local dir
  dir="$(ios_root)"
  RS_IOS_TESTS=1 pods "$dir"
  "$dir/scripts/ios-unit-tests.sh"
  pods "$dir"
  (cd "$dir/example/ios" && xcodebuild -workspace SecurityExample.xcworkspace -scheme SecurityExample \
    -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath build/e2e CODE_SIGNING_ALLOWED=NO -quiet build)
}

e2e_android() {
  cd "$ROOT"
  yarn nitrogen
  scripts/e2e.sh android
}

e2e_ios() {
  cd "$ROOT"
  yarn nitrogen
  local dir
  dir="$(ios_root)"
  pods "$dir"
  E2E_OUTPUT="$ROOT/example/e2e/output" "$dir/scripts/e2e.sh" ios
}

case "$TARGET" in
  js) js ;;
  android) js; android ;;
  ios) js; ios ;;
  e2e-android) e2e_android ;;
  e2e-ios) e2e_ios ;;
  all) js; android; ios; e2e_android; e2e_ios ;;
  *)
    echo "Unknown target: $TARGET" >&2
    exit 2
    ;;
esac
