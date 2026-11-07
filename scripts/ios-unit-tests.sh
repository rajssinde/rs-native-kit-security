#!/usr/bin/env bash
# Runs ios/Tests on a simulator. Run `RS_IOS_TESTS=1 pod install` in example/ios first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVICE="$("$ROOT/scripts/ios-simulator.sh")"

cd "$ROOT/example/ios"
xcodebuild test -workspace SecurityExample.xcworkspace -scheme RsNativeKitSecurity-Unit-Tests \
  -destination "platform=iOS Simulator,id=$DEVICE" -quiet
