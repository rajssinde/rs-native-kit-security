#!/usr/bin/env bash
# Builds the example app against several react-native-nitro-modules runtimes to
# prove the shipped bindings (nitrogen/generated + nitrogen/generated-legacy)
# compile and link for every supported version range (nitro-compat.json).
#
#   scripts/nitro-compat-matrix.sh android 0.32.2 0.34.1 0.35.10 0.37.1
#   scripts/nitro-compat-matrix.sh ios     0.32.2 0.37.1
#
# It REPLACES node_modules/react-native-nitro-modules in place, so it refuses to
# run outside CI unless you pass --force (run it in a throwaway checkout).
set -uo pipefail

if [[ "${1:-}" == "--force" ]]; then FORCE=1; shift; else FORCE=0; fi
PLATFORM="${1:?usage: nitro-compat-matrix.sh [--force] <android|ios> <version>...}"
shift
if [[ "${CI:-}" != "true" && $FORCE -ne 1 ]]; then
  echo "Refusing to swap node_modules outside CI; re-run with --force in a throwaway checkout." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILED=0

install_runtime() {
  local version="$1"
  (cd "$WORK" && npm pack "react-native-nitro-modules@$version" --silent >/dev/null)
  for nm in "$ROOT/node_modules" "$ROOT/example/node_modules"; do
    rm -rf "$nm/react-native-nitro-modules"
    mkdir -p "$nm/react-native-nitro-modules"
    tar -xzf "$WORK/react-native-nitro-modules-$version.tgz" -C "$nm/react-native-nitro-modules" --strip-components=1
  done
}

build_android() {
  rm -rf "$ROOT/android/build" "$ROOT/android/.cxx" "$ROOT/example/android/app/build" \
    "$ROOT/example/android/build/generated/autolinking"
  (cd "$ROOT/example/android" && ./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a --console=plain)
}

build_ios() {
  (cd "$ROOT/example/ios" && bundle exec pod install) &&
    (cd "$ROOT/example/ios" && xcodebuild -workspace SecurityExample.xcworkspace -scheme SecurityExample \
      -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$WORK/DerivedData" CODE_SIGNING_ALLOWED=NO build)
}

for version in "$@"; do
  echo "::group::react-native-nitro-modules $version ($PLATFORM)"
  install_runtime "$version"
  if "build_$PLATFORM" > "$WORK/build-$version.log" 2>&1; then
    result="PASS"
  else
    result="FAIL"
    FAILED=1
    grep -m5 -E "error:|^e: |What went wrong|not supported" -A1 "$WORK/build-$version.log" || tail -20 "$WORK/build-$version.log"
  fi
  echo "::endgroup::"
  echo "nitro $version ($PLATFORM): $result"
done
exit $FAILED
