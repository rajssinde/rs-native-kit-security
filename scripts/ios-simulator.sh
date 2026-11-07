#!/usr/bin/env bash
# Prints the UDID of the iPhone simulator to use: on the newest installed iOS,
# preferring one already booted, so every step targets the same device.
set -euo pipefail

xcrun simctl list devices available -j | node -e "
  const { devices } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
  const iPhones = Object.keys(devices).filter((r) => r.includes('iOS')).sort()
    .flatMap((r) => devices[r]).filter((d) => d.name.startsWith('iPhone'));
  if (!iPhones.length) process.exit(1);
  const booted = iPhones.filter((d) => d.state === 'Booted');
  console.log((booted.length ? booted : iPhones).pop().udid);
"
