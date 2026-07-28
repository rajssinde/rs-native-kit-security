# Examples

## Gate login behind a security scan

```ts
import Security from '@rs-native-kit/security';

async function canProceedToLogin(): Promise<boolean> {
  const report = await Security.scan();

  if (report.riskLevel === 'CRITICAL') {
    // e.g. Frida attached, or the app was tampered with — hard block.
    return false;
  }
  if (report.riskLevel === 'HIGH') {
    // e.g. rooted/jailbroken — allow, but flag the session server-side
    // for step-up auth or reduced transaction limits.
  }
  return true;
}
```

## Risk-based step-up authentication

```ts
const report = await Security.scan();

switch (report.riskLevel) {
  case 'LOW':
    return startBiometricLogin();
  case 'MEDIUM':
    return startBiometricLogin({ requireDeviceAttestation: true });
  case 'HIGH':
  case 'CRITICAL':
    return requireStepUpAuth(); // e.g. SMS OTP + fraud review
}
```

Send `report` (or at least `riskLevel`/`score`/`reasons`) to your backend alongside the login request — a client-reported risk level should inform server-side policy, never be trusted as the sole gate (see [Security Notes](SECURITY_NOTES.md)).

## React hook wrapping `scan()`

```tsx
import { useEffect, useState } from 'react';
import Security, { type SecurityReport } from '@rs-native-kit/security';

export function useSecurityScan() {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    Security.scan()
      .then((result) => !cancelled && setReport(result))
      .catch((err) => !cancelled && setError(err));
    return () => {
      cancelled = true;
    };
  }, []);

  return { report, error };
}
```

## Subscribing to live events

```ts
useEffect(() => {
  return Security.addListener((event) => {
    if (event.type === 'SCREENSHOT') {
      analytics.track('sensitive_screen_screenshotted');
    }
    if (event.type === 'DEBUGGER' || event.type === 'HOOK_DETECTED') {
      forceLogout();
    }
  });
}, []);
```

## Pinning a known-good app signature

Fetch the hash once (e.g. print it in a debug build), then pin it as an app-side constant:

```ts
// One-time, in a debug build:
console.log(await Security.getAppSignatureHash());

// In production code:
const EXPECTED_SIGNATURE_HASH = 'your-hash-here';
const isGenuine = await Security.verifyAppSignature(EXPECTED_SIGNATURE_HASH);
```

## Custom risk weighting for a fintech app

```ts
Security.configureRiskEngine({
  weights: {
    root: 60,          // heavier than the default 30
    jailbreak: 60,
    frida: 100,         // any hooking framework is an instant CRITICAL
    hookDetected: 100,
  },
  thresholds: { medium: 15, high: 30, critical: 50 }, // stricter bands
});
```

## Running the example app

```sh
git clone <this repo>
cd security
yarn install

# Android (device or emulator)
yarn example android

# iOS (simulator or device)
yarn example ios

# Web preview of the dashboard UI only — see FAQ for why detections don't run there
yarn example web
```

The example app (`example/src/App.tsx`) is a working dashboard: security score, per-check status grid, live event log, and a refresh button.
