# Best Practices

## Treat this as one signal, not the verdict

Send `scan()`'s `riskLevel`/`score`/`reasons` to your backend and combine it with server-side signals (device attestation, behavioral/fraud scoring, rate limiting). Never make a client-only "if rooted, block" decision for anything security-critical — the check itself runs on the same (potentially compromised) device it's evaluating. See [Security Notes](SECURITY_NOTES.md).

## Scan at the right moments, not on every render

- **App launch** (before showing sensitive content) and **before high-value actions** (login, payment, changing security settings) are the right times to call `scan()`.
- Don't call `scan()` in a render loop or on every navigation — cache the result for the session and re-scan on an interval (e.g. every few minutes) or in response to app-foreground events, combined with `addListener()` for real-time state changes in between.

```ts
useEffect(() => {
  const subscription = AppState.addEventListener('change', (state) => {
    if (state === 'active') void refreshScan();
  });
  return () => subscription.remove();
}, []);
```

## Use `addListener()` for state changes, `scan()` for point-in-time decisions

The event system exists so you don't have to poll `scan()` yourself to catch a screenshot, a newly-attached debugger, or a VPN connecting mid-session. Use it to react in real time (e.g. blur a sensitive screen on `SCREENSHOT`), and reserve `scan()` for decisions gated on a fresh, complete snapshot (e.g. right before submitting a payment).

## Configure expected signers

Without them, `checks.signature` is `not_configured` and a re-signed app goes unnoticed by `scan()`:

```ts
Security.configure({
  expectedSigners: {
    android: [process.env.ANDROID_SIGNING_CERT_SHA256!], // injected at build time, per environment
    ios: [process.env.APPLE_TEAM_ID!],
  },
});
```

Inject the values per build environment (CI secret → build-time constant) rather than hard-coding them next to the check. An attacker who controls the device can still patch the comparison out — that's why the authoritative signal is server-side attestation, not this check.

## Treat `error` and `not_configured` as "unknown", never as "safe"

`report.complete === false` means at least one check failed to run; `report.notConfigured` lists checks that verified nothing. Both make a "clean" report less trustworthy — send them to your backend along with the score.

## Tune risk weights to your actual policy, don't ship the defaults blindly

The default weights (`src/risk/weights.ts`) are a reasonable starting point, not a regulatory requirement. A banking app handling wire transfers should likely weight `frida`/`hooks`/`tampering`/`signature` far more heavily than the defaults; a casual mobile game might not care about root/jailbreak at all. Decide your policy, then call `configureRiskEngine()` once at app startup.

## Don't over-react to `MEDIUM`

A rooted developer's own test device, a legitimate VPN app, or a corporate MDM-managed phone can all trigger individual `MEDIUM`-weighted checks without being a threat. Reserve hard blocks for `CRITICAL`, and use `HIGH`/`MEDIUM` for step-up auth or backend flagging rather than an outright deny — see [Examples](EXAMPLES.md#risk-based-step-up-authentication).

## Protect sensitive screens, don't just detect capture

`checkScreenRecording()`/`checkScreenCapture()` are *detection*. On screens showing card numbers, balances or credentials, turn on prevention:

```ts
useFocusEffect(useCallback(() => {
  Security.setScreenCaptureProtection(true);
  Security.setOverlayProtection(true);
  return () => {
    Security.setScreenCaptureProtection(false);
    Security.setOverlayProtection(false);
  };
}, []));
```

- **Android:** `FLAG_SECURE` makes screenshots and recordings come out black and blanks the app in recents. Overlay protection hides other apps' overlays and drops touches through them (tapjacking).
- **iOS:** there's no API to block screenshots. The app is covered while the screen is recorded or mirrored and in the app-switcher snapshot. Pair it with a reaction to `SCREENSHOT` events (e.g. warn, log, or invalidate a displayed one-time code).

## Keep the library updated

Detection techniques are inherently a moving target — root/jailbreak tooling evolves, and so should the signals this SDK checks for. Track releases and update regularly rather than pinning indefinitely; see the [Migration Guide](MIGRATION.md) for the versioning policy.

## Test your actual policy, not just that the SDK compiles

Unit-test your *risk policy* (the code that reads `SecurityReport` and decides what to do) with mocked reports covering every `riskLevel` and representative `checks` combinations — this is cheap, deterministic, and catches policy bugs (e.g. an inverted `secure` check) that no amount of real-device testing of the SDK itself will catch.
