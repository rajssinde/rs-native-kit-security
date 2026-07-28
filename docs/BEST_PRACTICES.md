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

## Pin your app signature at build time

```ts
const EXPECTED_SIGNATURE_HASH = process.env.EXPECTED_SIGNATURE_HASH; // injected at build time, per environment
const genuine = await Security.verifyAppSignature(EXPECTED_SIGNATURE_HASH);
```

Don't hardcode the hash in a way that's trivially greppable and swappable in a repackaged build — inject it per build environment (CI secret → build-time constant) so a naive "search and replace the expected hash" attack doesn't work against a casually inspected bundle.

## Tune risk weights to your actual policy, don't ship the defaults blindly

The default weights (`src/risk/weights.ts`) are a reasonable starting point, not a regulatory requirement. A banking app handling wire transfers should likely weight `frida`/`hookDetected`/`tampered` far more heavily than the defaults; a casual mobile game might not care about root/jailbreak at all. Decide your policy, then call `configureRiskEngine()` once at app startup.

## Don't over-react to `MEDIUM`

A rooted developer's own test device, a legitimate VPN app, or a corporate MDM-managed phone can all trigger individual `MEDIUM`-weighted checks without being a threat. Reserve hard blocks for `CRITICAL`, and use `HIGH`/`MEDIUM` for step-up auth or backend flagging rather than an outright deny — see [Examples](EXAMPLES.md#risk-based-step-up-authentication).

## Combine with `FLAG_SECURE` (Android) / disable screenshots on sensitive screens

`isScreenRecording()`/`isScreenCaptured()` are *detection*, not *prevention*. Pair them with `WindowManager.LayoutParams.FLAG_SECURE` (Android) on screens showing card numbers, balances, or credentials — that actually blocks capture, rather than just reporting it after the fact. iOS has no equivalent "block capture" API; detection + reactive blurring (on `SCREENSHOT`/`SCREEN_RECORDING` events) is the best available mitigation there.

## Keep the library updated

Detection techniques are inherently a moving target — root/jailbreak tooling evolves, and so should the signals this SDK checks for. Track releases and update regularly rather than pinning indefinitely; see the [Migration Guide](MIGRATION.md) for the versioning policy.

## Test your actual policy, not just that the SDK compiles

Unit-test your *risk policy* (the code that reads `SecurityReport` and decides what to do) with mocked reports covering every `riskLevel` and representative `checks` combinations — this is cheap, deterministic, and catches policy bugs (e.g. an inverted `secure` check) that no amount of real-device testing of the SDK itself will catch.
