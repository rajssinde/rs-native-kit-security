# Attestation (Play Integrity & App Attest)

On-device checks (`scan()`) run inside the app, so an attacker who controls the device can patch them to report "clean". **Platform attestation can't be faked that way:** Google (Play Integrity) or Apple (App Attest) sign a statement about the app and device, and **your server** verifies it. Use attestation as the trust anchor for sensitive operations, and the on-device checks as supplementary signal.

The client half lives in `@rs-native-kit/security`; the server half is the zero-dependency [`@rs-native-kit/security-server`](../server/README.md) package (Node 20+).

## The flow

```
App                                   Your server
 │  1. GET /challenge  ─────────────────▶ createChallenge(), store single-use (TTL ~5 min)
 │  ◀──────────────────────────── challenge
 │  2. token = attest(challenge + request)
 │  3. POST /transfer { token, request } ▶ consume(challenge) — once only
 │                                        verify token against challenge + request
 │                                        allow / step-up / deny
```

Three rules make this work:

1. **The server issues the challenge, and accepts each one exactly once.** That stops replays. `InMemoryChallengeStore` is fine for one instance; use Redis or your database across instances.
2. **Bind the token to the request.** Put the challenge *and* the request body in the data you attest, so a token can't be moved onto a different request.
3. **The server never trusts a client-reported result.** Not `scan()`'s `secure`, not its score, nothing — only what it verified itself.

## Android: Play Integrity

**Setup:** enable the Play Integrity API in a Google Cloud project, link that project in the Play Console (*App integrity → Play Integrity API*), and create a service account with access to it for your server. Verdicts are only meaningful for builds installed from Google Play (including internal testing tracks).

```ts
import Security from '@rs-native-kit/security';

// Once, early (takes a few seconds):
await Security.prepareIntegrityToken(123456789012); // Google Cloud project number

// Per sensitive request:
const challenge = await api.getChallenge();
const body = JSON.stringify({ amount: 100, to: 'acct-42' });
const requestData = `${challenge}|POST /transfer|${body}`;
const integrityToken = await Security.requestIntegrityToken(requestData);
await api.post('/transfer', body, { headers: { 'x-challenge': challenge, 'x-integrity': integrityToken } });
```

```ts
// Server
import { PlayIntegrityClient } from '@rs-native-kit/security-server';

const playIntegrity = new PlayIntegrityClient({ serviceAccount: JSON.parse(process.env.GOOGLE_SA_KEY!) });

if (!(await challenges.consume(challenge))) return deny('CHALLENGE_INVALID');
const verdict = await playIntegrity.verify(integrityToken, {
  packageName: 'com.example.app',
  requestData: `${challenge}|POST /transfer|${rawBody}`,
  certificateSha256Digests: [process.env.PLAY_APP_SIGNING_CERT_SHA256!], // Play Console → App signing key
  requiredDeviceIntegrity: 'MEETS_DEVICE_INTEGRITY',
});
if (!verdict.ok) return deny(verdict.failures); // e.g. ['DEVICE_INTEGRITY_INSUFFICIENT']
```

`verdict.failures` lists every unmet requirement (`REQUEST_HASH_MISMATCH`, `TOKEN_STALE`, `APP_NOT_RECOGNIZED`, `CERTIFICATE_MISMATCH`, `DEVICE_INTEGRITY_INSUFFICIENT`, `APP_NOT_LICENSED`, `PACKAGE_MISMATCH`), so you can choose a softer response (step-up auth) for some of them.

## iOS: App Attest

**Setup:** add the **App Attest** capability in Xcode. Set the `com.apple.developer.devicecheck.appattest-environment` entitlement to `production` for release builds — without it, development-signed builds attest in the `development` environment, which the server rejects unless you allow it. App Attest needs iOS 14+ on a physical device; the Simulator isn't supported.

```ts
import Security from '@rs-native-kit/security';

// Once per install: create and attest a key.
if (await Security.isAppAttestSupported()) {
  const keyId = await Security.generateAppAttestKey();          // persist in the Keychain
  const challenge = await api.getChallenge();
  const attestation = await Security.attestAppAttestKey(keyId, challenge);
  await api.post('/app-attest/register', { keyId, challenge, attestation });
}

// Per sensitive request:
const challenge = await api.getChallenge();
const clientData = JSON.stringify({ challenge, method: 'POST', path: '/transfer', body });
const assertion = await Security.generateAppAttestAssertion(keyId, clientData);
await api.post('/transfer', { keyId, clientData, assertion });
```

```ts
// Server
import { verifyAppAttestAttestation, verifyAppAttestAssertion } from '@rs-native-kit/security-server';

// Registration:
if (!(await challenges.consume(challenge))) return deny('CHALLENGE_INVALID');
const key = verifyAppAttestAttestation({ attestation, keyId, challenge, appId: 'AB12CD34EF.com.example.app' });
await db.appAttestKeys.insert({ keyId, publicKeyPem: key.publicKeyPem, signCount: key.signCount, userId });

// Each request:
const stored = await db.appAttestKeys.get(keyId);
const { challenge } = JSON.parse(clientData);
if (!(await challenges.consume(challenge))) return deny('CHALLENGE_INVALID');
const { signCount } = verifyAppAttestAssertion({
  assertion, clientData, appId: 'AB12CD34EF.com.example.app',
  publicKeyPem: stored.publicKeyPem, previousSignCount: stored.signCount,
});
await db.appAttestKeys.update(keyId, { signCount }); // must strictly increase
// ...and check that clientData's method/path/body match the request you're serving.
```

Verification follows Apple's *Validating apps that connect to your server*. Attestation checks:

- the certificate chain up to Apple's App Attestation Root CA (pinned in the package)
- the nonce in the credential certificate
- the key ID
- the App ID hash
- that the counter starts at 0
- the environment

Assertion checks:

- the ECDSA signature over the request's client data
- the App ID hash
- that the counter strictly increases, which blocks replays and cloned keys

Failures throw `AttestationError` with a stable `code`.

## What attestation does and doesn't prove

- **Proves:** the request came from your genuine, unmodified app (as distributed by Play / signed by your team), and, for Play Integrity, that the device passes Google's integrity checks.
- **Doesn't prove:** that the person using the app is legitimate, or that the device is free of all malware. Keep authentication, authorization and fraud scoring on the server.
- **Availability:** both services can be unavailable (no Google Play services, old iOS, quota limits, network errors). Decide your fallback per operation: deny, step up authentication, or allow with reduced limits. Don't silently skip verification.
