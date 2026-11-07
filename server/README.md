# @rs-native-kit/security-server

Server-side verification for [`@rs-native-kit/security`](../README.md): **Apple App Attest**, **Google Play Integrity** and **Android Key Attestation**, plus single-use challenges. Zero runtime dependencies, Node 20+.

On-device security checks can be patched by whoever controls the device. These verifiers check statements signed by Apple and Google, which can't be forged on the device — use them to gate sensitive operations. Full end-to-end guide: [docs/ATTESTATION.md](../docs/ATTESTATION.md).

## API

| Export | Purpose |
|---|---|
| `createChallenge()` | 32 random bytes, base64url |
| `InMemoryChallengeStore` | Single-use, TTL-bound challenges for one instance (implement `ChallengeStore` on Redis/DB for more) |
| `verifyAppAttestAttestation(input)` | Verifies a one-time key attestation → `{ keyId, publicKeyPem, signCount, environment, receipt }` to store |
| `verifyAppAttestAssertion(input)` | Verifies a per-request assertion → new `signCount` to store |
| `APPLE_APP_ATTEST_ROOT_CA` | Pinned Apple App Attestation Root CA (SHA-256 `1C:B9:82:3B:…:C9:32`) |
| `PlayIntegrityClient` | Decodes tokens via Google's `decodeIntegrityToken` API using a service account (no Google SDK) |
| `evaluatePlayIntegrity(payload, policy)` | Pure verdict evaluation → `{ ok, failures[] }` |
| `verifyKeyAttestation(input)` | Verifies an Android Key Attestation chain → `{ ok, failures[], deviceLocked, verifiedBootState, ... }` |
| `fetchKeyAttestationRevocations()` | Google's revoked attestation-key serials; pass to `verifyKeyAttestation()` (refresh ≤ 24 h) |
| `GOOGLE_KEY_ATTESTATION_ROOTS` | Pinned Google hardware attestation roots (RSA `CE:DB:1C:…:0D:FC`, EC `6D:9D:B4:…:BC:C0`) |
| `AttestationError` | Thrown on verification failure, with a stable `code` |

## Development

```sh
node --test test/*.test.mts                     # tests (Node 22.6+ runs TypeScript directly)
../node_modules/.bin/tsc -p tsconfig.test.json  # typecheck
../node_modules/.bin/tsc -p tsconfig.json       # build to dist/
```

The App Attest tests build a real X.509 chain with `openssl` (root → intermediate → credential certificate carrying the nonce extension) and real ECDSA-signed assertions, so the full verification path runs, not a mock. The Key Attestation tests do the same, with a DER-encoded attestation extension, and include a leaf forged with a genuine device key. The parser was also run against a real KeyMint chain from an Android emulator. Neither can use a genuine Apple-issued attestation or a hardware-backed Google-rooted chain, which only exist on physical devices. Verify against one from your app before going live.
