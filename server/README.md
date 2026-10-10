# @rs-native-kit/security-server

Server-side verification for [`@rs-native-kit/security`](../README.md): **Apple App Attest** and **Google Play Integrity**, plus single-use challenges. Zero runtime dependencies, Node 20+.

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
| `AttestationError` | Thrown on verification failure, with a stable `code` |

## Development

```sh
node --test test/*.test.mts                     # tests (Node 22.6+ runs TypeScript directly)
../node_modules/.bin/tsc -p tsconfig.test.json  # typecheck
../node_modules/.bin/tsc -p tsconfig.json       # build to dist/
```

The App Attest tests build a real X.509 chain with `openssl` (root → intermediate → credential certificate carrying the nonce extension) and real ECDSA-signed assertions, so the full verification path runs, not a mock. They can't use a genuine Apple-issued attestation, which only exists on a physical device. Verify against one from your app before going live.
