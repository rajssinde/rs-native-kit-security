import assert from 'node:assert/strict';
import { createHash, createVerify, generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  AttestationError,
  evaluatePlayIntegrity,
  PlayIntegrityClient,
  type PlayIntegrityPayload,
} from '../src/index.mts';

const NOW = 1_800_000_000_000;
const REQUEST_DATA = 'challenge-abc|POST /transfer|{"amount":100}';
const CERT_HEX = 'ab'.repeat(32);

function payload(overrides: Partial<PlayIntegrityPayload> = {}): PlayIntegrityPayload {
  return {
    requestDetails: {
      requestPackageName: 'com.example.app',
      requestHash: createHash('sha256').update(REQUEST_DATA).digest('hex'),
      timestampMillis: String(NOW - 5_000),
    },
    appIntegrity: {
      appRecognitionVerdict: 'PLAY_RECOGNIZED',
      packageName: 'com.example.app',
      certificateSha256Digest: [Buffer.from(CERT_HEX, 'hex').toString('base64url')],
    },
    deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY', 'MEETS_BASIC_INTEGRITY'] },
    accountDetails: { appLicensingVerdict: 'LICENSED' },
    ...overrides,
  };
}

const policy = {
  packageName: 'com.example.app',
  requestData: REQUEST_DATA,
  certificateSha256Digests: [CERT_HEX.toUpperCase().match(/../g)!.join(':')],
  now: NOW,
};

describe('evaluatePlayIntegrity', () => {
  it('accepts a genuine app on a genuine device for this request', () => {
    const verdict = evaluatePlayIntegrity(payload(), policy);
    assert.deepEqual(verdict.failures, []);
    assert.equal(verdict.ok, true);
  });

  it('rejects a token bound to a different request (replay onto another request)', () => {
    const verdict = evaluatePlayIntegrity(payload(), { ...policy, requestData: 'challenge-abc|POST /transfer|{"amount":999}' });
    assert.deepEqual(verdict.failures, ['REQUEST_HASH_MISMATCH']);
  });

  it('rejects stale and future-dated tokens', () => {
    const stale = payload({ requestDetails: { ...payload().requestDetails, timestampMillis: NOW - 10 * 60_000 } });
    assert.deepEqual(evaluatePlayIntegrity(stale, policy).failures, ['TOKEN_STALE']);
    const future = payload({ requestDetails: { ...payload().requestDetails, timestampMillis: NOW + 5 * 60_000 } });
    assert.deepEqual(evaluatePlayIntegrity(future, policy).failures, ['TOKEN_STALE']);
  });

  it('rejects a repackaged app (unrecognized, wrong signing cert)', () => {
    const repackaged = payload({
      appIntegrity: {
        appRecognitionVerdict: 'UNRECOGNIZED_VERSION',
        packageName: 'com.example.app',
        certificateSha256Digest: [Buffer.alloc(32, 9).toString('base64url')],
      },
    });
    assert.deepEqual(evaluatePlayIntegrity(repackaged, policy).failures, ['APP_NOT_RECOGNIZED', 'CERTIFICATE_MISMATCH']);
  });

  it('enforces the minimum device integrity level', () => {
    const basicOnly = payload({ deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] } });
    assert.deepEqual(evaluatePlayIntegrity(basicOnly, policy).failures, ['DEVICE_INTEGRITY_INSUFFICIENT']);
    assert.equal(evaluatePlayIntegrity(basicOnly, { ...policy, requiredDeviceIntegrity: 'MEETS_BASIC_INTEGRITY' }).ok, true);

    const none = payload({ deviceIntegrity: {} });
    assert.deepEqual(evaluatePlayIntegrity(none, policy).failures, ['DEVICE_INTEGRITY_INSUFFICIENT']);

    assert.deepEqual(
      evaluatePlayIntegrity(payload(), { ...policy, requiredDeviceIntegrity: 'MEETS_STRONG_INTEGRITY' }).failures,
      ['DEVICE_INTEGRITY_INSUFFICIENT']
    );
  });

  it('checks licensing only when required', () => {
    const unlicensed = payload({ accountDetails: { appLicensingVerdict: 'UNLICENSED' } });
    assert.equal(evaluatePlayIntegrity(unlicensed, policy).ok, true);
    assert.deepEqual(evaluatePlayIntegrity(unlicensed, { ...policy, requireLicensed: true }).failures, ['APP_NOT_LICENSED']);
  });

  it('rejects a token for another package', () => {
    const other = payload({ requestDetails: { ...payload().requestDetails, requestPackageName: 'com.evil.app' } });
    assert.deepEqual(evaluatePlayIntegrity(other, policy).failures, ['PACKAGE_MISMATCH']);
  });

  it('fails closed on an empty payload', () => {
    const verdict = evaluatePlayIntegrity({}, policy);
    assert.equal(verdict.ok, false);
    assert.ok(verdict.failures.includes('REQUEST_HASH_MISMATCH'));
    assert.ok(verdict.failures.includes('APP_NOT_RECOGNIZED'));
  });
});

describe('PlayIntegrityClient', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const serviceAccount = {
    client_email: 'verifier@project.iam.gserviceaccount.com',
    private_key: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };

  function fakeFetch(log: { url: string; init: RequestInit }[], decodeStatus = 200) {
    return (async (url: string | URL, init?: RequestInit) => {
      log.push({ url: String(url), init: init! });
      if (String(url) === 'https://oauth2.googleapis.com/token') {
        return new Response(JSON.stringify({ access_token: 'access-123', expires_in: 3600 }));
      }
      if (decodeStatus !== 200) return new Response('denied', { status: decodeStatus });
      return new Response(JSON.stringify({ tokenPayloadExternal: payload() }));
    }) as typeof fetch;
  }

  it('authenticates with a correctly signed service-account JWT and decodes the token', async () => {
    const log: { url: string; init: RequestInit }[] = [];
    const client = new PlayIntegrityClient({ serviceAccount, fetch: fakeFetch(log) });

    const decoded = await client.decode('com.example.app', 'opaque-token');
    assert.equal(decoded.appIntegrity?.appRecognitionVerdict, 'PLAY_RECOGNIZED');

    const tokenRequest = new URLSearchParams(String(log[0]!.init.body));
    assert.equal(tokenRequest.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    const [header, claims, signature] = tokenRequest.get('assertion')!.split('.');
    assert.ok(
      createVerify('RSA-SHA256').update(`${header}.${claims}`).verify(publicKey, Buffer.from(signature!, 'base64url')),
      'JWT signature must verify with the service account public key'
    );
    const parsedClaims = JSON.parse(Buffer.from(claims!, 'base64url').toString());
    assert.equal(parsedClaims.iss, serviceAccount.client_email);
    assert.equal(parsedClaims.scope, 'https://www.googleapis.com/auth/playintegrity');

    assert.equal(log[1]!.url, 'https://playintegrity.googleapis.com/v1/com.example.app:decodeIntegrityToken');
    assert.equal((log[1]!.init.headers as Record<string, string>).authorization, 'Bearer access-123');
    assert.deepEqual(JSON.parse(String(log[1]!.init.body)), { integrity_token: 'opaque-token' });
  });

  it('caches the access token across decodes', async () => {
    const log: { url: string; init: RequestInit }[] = [];
    const client = new PlayIntegrityClient({ serviceAccount, fetch: fakeFetch(log) });
    await client.decode('com.example.app', 't1');
    await client.decode('com.example.app', 't2');
    assert.equal(log.filter((entry) => entry.url.includes('oauth2')).length, 1);
  });

  it('surfaces decode failures as AttestationError', async () => {
    const client = new PlayIntegrityClient({ serviceAccount, fetch: fakeFetch([], 403) });
    await assert.rejects(client.decode('com.example.app', 't'), (error: unknown) => error instanceof AttestationError && error.code === 'DECODE_FAILED');
  });
});
