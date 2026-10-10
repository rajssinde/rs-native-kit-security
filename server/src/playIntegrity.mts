import { createHash, createSign } from 'node:crypto';
import { AttestationError } from './errors.mts';

/** The fields of a decoded Play Integrity payload this verifier evaluates. */
export interface PlayIntegrityPayload {
  requestDetails?: {
    requestPackageName?: string;
    requestHash?: string;
    nonce?: string;
    timestampMillis?: string | number;
  };
  appIntegrity?: {
    appRecognitionVerdict?: string;
    packageName?: string;
    certificateSha256Digest?: string[];
    versionCode?: string | number;
  };
  deviceIntegrity?: {
    deviceRecognitionVerdict?: string[];
  };
  accountDetails?: {
    appLicensingVerdict?: string;
  };
  environmentDetails?: Record<string, unknown>;
}

export type DeviceIntegrityLevel =
  | 'MEETS_STRONG_INTEGRITY'
  | 'MEETS_DEVICE_INTEGRITY'
  | 'MEETS_BASIC_INTEGRITY';

export interface PlayIntegrityPolicy {
  packageName: string;
  /** The exact `requestData` string the app passed to `requestIntegrityToken()`. */
  requestData: string;
  /**
   * Signing-certificate SHA-256 digests to accept (hex, `:`-separated hex,
   * base64 or base64url). With Play App Signing this is the app-signing key
   * from the Play Console. Omit to skip the check (not recommended).
   */
  certificateSha256Digests?: string[];
  /** Minimum device verdict. Default `MEETS_DEVICE_INTEGRITY`. */
  requiredDeviceIntegrity?: DeviceIntegrityLevel;
  /** Require `appLicensingVerdict === 'LICENSED'`. Default false. */
  requireLicensed?: boolean;
  /** Maximum token age. Default 2 minutes. */
  maxAgeMs?: number;
  now?: number;
}

export interface PlayIntegrityVerdict {
  /** `true` only when every requirement passed. */
  ok: boolean;
  /** Machine-readable codes for every requirement that failed. */
  failures: string[];
  deviceRecognitionVerdict: string[];
  appRecognitionVerdict?: string;
  appLicensingVerdict?: string;
}

const DEVICE_LEVELS: DeviceIntegrityLevel[] = [
  'MEETS_BASIC_INTEGRITY',
  'MEETS_DEVICE_INTEGRITY',
  'MEETS_STRONG_INTEGRITY',
];

function digestBytes(value: string): Buffer {
  const hex = value.replace(/[:\s]/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Evaluates a decoded payload against your policy. Pure: no network. Every
 * failed requirement is reported, so you can log exactly why a request was
 * rejected — and choose a softer response (step-up auth) for some codes.
 */
export function evaluatePlayIntegrity(
  payload: PlayIntegrityPayload,
  policy: PlayIntegrityPolicy
): PlayIntegrityVerdict {
  const failures: string[] = [];
  const now = policy.now ?? Date.now();
  const request = payload.requestDetails ?? {};
  const app = payload.appIntegrity ?? {};
  const deviceVerdicts = payload.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const licensing = payload.accountDetails?.appLicensingVerdict;

  if (request.requestPackageName !== policy.packageName) failures.push('PACKAGE_MISMATCH');

  const expectedHash = createHash('sha256').update(policy.requestData, 'utf8').digest('hex');
  if (request.requestHash !== expectedHash) failures.push('REQUEST_HASH_MISMATCH');

  const timestamp = Number(request.timestampMillis);
  if (!Number.isFinite(timestamp) || now - timestamp > (policy.maxAgeMs ?? 120_000) || timestamp - now > 60_000) {
    failures.push('TOKEN_STALE');
  }

  if (app.appRecognitionVerdict !== 'PLAY_RECOGNIZED') failures.push('APP_NOT_RECOGNIZED');
  if (app.packageName !== undefined && app.packageName !== policy.packageName) failures.push('PACKAGE_MISMATCH');

  if (policy.certificateSha256Digests) {
    const accepted = policy.certificateSha256Digests.map(digestBytes);
    const actual = (app.certificateSha256Digest ?? []).map(digestBytes);
    const matches = actual.length > 0 && actual.every((digest) => accepted.some((a) => a.equals(digest)));
    if (!matches) failures.push('CERTIFICATE_MISMATCH');
  }

  const required = DEVICE_LEVELS.indexOf(policy.requiredDeviceIntegrity ?? 'MEETS_DEVICE_INTEGRITY');
  const achieved = Math.max(-1, ...deviceVerdicts.map((v) => DEVICE_LEVELS.indexOf(v as DeviceIntegrityLevel)));
  if (achieved < required) failures.push('DEVICE_INTEGRITY_INSUFFICIENT');

  if (policy.requireLicensed && licensing !== 'LICENSED') failures.push('APP_NOT_LICENSED');

  return {
    ok: failures.length === 0,
    failures: [...new Set(failures)],
    deviceRecognitionVerdict: deviceVerdicts,
    appRecognitionVerdict: app.appRecognitionVerdict,
    appLicensingVerdict: licensing,
  };
}

/** The fields of a Google service-account JSON key this client uses. */
export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

export interface PlayIntegrityClientOptions {
  serviceAccount: ServiceAccountKey;
  /** Injectable for tests/proxies. Default: global `fetch`. */
  fetch?: typeof fetch;
}

const SCOPE = 'https://www.googleapis.com/auth/playintegrity';
const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';

/**
 * Decodes Play Integrity tokens through Google's `decodeIntegrityToken` API,
 * authenticating as a service account (OAuth 2.0 JWT bearer flow, no SDK).
 * The service account needs access to the Cloud project linked in the Play
 * Console. Access tokens are cached until shortly before expiry.
 */
export class PlayIntegrityClient {
  private readonly serviceAccount: ServiceAccountKey;
  private readonly fetchImpl: typeof fetch;
  private accessToken?: { value: string; expiresAt: number };

  constructor(options: PlayIntegrityClientOptions) {
    this.serviceAccount = options.serviceAccount;
    this.fetchImpl = options.fetch ?? fetch;
  }

  async decode(packageName: string, integrityToken: string): Promise<PlayIntegrityPayload> {
    const response = await this.fetchImpl(
      `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`,
      {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${await this.getAccessToken()}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ integrity_token: integrityToken }),
      }
    );
    if (!response.ok) {
      throw new AttestationError('DECODE_FAILED', `decodeIntegrityToken returned HTTP ${response.status}: ${await response.text()}`);
    }
    const body = (await response.json()) as { tokenPayloadExternal?: PlayIntegrityPayload };
    if (!body.tokenPayloadExternal) {
      throw new AttestationError('DECODE_FAILED', 'decodeIntegrityToken response has no tokenPayloadExternal');
    }
    return body.tokenPayloadExternal;
  }

  /** `decode()` + `evaluatePlayIntegrity()`. */
  async verify(integrityToken: string, policy: PlayIntegrityPolicy): Promise<PlayIntegrityVerdict> {
    return evaluatePlayIntegrity(await this.decode(policy.packageName, integrityToken), policy);
  }

  private async getAccessToken(): Promise<string> {
    const now = Date.now();
    if (this.accessToken && this.accessToken.expiresAt - 60_000 > now) return this.accessToken.value;

    const tokenUri = this.serviceAccount.token_uri ?? DEFAULT_TOKEN_URI;
    const issuedAt = Math.floor(now / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const claims = Buffer.from(
      JSON.stringify({
        iss: this.serviceAccount.client_email,
        scope: SCOPE,
        aud: tokenUri,
        iat: issuedAt,
        exp: issuedAt + 3600,
      })
    ).toString('base64url');
    const signature = createSign('RSA-SHA256')
      .update(`${header}.${claims}`)
      .sign(this.serviceAccount.private_key)
      .toString('base64url');

    const response = await this.fetchImpl(tokenUri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${header}.${claims}.${signature}`,
      }).toString(),
    });
    if (!response.ok) {
      throw new AttestationError('AUTH_FAILED', `service-account token exchange returned HTTP ${response.status}`);
    }
    const body = (await response.json()) as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new AttestationError('AUTH_FAILED', 'token response has no access_token');
    this.accessToken = { value: body.access_token, expiresAt: now + (body.expires_in ?? 3600) * 1000 };
    return body.access_token;
  }
}
