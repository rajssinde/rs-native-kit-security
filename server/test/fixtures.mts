import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const sha256 = (...parts: Buffer[]): Buffer => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

// --- Minimal CBOR encoder (test-only) -------------------------------------------

type Encodable = number | string | Buffer | Encodable[] | Map<string, Encodable>;

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  if (length < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

export function encodeCbor(value: Encodable): Buffer {
  if (typeof value === 'number') return head(0, value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  const parts = [head(5, value.size)];
  for (const [k, v] of value) parts.push(encodeCbor(k), encodeCbor(v));
  return Buffer.concat(parts);
}

// --- Synthetic App Attest chain ---------------------------------------------------

function openssl(cwd: string, ...args: string[]): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

export interface AttestationFixture {
  attestation: string;
  keyId: string;
  challenge: string;
  appId: string;
  rootPem: string;
  privateKey: KeyObject;
}

export const AAGUID_PRODUCTION = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
export const AAGUID_DEVELOPMENT = Buffer.from('appattestdevelop');

export function rawP256(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, 'base64url'), Buffer.from(jwk.y!, 'base64url')]);
}

/**
 * Builds a structurally faithful App Attest attestation object: a P-384
 * root and intermediate, a P-256 credential certificate carrying the nonce in
 * extension 1.2.840.113635.100.8.2, and matching authenticator data.
 */
export function makeAttestation(options: {
  challenge?: string;
  appId?: string;
  aaguid?: Buffer;
  counter?: number;
  /** Bind the certificate to a different nonce than the data implies. */
  nonceOverride?: Buffer;
} = {}): AttestationFixture {
  const challenge = options.challenge ?? 'server-challenge-123';
  const appId = options.appId ?? 'AB12CD34EF.com.example.app';
  const dir = mkdtempSync(join(tmpdir(), 'appattest-'));
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const keyIdBytes = sha256(rawP256(publicKey));

    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(options.counter ?? 0);
    const credentialIdLength = Buffer.alloc(2);
    credentialIdLength.writeUInt16BE(keyIdBytes.length);
    const authData = Buffer.concat([
      sha256(Buffer.from(appId)),
      Buffer.from([0x40]), // flags: attested credential data present
      counter,
      options.aaguid ?? AAGUID_PRODUCTION,
      credentialIdLength,
      keyIdBytes,
      Buffer.from([0xa0]), // empty COSE key placeholder (the verifier uses the certificate's key)
    ]);
    const nonce = options.nonceOverride ?? sha256(authData, sha256(Buffer.from(challenge)));

    writeFileSync(join(dir, 'leaf.key'), privateKey.export({ format: 'pem', type: 'pkcs8' }));
    writeFileSync(
      join(dir, 'ext.cnf'),
      [
        '[ca]',
        'basicConstraints=critical,CA:TRUE',
        'keyUsage=critical,keyCertSign,cRLSign',
        '[leaf]',
        'basicConstraints=critical,CA:FALSE',
        `1.2.840.113635.100.8.2=DER:3024a1220420${nonce.toString('hex')}`,
      ].join('\n')
    );
    openssl(dir, 'ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', 'root.key');
    openssl(dir, 'req', '-new', '-x509', '-key', 'root.key', '-subj', '/CN=Test App Attest Root', '-days', '3650', '-out', 'root.pem', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    openssl(dir, 'ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', 'int.key');
    openssl(dir, 'req', '-new', '-key', 'int.key', '-subj', '/CN=Test App Attest CA 1', '-out', 'int.csr');
    openssl(dir, 'x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '365', '-extfile', 'ext.cnf', '-extensions', 'ca', '-out', 'int.pem');
    openssl(dir, 'req', '-new', '-key', 'leaf.key', '-subj', '/CN=test-credential', '-out', 'leaf.csr');
    openssl(dir, 'x509', '-req', '-in', 'leaf.csr', '-CA', 'int.pem', '-CAkey', 'int.key', '-CAcreateserial', '-days', '30', '-extfile', 'ext.cnf', '-extensions', 'leaf', '-outform', 'DER', '-out', 'leaf.der');
    openssl(dir, 'x509', '-in', 'int.pem', '-outform', 'DER', '-out', 'int.der');

    const attestation = encodeCbor(
      new Map<string, Encodable>([
        ['fmt', 'apple-appattest'],
        [
          'attStmt',
          new Map<string, Encodable>([
            ['x5c', [readFileSync(join(dir, 'leaf.der')), readFileSync(join(dir, 'int.der'))]],
            ['receipt', Buffer.from('receipt-bytes')],
          ]),
        ],
        ['authData', authData],
      ])
    );

    return {
      attestation: attestation.toString('base64'),
      keyId: keyIdBytes.toString('base64'),
      challenge,
      appId,
      rootPem: readFileSync(join(dir, 'root.pem'), 'utf8'),
      privateKey,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** An App Attest assertion signed by `privateKey` for `clientData`. */
export function makeAssertion(options: {
  privateKey: KeyObject;
  clientData: string;
  appId: string;
  counter: number;
}): string {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(options.counter);
  const authenticatorData = Buffer.concat([sha256(Buffer.from(options.appId)), Buffer.from([0x00]), counter]);
  const nonce = sha256(authenticatorData, sha256(Buffer.from(options.clientData)));
  const signature = sign('sha256', nonce, options.privateKey);
  return encodeCbor(
    new Map<string, Encodable>([
      ['signature', signature],
      ['authenticatorData', authenticatorData],
    ])
  ).toString('base64');
}
