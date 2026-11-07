import { X509Certificate } from 'node:crypto';
import { findExtension, readTlv, type Tlv } from './der.mts';
import { AttestationError } from './errors.mts';
import { digestBytes } from './playIntegrity.mts';

/**
 * Google's hardware attestation roots, from https://android.googleapis.com/attestation/root
 * (fetched 2026-10-11; fingerprints checked by test):
 * - RSA-4096, valid until 2042-03-15,
 *   SHA-256 CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC
 * - "Key Attestation CA1", EC P-384, valid until 2035-07-15,
 *   SHA-256 6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0
 * A chain is trusted when its top certificate is signed by one of these keys,
 * so chains ending in an older certificate for the same RSA key still verify.
 */
export const GOOGLE_KEY_ATTESTATION_ROOTS: readonly string[] = [
  `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----
`,
  `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----
`,
];

/** Google's attestation certificate status list (revoked/suspended serials). */
export const KEY_ATTESTATION_STATUS_URL = 'https://android.googleapis.com/attestation/status';

const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';

export type KeySecurityLevel = 'Software' | 'TrustedEnvironment' | 'StrongBox';
export type VerifiedBootState = 'Verified' | 'SelfSigned' | 'Unverified' | 'Failed';

const SECURITY_LEVELS: KeySecurityLevel[] = ['Software', 'TrustedEnvironment', 'StrongBox'];
const BOOT_STATES: VerifiedBootState[] = ['Verified', 'SelfSigned', 'Unverified', 'Failed'];

export interface KeyAttestationInput {
  /** Base64 DER certificates from `requestKeyAttestation()`, leaf first. */
  certificateChain: string[];
  /** The exact challenge string the app passed to `requestKeyAttestation()`. */
  challenge: string;
  /** Your app's package name. */
  packageName: string;
  /**
   * Signing-certificate SHA-256 digests to accept (hex, `:`-separated hex,
   * base64 or base64url). Omit to skip the check (not recommended).
   */
  certificateSha256Digests?: string[];
  /**
   * Revoked attestation certificate serials, from
   * `fetchKeyAttestationRevocations()`. Required: leaked device keys are the
   * main way Key Attestation is forged, and this list is how Google revokes them.
   */
  revokedSerials: ReadonlySet<string>;
  /** Override the trust anchors (tests only). Default: `GOOGLE_KEY_ATTESTATION_ROOTS`. */
  rootCertificatesPem?: readonly string[];
  /** Verification time. Default: now. */
  now?: Date;
}

export interface KeyAttestationVerdict {
  /** `true` only when every requirement passed. */
  ok: boolean;
  /**
   * Machine-readable codes for every requirement that failed:
   * `NOT_HARDWARE_BACKED`, `BOOTLOADER_UNLOCKED`, `BOOT_STATE_NOT_VERIFIED`,
   * `PACKAGE_MISMATCH`, `CERTIFICATE_MISMATCH`.
   */
  failures: string[];
  attestationVersion: number;
  /** Who produced the attestation; only `TrustedEnvironment`/`StrongBox` are hardware. */
  attestationSecurityLevel: KeySecurityLevel;
  keyMintSecurityLevel: KeySecurityLevel;
  /** From the hardware-enforced root of trust; `undefined` when the device didn't report it. */
  deviceLocked?: boolean;
  verifiedBootState?: VerifiedBootState;
  /** Hex digest of the key that verified the boot image (identifies the OS signer). */
  verifiedBootKey?: string;
  osVersion?: number;
  /** YYYYMM */
  osPatchLevel?: number;
  /** YYYYMMDD */
  vendorPatchLevel?: number;
  /** YYYYMMDD */
  bootPatchLevel?: number;
  /** Packages sharing the attesting app's UID, as reported by Android. */
  packageNames: string[];
}

interface RootOfTrust {
  verifiedBootKey: Buffer;
  deviceLocked: boolean;
  verifiedBootState: VerifiedBootState;
}

interface AuthorizationList {
  rootOfTrust?: RootOfTrust;
  osVersion?: number;
  osPatchLevel?: number;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  packageNames?: string[];
  signatureDigests?: Buffer[];
}

interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: KeySecurityLevel;
  keyMintVersion: number;
  keyMintSecurityLevel: KeySecurityLevel;
  attestationChallenge: Buffer;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

function fail(code: string, message: string): never {
  throw new AttestationError(code, message);
}

// --- KeyDescription (Android Keystore attestation extension) --------------------------

function children(input: Buffer, parent: Tlv): Tlv[] {
  const items: Tlv[] = [];
  for (let offset = parent.start; offset < parent.end; ) {
    const item = readTlv(input, offset, parent.end);
    items.push(item);
    offset = item.end;
  }
  return items;
}

function expectTag(item: Tlv | undefined, tag: number, what: string): Tlv {
  if (!item || item.tag !== tag) fail('MALFORMED', `${what} has an unexpected type`);
  return item;
}

/** Non-negative INTEGER or ENUMERATED that fits in a JS number. */
function readUint(input: Buffer, item: Tlv | undefined, what: string): number {
  if (!item || (item.tag !== 0x02 && item.tag !== 0x0a)) fail('MALFORMED', `${what} is not an integer`);
  const bytes = input.subarray(item.start, item.end);
  if (bytes.length === 0 || bytes.length > 7 || (bytes[0]! & 0x80) !== 0) fail('MALFORMED', `${what} is out of range`);
  return bytes.reduce((value, byte) => value * 256 + byte, 0);
}

function readOctets(input: Buffer, item: Tlv | undefined, what: string): Buffer {
  const octets = expectTag(item, 0x04, what);
  return Buffer.from(input.subarray(octets.start, octets.end));
}

function readSecurityLevel(input: Buffer, item: Tlv | undefined, what: string): KeySecurityLevel {
  return SECURITY_LEVELS[readUint(input, item, what)] ?? fail('MALFORMED', `${what} has an unknown value`);
}

function readRootOfTrust(input: Buffer, item: Tlv): RootOfTrust {
  const [bootKey, locked, state] = children(input, expectTag(item, 0x30, 'rootOfTrust'));
  const lockedTlv = expectTag(locked, 0x01, 'rootOfTrust.deviceLocked');
  return {
    verifiedBootKey: readOctets(input, bootKey, 'rootOfTrust.verifiedBootKey'),
    deviceLocked: lockedTlv.end > lockedTlv.start && input[lockedTlv.start] !== 0,
    verifiedBootState:
      BOOT_STATES[readUint(input, state, 'rootOfTrust.verifiedBootState')] ??
      fail('MALFORMED', 'rootOfTrust.verifiedBootState has an unknown value'),
  };
}

/** AttestationApplicationId ::= SEQUENCE { SET OF SEQUENCE { name OCTET STRING, version INTEGER }, SET OF OCTET STRING } */
function readApplicationId(value: Buffer): Pick<AuthorizationList, 'packageNames' | 'signatureDigests'> {
  const [packageInfos, digests] = children(value, expectTag(readTlv(value, 0), 0x30, 'attestationApplicationId'));
  return {
    packageNames: children(value, expectTag(packageInfos, 0x31, 'packageInfos')).map((info) => {
      const [name] = children(value, expectTag(info, 0x30, 'packageInfo'));
      return readOctets(value, name, 'packageInfo.name').toString('utf8');
    }),
    signatureDigests: children(value, expectTag(digests, 0x31, 'signatureDigests')).map((digest) =>
      readOctets(value, digest, 'signatureDigest')
    ),
  };
}

/** Only the tags this verifier evaluates; everything else in the list is skipped. */
function readAuthorizationList(input: Buffer, item: Tlv | undefined, what: string): AuthorizationList {
  const list: AuthorizationList = {};
  for (const field of children(input, expectTag(item, 0x30, what))) {
    if ((field.tag & 0xe0) !== 0xa0) continue; // context-specific, constructed (EXPLICIT)
    const [inner] = children(input, field);
    switch (field.tagNumber) {
      case 704:
        list.rootOfTrust = readRootOfTrust(input, inner!);
        break;
      case 705:
        list.osVersion = readUint(input, inner, 'osVersion');
        break;
      case 706:
        list.osPatchLevel = readUint(input, inner, 'osPatchLevel');
        break;
      case 709:
        Object.assign(list, readApplicationId(readOctets(input, inner, 'attestationApplicationId')));
        break;
      case 718:
        list.vendorPatchLevel = readUint(input, inner, 'vendorPatchLevel');
        break;
      case 719:
        list.bootPatchLevel = readUint(input, inner, 'bootPatchLevel');
        break;
    }
  }
  return list;
}

function parseKeyDescription(value: Buffer): KeyDescription {
  const fields = children(value, expectTag(readTlv(value, 0), 0x30, 'KeyDescription'));
  return {
    attestationVersion: readUint(value, fields[0], 'attestationVersion'),
    attestationSecurityLevel: readSecurityLevel(value, fields[1], 'attestationSecurityLevel'),
    keyMintVersion: readUint(value, fields[2], 'keyMintVersion'),
    keyMintSecurityLevel: readSecurityLevel(value, fields[3], 'keyMintSecurityLevel'),
    attestationChallenge: readOctets(value, fields[4], 'attestationChallenge'),
    softwareEnforced: readAuthorizationList(value, fields[6], 'softwareEnforced'),
    hardwareEnforced: readAuthorizationList(value, fields[7], 'hardwareEnforced'),
  };
}

// --- Certificate chain --------------------------------------------------------------

/** Serials as Google's status list writes them: lowercase hex, no leading zeros. */
function normalizeSerial(serial: string): string {
  return serial.toLowerCase().replace(/^0+(?=.)/, '');
}

function isSelfSigned(certificate: X509Certificate): boolean {
  return certificate.checkIssued(certificate) && certificate.verify(certificate.publicKey);
}

function verifyChain(input: KeyAttestationInput): X509Certificate[] {
  const chain = input.certificateChain;
  if (!Array.isArray(chain) || chain.length < 2) fail('MALFORMED', 'certificate chain needs at least two certificates');
  const certificates = chain.map((der, index) => {
    try {
      return new X509Certificate(Buffer.from(der, 'base64'));
    } catch {
      return fail('MALFORMED', `certificate ${index} is not a DER X.509 certificate`);
    }
  });

  for (let i = 0; i < certificates.length - 1; i++) {
    const [subject, issuer] = [certificates[i]!, certificates[i + 1]!];
    if (!subject.checkIssued(issuer) || !subject.verify(issuer.publicKey)) {
      fail('UNTRUSTED_CHAIN', `certificate ${i} is not signed by certificate ${i + 1}`);
    }
  }
  const top = certificates[certificates.length - 1]!;
  const roots = (input.rootCertificatesPem ?? GOOGLE_KEY_ATTESTATION_ROOTS).map((pem) => new X509Certificate(pem));
  if (!roots.some((root) => top.verify(root.publicKey))) {
    fail('UNTRUSTED_CHAIN', 'chain does not end at a Google hardware attestation root');
  }

  // The device key is a signing key too: someone holding a genuine attested
  // key could use it to sign a forged leaf. Only the real leaf may carry the
  // attestation extension.
  certificates.slice(1).forEach((certificate, index) => {
    if (findExtension(certificate.raw, KEY_DESCRIPTION_OID)) {
      fail('UNTRUSTED_CHAIN', `certificate ${index + 1} carries an attestation extension; only the leaf may`);
    }
  });

  // The leaf's validity comes from the device clock, and a self-signed top is
  // trusted for its pinned key, not its dates; check the CA certificates between.
  const now = input.now ?? new Date();
  certificates.slice(1).forEach((certificate, index) => {
    if (isSelfSigned(certificate)) return;
    if (now < new Date(certificate.validFrom) || now > new Date(certificate.validTo)) {
      fail('CERT_EXPIRED', `certificate ${index + 1} is not valid at ${now.toISOString()}`);
    }
  });

  const revoked = new Set([...input.revokedSerials].map(normalizeSerial));
  certificates.forEach((certificate, index) => {
    if (revoked.has(normalizeSerial(certificate.serialNumber))) {
      fail('CERT_REVOKED', `certificate ${index} (serial ${certificate.serialNumber}) has been revoked by Google`);
    }
  });
  return certificates;
}

// --- Public API -----------------------------------------------------------------------

/**
 * Downloads Google's attestation status list and returns every listed serial
 * (revoked or suspended). Google updates it as device keys leak; cache it for
 * no more than 24 hours.
 */
export async function fetchKeyAttestationRevocations(fetchImpl: typeof fetch = fetch): Promise<Set<string>> {
  const response = await fetchImpl(KEY_ATTESTATION_STATUS_URL, { cache: 'no-store' });
  if (!response.ok) fail('REVOCATION_LIST_UNAVAILABLE', `status list request failed with HTTP ${response.status}`);
  const body = (await response.json()) as { entries?: unknown };
  if (!body.entries || typeof body.entries !== 'object') fail('REVOCATION_LIST_UNAVAILABLE', 'status list has no entries');
  return new Set(Object.keys(body.entries).map(normalizeSerial));
}

/**
 * Verifies an Android Key Attestation certificate chain from
 * `requestKeyAttestation()`. Throws `AttestationError` when the chain can't be
 * trusted at all (`MALFORMED`, `UNTRUSTED_CHAIN`, `CERT_EXPIRED`,
 * `CERT_REVOKED`, `CHALLENGE_MISMATCH`); otherwise returns what the device's
 * secure hardware attested, with a `failures` entry for every requirement it
 * doesn't meet.
 *
 * The bootloader and verified-boot state are signed by the TEE/StrongBox, so
 * root-hiding tools on the device can't change them. The package name and
 * signing digests are reported by Android itself, so they are only as
 * trustworthy as the OS — which a locked, verified boot is what establishes.
 */
export function verifyKeyAttestation(input: KeyAttestationInput): KeyAttestationVerdict {
  const [leaf] = verifyChain(input);
  const extension =
    findExtension(leaf!.raw, KEY_DESCRIPTION_OID) ?? fail('MALFORMED', 'leaf certificate has no attestation extension');
  const description = parseKeyDescription(extension);

  if (!description.attestationChallenge.equals(Buffer.from(input.challenge, 'utf8'))) {
    fail('CHALLENGE_MISMATCH', 'attestation is not bound to this challenge');
  }

  const hardware = description.hardwareEnforced;
  const software = description.softwareEnforced;
  const rootOfTrust = hardware.rootOfTrust;
  const packageNames = software.packageNames ?? hardware.packageNames ?? [];
  const signatureDigests = software.signatureDigests ?? hardware.signatureDigests ?? [];

  const failures: string[] = [];
  if (description.attestationSecurityLevel === 'Software' || description.keyMintSecurityLevel === 'Software') {
    failures.push('NOT_HARDWARE_BACKED');
  }
  if (rootOfTrust?.deviceLocked !== true) failures.push('BOOTLOADER_UNLOCKED');
  if (rootOfTrust?.verifiedBootState !== 'Verified') failures.push('BOOT_STATE_NOT_VERIFIED');
  if (!packageNames.includes(input.packageName)) failures.push('PACKAGE_MISMATCH');
  if (input.certificateSha256Digests) {
    const accepted = input.certificateSha256Digests.map(digestBytes);
    const matches =
      signatureDigests.length > 0 && signatureDigests.every((digest) => accepted.some((a) => a.equals(digest)));
    if (!matches) failures.push('CERTIFICATE_MISMATCH');
  }

  return {
    ok: failures.length === 0,
    failures,
    attestationVersion: description.attestationVersion,
    attestationSecurityLevel: description.attestationSecurityLevel,
    keyMintSecurityLevel: description.keyMintSecurityLevel,
    deviceLocked: rootOfTrust?.deviceLocked,
    verifiedBootState: rootOfTrust?.verifiedBootState,
    verifiedBootKey: rootOfTrust?.verifiedBootKey.toString('hex'),
    osVersion: hardware.osVersion,
    osPatchLevel: hardware.osPatchLevel,
    vendorPatchLevel: hardware.vendorPatchLevel,
    bootPatchLevel: hardware.bootPatchLevel,
    packageNames,
  };
}
