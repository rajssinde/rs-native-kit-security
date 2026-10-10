import { AttestationError } from './errors.mts';

/** One DER TLV: tag byte, and the start/end of its contents within the input. */
interface Tlv {
  tag: number;
  start: number;
  end: number;
}

function readTlv(input: Buffer, offset: number, limit = input.length): Tlv {
  if (offset + 2 > limit) throw new AttestationError('DER_TRUNCATED', 'DER data ends unexpectedly');
  const tag = input.readUInt8(offset);
  let length = input.readUInt8(offset + 1);
  let start = offset + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4 || start + bytes > limit) {
      throw new AttestationError('DER_INVALID', 'unsupported DER length encoding');
    }
    length = 0;
    for (let i = 0; i < bytes; i++) length = length * 256 + input.readUInt8(start + i);
    start += bytes;
  }
  const end = start + length;
  if (end > limit) throw new AttestationError('DER_TRUNCATED', 'DER value runs past its container');
  return { tag, start, end };
}

/** DER encoding of an OBJECT IDENTIFIER's contents, e.g. "1.2.840.113635.100.8.2". */
export function encodeOid(oid: string): Buffer {
  const parts = oid.split('.').map(Number);
  const bytes = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const chunk = [part & 0x7f];
    for (let value = Math.floor(part / 128); value > 0; value = Math.floor(value / 128)) {
      chunk.unshift((value & 0x7f) | 0x80);
    }
    bytes.push(...chunk);
  }
  return Buffer.from(bytes);
}

/**
 * Returns the `extnValue` contents of the X.509 extension identified by `oid`
 * in a DER certificate, or `undefined` if absent. Walks the certificate's
 * structure (Certificate → TBSCertificate → [3] extensions) rather than
 * searching for the OID bytes, so a matching byte pattern elsewhere in the
 * certificate can't be mistaken for the extension.
 */
export function findExtension(certificateDer: Buffer, oid: string): Buffer | undefined {
  const wantedOid = encodeOid(oid);
  const certificate = readTlv(certificateDer, 0);
  const tbs = readTlv(certificateDer, certificate.start, certificate.end);

  for (let offset = tbs.start; offset < tbs.end; ) {
    const field = readTlv(certificateDer, offset, tbs.end);
    offset = field.end;
    if (field.tag !== 0xa3) continue; // [3] EXPLICIT Extensions

    const extensions = readTlv(certificateDer, field.start, field.end);
    for (let extOffset = extensions.start; extOffset < extensions.end; ) {
      const extension = readTlv(certificateDer, extOffset, extensions.end);
      extOffset = extension.end;

      const extnId = readTlv(certificateDer, extension.start, extension.end);
      if (extnId.tag !== 0x06) continue;
      if (!certificateDer.subarray(extnId.start, extnId.end).equals(wantedOid)) continue;

      let next = readTlv(certificateDer, extnId.end, extension.end);
      if (next.tag === 0x01) next = readTlv(certificateDer, next.end, extension.end); // critical BOOLEAN
      if (next.tag !== 0x04) throw new AttestationError('DER_INVALID', 'extension value is not an OCTET STRING');
      return Buffer.from(certificateDer.subarray(next.start, next.end));
    }
  }
  return undefined;
}

/**
 * Apple's App Attest nonce extension value is `SEQUENCE { [1] EXPLICIT OCTET STRING }`.
 * Returns that octet string.
 */
export function readAppAttestNonce(extensionValue: Buffer): Buffer {
  const sequence = readTlv(extensionValue, 0);
  if (sequence.tag !== 0x30) throw new AttestationError('DER_INVALID', 'nonce extension is not a SEQUENCE');
  for (let offset = sequence.start; offset < sequence.end; ) {
    const item = readTlv(extensionValue, offset, sequence.end);
    offset = item.end;
    if (item.tag !== 0xa1) continue;
    const octets = readTlv(extensionValue, item.start, item.end);
    if (octets.tag !== 0x04) throw new AttestationError('DER_INVALID', 'nonce is not an OCTET STRING');
    return Buffer.from(extensionValue.subarray(octets.start, octets.end));
  }
  throw new AttestationError('DER_INVALID', 'nonce extension has no [1] element');
}
