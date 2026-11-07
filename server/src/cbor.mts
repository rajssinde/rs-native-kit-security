import { AttestationError } from './errors.mts';

/**
 * Minimal CBOR (RFC 8949) decoder covering what App Attest objects use:
 * unsigned/negative integers, byte and text strings, arrays, maps, and the
 * simple values false/true/null. Definite lengths only; anything else throws.
 * Input is attacker-controlled, so every read is bounds-checked.
 */
export type CborValue =
  | number
  | bigint
  | Buffer
  | string
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>;

const MAX_DEPTH = 16;

export function decodeCbor(input: Buffer): CborValue {
  const state = { offset: 0 };
  const value = decodeItem(input, state, 0);
  if (state.offset !== input.length) {
    throw new AttestationError('CBOR_TRAILING_BYTES', 'unexpected bytes after the CBOR item');
  }
  return value;
}

function need(input: Buffer, offset: number, count: number): void {
  if (offset + count > input.length) {
    throw new AttestationError('CBOR_TRUNCATED', 'CBOR data ends unexpectedly');
  }
}

function readArgument(input: Buffer, state: { offset: number }, info: number): number | bigint {
  if (info < 24) return info;
  const sizes: Record<number, number> = { 24: 1, 25: 2, 26: 4, 27: 8 };
  const size = sizes[info];
  if (size === undefined) {
    throw new AttestationError('CBOR_UNSUPPORTED', `unsupported CBOR additional info ${info}`);
  }
  need(input, state.offset, size);
  const at = state.offset;
  state.offset += size;
  if (size === 1) return input.readUInt8(at);
  if (size === 2) return input.readUInt16BE(at);
  if (size === 4) return input.readUInt32BE(at);
  const big = input.readBigUInt64BE(at);
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
}

function readLength(input: Buffer, state: { offset: number }, info: number): number {
  const length = readArgument(input, state, info);
  if (typeof length !== 'number') {
    throw new AttestationError('CBOR_TOO_LARGE', 'CBOR length exceeds the supported range');
  }
  return length;
}

function decodeItem(input: Buffer, state: { offset: number }, depth: number): CborValue {
  if (depth > MAX_DEPTH) {
    throw new AttestationError('CBOR_TOO_DEEP', 'CBOR nesting is too deep');
  }
  need(input, state.offset, 1);
  const initial = input.readUInt8(state.offset++);
  const major = initial >> 5;
  const info = initial & 0x1f;

  switch (major) {
    case 0:
      return readArgument(input, state, info);
    case 1: {
      const n = readArgument(input, state, info);
      return typeof n === 'bigint' ? -1n - n : -1 - n;
    }
    case 2: {
      const length = readLength(input, state, info);
      need(input, state.offset, length);
      const bytes = Buffer.from(input.subarray(state.offset, state.offset + length));
      state.offset += length;
      return bytes;
    }
    case 3: {
      const length = readLength(input, state, info);
      need(input, state.offset, length);
      const text = input.toString('utf8', state.offset, state.offset + length);
      state.offset += length;
      return text;
    }
    case 4: {
      const length = readLength(input, state, info);
      const items: CborValue[] = [];
      for (let i = 0; i < length; i++) items.push(decodeItem(input, state, depth + 1));
      return items;
    }
    case 5: {
      const length = readLength(input, state, info);
      const map = new Map<CborValue, CborValue>();
      for (let i = 0; i < length; i++) {
        const key = decodeItem(input, state, depth + 1);
        map.set(key, decodeItem(input, state, depth + 1));
      }
      return map;
    }
    case 7:
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new AttestationError('CBOR_UNSUPPORTED', `unsupported CBOR simple value ${info}`);
    default:
      throw new AttestationError('CBOR_UNSUPPORTED', `unsupported CBOR major type ${major}`);
  }
}
