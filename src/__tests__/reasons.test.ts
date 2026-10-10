import { describe, expect, it } from '@jest/globals';
import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import { describeReason, REASON_DESCRIPTIONS } from '../reasons';

const ROOT = join(__dirname, '..', '..');

function sourceFiles(dir: string, extension: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path, extension);
    return path.endsWith(extension) ? [path] : [];
  });
}

/** Reason codes emitted by native detectors: signal("CODE", ...), arrayOf("CODE"), reasons: ["CODE"], notConfigured("CODE"). */
function nativeReasonCodes(): Set<string> {
  const files = [
    ...sourceFiles(join(ROOT, 'android/src/main'), '.kt'),
    ...sourceFiles(join(ROOT, 'ios'), '.swift').filter(
      (f) => !f.includes('/Tests/')
    ),
  ];
  const pattern =
    /(?:signal\(|arrayOf\(|reasons: \[|notConfigured\()"([A-Z][A-Z0-9_]+)"/g;
  const codes = new Set<string>();
  for (const file of files) {
    for (const match of readFileSync(file, 'utf8').matchAll(pattern)) {
      codes.add(match[1]!);
    }
  }
  return codes;
}

describe('reason codes', () => {
  it('finds the native codes (guards against the scan silently matching nothing)', () => {
    expect(nativeReasonCodes().size).toBeGreaterThan(50);
  });

  it('every reason code a native detector emits has a description', () => {
    const missing = [...nativeReasonCodes()].filter(
      (code) => !(code in REASON_DESCRIPTIONS)
    );
    expect(missing).toEqual([]);
  });

  it('every described code is emitted by some native detector', () => {
    const codes = nativeReasonCodes();
    const unused = Object.keys(REASON_DESCRIPTIONS).filter(
      (code) => !codes.has(code)
    );
    expect(unused).toEqual([]);
  });

  it('describeReason falls back to the code itself', () => {
    expect(describeReason('SU_BINARY_FOUND')).toMatch(/su/);
    expect(describeReason('NOT_A_REAL_CODE')).toBe('NOT_A_REAL_CODE');
  });
});
