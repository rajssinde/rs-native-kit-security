import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { createMockNativeSecurity } from '../__fixtures__/nativeSecurity';
import { SecurityConfigError } from '../types';

const mockNativeSecurity = createMockNativeSecurity();

jest.mock('../specs/nativeSecurity', () => ({
  isNativeSecuritySupported: true,
  getNativeSecurity: () => mockNativeSecurity,
}));

const { enableSslPinning, resetSslPinningState } = require('../ssl/enforce');

const PIN_A = `sha256/${'A'.repeat(43)}=`;
const PIN_B = `sha256/${'B'.repeat(43)}=`;
const NOW = 1_800_000_000_000;

afterEach(() => {
  resetSslPinningState();
  mockNativeSecurity.enableSslPinning.mockClear();
});

describe('enableSslPinning', () => {
  it('passes normalised hosts and bare hashes to native', async () => {
    await enableSslPinning(
      [{ hostname: 'API.Example.com', pins: [PIN_A, PIN_B] }],
      { includeSubdomains: true }
    );
    expect(mockNativeSecurity.enableSslPinning).toHaveBeenCalledWith([
      {
        hostname: 'api.example.com',
        pins: ['A'.repeat(43) + '=', 'B'.repeat(43) + '='],
        includeSubdomains: true,
      },
    ]);
  });

  it('requires a backup pin for every host', async () => {
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: [PIN_A] }])
    ).rejects.toThrow(SecurityConfigError);
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: [PIN_A, PIN_A] }])
    ).rejects.toThrow('two distinct');
    expect(mockNativeSecurity.enableSslPinning).not.toHaveBeenCalled();
  });

  it('rejects malformed pins and hostnames', async () => {
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: ['nope', PIN_B] }])
    ).rejects.toThrow(SecurityConfigError);
    for (const hostname of [
      'https://api.example.com',
      'api.example.com:443',
      '*.example.com',
      'localhost',
      'api.example.com/v1',
    ]) {
      await expect(
        enableSslPinning([{ hostname, pins: [PIN_A, PIN_B] }])
      ).rejects.toThrow('is not a hostname');
    }
    await expect(enableSslPinning([])).rejects.toThrow(SecurityConfigError);
  });

  it('skips hosts whose pins expired (with a warning) but pins the rest', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    await enableSslPinning(
      [
        {
          hostname: 'old.example.com',
          pins: [PIN_A, PIN_B],
          expiresAt: NOW - 1,
        },
        {
          hostname: 'api.example.com',
          pins: [PIN_A, PIN_B],
          expiresAt: NOW + 1,
        },
      ],
      { now: NOW }
    );
    const domains = mockNativeSecurity.enableSslPinning.mock.calls[0]![0] as {
      hostname: string;
    }[];
    expect(domains.map((d) => d.hostname)).toEqual(['api.example.com']);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('old.example.com')
    );
    warn.mockRestore();
  });

  it('refuses to run when every host has expired pins', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(
      enableSslPinning(
        [
          {
            hostname: 'api.example.com',
            pins: [PIN_A, PIN_B],
            expiresAt: NOW - 1,
          },
        ],
        { now: NOW }
      )
    ).rejects.toThrow('expired');
    warn.mockRestore();
  });

  it('can only be enabled once', async () => {
    await enableSslPinning([
      { hostname: 'api.example.com', pins: [PIN_A, PIN_B] },
    ]);
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: [PIN_A, PIN_B] }])
    ).rejects.toThrow('already enabled');
  });

  it('stays retryable when native rejects', async () => {
    mockNativeSecurity.enableSslPinning.mockRejectedValueOnce(
      new Error('boom')
    );
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: [PIN_A, PIN_B] }])
    ).rejects.toThrow('boom');
    await expect(
      enableSslPinning([{ hostname: 'api.example.com', pins: [PIN_A, PIN_B] }])
    ).resolves.toBeUndefined();
  });
});
