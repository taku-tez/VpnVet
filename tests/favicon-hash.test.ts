/**
 * Tests for MurmurHash3 and favicon hash detection
 */

import { murmurhash3_32, faviconHash } from '../src/utils.js';

describe('murmurhash3_32', () => {
  test('empty input returns 0', () => {
    expect(murmurhash3_32(Buffer.from(''))).toBe(0);
  });

  test('known test vectors', () => {
    // Standard MurmurHash3_x86_32 test vectors with seed=0
    expect(murmurhash3_32(Buffer.from('hello'))).toBe(613153351);
    expect(murmurhash3_32(Buffer.from('hello world'))).toBe(1586663183);
    expect(murmurhash3_32(Buffer.from('test'))).toBe(-1167338989);
  });

  test('handles various input lengths (tail cases)', () => {
    // 1 byte tail
    expect(typeof murmurhash3_32(Buffer.from('a'))).toBe('number');
    // 2 byte tail
    expect(typeof murmurhash3_32(Buffer.from('ab'))).toBe('number');
    // 3 byte tail
    expect(typeof murmurhash3_32(Buffer.from('abc'))).toBe('number');
    // Exact 4-byte block
    expect(typeof murmurhash3_32(Buffer.from('abcd'))).toBe('number');
  });

  test('different seeds produce different results', () => {
    const data = Buffer.from('test');
    const h0 = murmurhash3_32(data, 0);
    const h1 = murmurhash3_32(data, 1);
    expect(h0).not.toBe(h1);
  });
});

describe('faviconHash', () => {
  test('computes Shodan-compatible hash (base64 then mmh3)', () => {
    // faviconHash = mmh3(base64(bytes))
    const testBytes = Buffer.from('test favicon data');
    const b64 = testBytes.toString('base64');
    const expectedHash = murmurhash3_32(Buffer.from(b64, 'utf8'));
    expect(faviconHash(testBytes)).toBe(expectedHash);
  });

  test('returns signed 32-bit integer', () => {
    const hash = faviconHash(Buffer.from('any data'));
    expect(hash).toBeGreaterThanOrEqual(-2147483648);
    expect(hash).toBeLessThanOrEqual(2147483647);
  });

  test('empty favicon returns hash of empty base64', () => {
    // base64('') = ''
    const hash = faviconHash(Buffer.from(''));
    expect(hash).toBe(murmurhash3_32(Buffer.from('')));
  });
});
