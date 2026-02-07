/**
 * Agent R fixes: normalizeUrl hardening, error classification, adaptive concurrency
 * (#1, #3, #7)
 */
import { normalizeUrl } from '../src/utils';
import { classifyError, errorKindLabel, VpnScanner, scan, scanMultiple } from '../src/scanner';

// ============================================================
// Task 1: normalizeUrl hardening (#1)
// ============================================================
describe('normalizeUrl hardening', () => {
  test('trims leading/trailing whitespace', () => {
    expect(normalizeUrl('  example.com  ')).toBe('https://example.com');
  });

  test('trims whitespace with scheme', () => {
    expect(normalizeUrl('  https://example.com  ')).toBe('https://example.com');
  });

  test('throws on empty string', () => {
    expect(() => normalizeUrl('')).toThrow('Invalid URL: empty target');
  });

  test('throws on whitespace-only string', () => {
    expect(() => normalizeUrl('   ')).toThrow('Invalid URL: empty target');
  });

  test('throws on malformed URL (https://:)', () => {
    expect(() => normalizeUrl('https://:')).toThrow('Invalid URL');
  });

  test('throws on malformed URL (https://)', () => {
    expect(() => normalizeUrl('https://')).toThrow('Invalid URL');
  });

  test('valid URL passes through', () => {
    expect(normalizeUrl('https://vpn.example.com')).toBe('https://vpn.example.com');
  });

  test('prepends https:// to bare hostname', () => {
    expect(normalizeUrl('vpn.example.com')).toBe('https://vpn.example.com');
  });

  test('scan returns error for empty target', async () => {
    const result = await scan('', { timeout: 1000 });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('empty target');
  });

  test('scan returns error for invalid URL', async () => {
    const result = await scan('https://:', { timeout: 1000 });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('Invalid URL');
  });

  test('scan returns error including original target value', async () => {
    const result = await scan('   ', { timeout: 1000 });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('empty target');
    expect(result.target).toBe('   ');
  });
});

// ============================================================
// Task 2: Error classification (#3)
// ============================================================
describe('classifyError', () => {
  test('classifies timeout errors', () => {
    const err = Object.assign(new Error('connect ETIMEDOUT'), { code: 'ETIMEDOUT' });
    expect(classifyError(err)).toBe('timeout');
  });

  test('classifies DNS errors', () => {
    const err = Object.assign(new Error('getaddrinfo ENOTFOUND x.y'), { code: 'ENOTFOUND' });
    expect(classifyError(err)).toBe('dns');
  });

  test('classifies TLS errors', () => {
    const err = new Error('TLS handshake failed');
    expect(classifyError(err)).toBe('tls');
  });

  test('classifies connection reset', () => {
    const err = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    expect(classifyError(err)).toBe('reset');
  });

  test('classifies connection refused', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    expect(classifyError(err)).toBe('refused');
  });

  test('classifies unknown errors', () => {
    expect(classifyError(new Error('something weird'))).toBe('unknown');
  });

  test('classifies non-Error values', () => {
    expect(classifyError('string error')).toBe('unknown');
    expect(classifyError(null)).toBe('unknown');
  });
});

describe('errorKindLabel', () => {
  test('returns human-readable labels', () => {
    expect(errorKindLabel('timeout')).toBe('Connection timed out');
    expect(errorKindLabel('dns')).toBe('DNS resolution failed');
    expect(errorKindLabel('tls')).toBe('TLS/SSL error');
    expect(errorKindLabel('reset')).toBe('Connection reset');
    expect(errorKindLabel('refused')).toBe('Connection refused');
    expect(errorKindLabel('unknown')).toBe('Unknown error');
  });
});

// ============================================================
// Task 3: Adaptive concurrency (#7)
// ============================================================
describe('scanMultiple adaptive concurrency', () => {
  test('preserves result order', async () => {
    const targets = ['https://a.invalid', 'https://b.invalid', 'https://c.invalid'];
    const results = await scanMultiple(targets, { timeout: 1000, concurrency: 2 });
    expect(results).toHaveLength(3);
    expect(results[0].target).toBe('https://a.invalid');
    expect(results[1].target).toBe('https://b.invalid');
    expect(results[2].target).toBe('https://c.invalid');
  });

  test('adaptiveConcurrency option accepted without error', async () => {
    const targets = ['https://a.invalid', 'https://b.invalid'];
    const results = await scanMultiple(targets, {
      timeout: 1000,
      concurrency: 3,
      adaptiveConcurrency: true,
    });
    expect(results).toHaveLength(2);
  });

  test('maxRetries option accepted without error', async () => {
    const targets = ['https://a.invalid'];
    const results = await scanMultiple(targets, {
      timeout: 1000,
      maxRetries: 1,
    });
    expect(results).toHaveLength(1);
  });

  test('ScanOptions defaults are backward compatible', () => {
    // Should not throw with no new options
    const scanner = new VpnScanner({});
    expect(scanner).toBeDefined();
  });

  test('high failure rate with adaptive concurrency completes', async () => {
    // All targets will fail (DNS) — adaptive should reduce concurrency but still complete
    const targets = Array.from({ length: 10 }, (_, i) => `https://fail-${i}.invalid`);
    const results = await scanMultiple(targets, {
      timeout: 1000,
      concurrency: 5,
      adaptiveConcurrency: true,
    });
    expect(results).toHaveLength(10);
    // All should have errors (DNS failure)
    for (const r of results) {
      // Either errors or no device (unreachable hosts)
      expect(r.device).toBeUndefined();
    }
  });
});
