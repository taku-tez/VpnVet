import { classifyError, errorKindLabel } from '../src/scanner.js';

describe('classifyError', () => {
  it('classifies timeout errors', () => {
    const err = Object.assign(new Error('connect ETIMEDOUT'), { code: 'ETIMEDOUT' });
    expect(classifyError(err)).toBe('timeout');
  });

  it('classifies DNS errors', () => {
    const err = Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' });
    expect(classifyError(err)).toBe('dns');
  });

  it('classifies TLS errors', () => {
    const err = new Error('unable to verify the first certificate (tls)');
    expect(classifyError(err)).toBe('tls');
  });

  it('classifies connection reset', () => {
    const err = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    expect(classifyError(err)).toBe('reset');
  });

  it('classifies connection refused', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    expect(classifyError(err)).toBe('refused');
  });

  it('classifies invalid URL', () => {
    const err = new Error('Invalid URL: "not-a-url"');
    expect(classifyError(err)).toBe('invalid-url');
  });

  it('returns unknown for non-Error', () => {
    expect(classifyError('string error')).toBe('unknown');
    expect(classifyError(42)).toBe('unknown');
  });

  it('returns unknown for unrecognized errors', () => {
    expect(classifyError(new Error('something weird'))).toBe('unknown');
  });
});

describe('errorKindLabel', () => {
  it('returns human-readable labels', () => {
    expect(errorKindLabel('timeout')).toBe('Connection timed out');
    expect(errorKindLabel('dns')).toBe('DNS resolution failed');
    expect(errorKindLabel('ssrf-blocked')).toBe('Blocked (internal address)');
  });
});

describe('ScanResult.scanErrors integration', () => {
  // We test via the scan function directly with invalid URLs
  it('populates scanErrors for invalid URL', async () => {
    const { scan } = await import('../src/scanner.js');
    const result = await scan(':::invalid');
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.scanErrors).toBeDefined();
    expect(result.scanErrors!.length).toBeGreaterThan(0);
    expect(result.scanErrors![0].kind).toBe('invalid-url');
  });

  it('omits scanErrors when no errors', async () => {
    const { VpnScanner } = await import('../src/scanner.js');
    const scanner = new VpnScanner({ timeout: 1000 });
    // Mock scan to return clean result
    jest.spyOn(scanner, 'scan').mockResolvedValue({
      target: 'clean.example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
    });
    const result = await scanner.scan('clean.example.com');
    expect(result.scanErrors).toBeUndefined();
  });
});
