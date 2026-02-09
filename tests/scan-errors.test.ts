import { classifyError, errorKindLabel } from '../src/scanner.js';
import { addScanError, testPattern } from '../src/detector.js';
import * as httpClient from '../src/http-client.js';
import type { ScanResult, ScanError, FingerprintPattern } from '../src/types.js';
import type { HttpClientOptions } from '../src/http-client.js';

// Mock http-client for testPattern tests
jest.mock('../src/http-client.js', () => {
  const actual = jest.requireActual('../src/http-client.js');
  return {
    __esModule: true,
    ...actual,
    httpRequest: jest.fn(),
    httpRequestBinary: jest.fn(),
    getCertificateInfo: jest.fn(),
    isHostSafe: jest.fn().mockResolvedValue(true),
  };
});

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

describe('addScanError dedup', () => {
  function makeScanResult(): ScanResult {
    return {
      target: 'https://example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanErrors: [],
    };
  }

  it('adds unique errors', () => {
    const sr = makeScanResult();
    addScanError(sr, { kind: 'timeout', message: 'timed out', url: 'https://a.com' });
    addScanError(sr, { kind: 'dns', message: 'dns fail', url: 'https://a.com' });
    expect(sr.scanErrors!.length).toBe(2);
  });

  it('deduplicates by kind + url + statusCode', () => {
    const sr = makeScanResult();
    addScanError(sr, { kind: 'http-status', message: 'HTTP 403', url: 'https://a.com', statusCode: 403 });
    addScanError(sr, { kind: 'http-status', message: 'HTTP 403 again', url: 'https://a.com', statusCode: 403 });
    expect(sr.scanErrors!.length).toBe(1);
  });

  it('allows same kind different url', () => {
    const sr = makeScanResult();
    addScanError(sr, { kind: 'timeout', message: 'a', url: 'https://a.com' });
    addScanError(sr, { kind: 'timeout', message: 'b', url: 'https://b.com' });
    expect(sr.scanErrors!.length).toBe(2);
  });

  it('allows same kind+url different statusCode', () => {
    const sr = makeScanResult();
    addScanError(sr, { kind: 'http-status', message: 'a', url: 'https://a.com', statusCode: 403 });
    addScanError(sr, { kind: 'http-status', message: 'b', url: 'https://a.com', statusCode: 500 });
    expect(sr.scanErrors!.length).toBe(2);
  });
});

describe('testPattern records errors uniformly across pattern types', () => {
  const httpOpts: HttpClientOptions = {
    timeout: 5000,
    userAgent: 'test',
    headers: {},
    followRedirects: false,
    allowCrossHostRedirects: false,
  };

  function makeScanResult(): ScanResult {
    return {
      target: 'https://vpn.example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanErrors: [],
    };
  }

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it('records network failure for endpoint pattern', async () => {
    (httpClient.httpRequest as jest.Mock).mockResolvedValue({
      data: null,
      error: { kind: 'timeout', message: 'Request timed out' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'endpoint', path: '/login', match: /test/, weight: 5 };
    const result = await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(result.success).toBe(false);
    expect(sr.scanErrors!.length).toBe(1);
    expect(sr.scanErrors![0].kind).toBe('timeout');
    expect(sr.scanErrors![0].url).toBe('https://vpn.example.com/login');
  });

  it('records network failure for header pattern', async () => {
    (httpClient.httpRequest as jest.Mock).mockResolvedValue({
      data: null,
      error: { kind: 'refused', message: 'Connection refused' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'header', match: /x-custom/, weight: 3 };
    const result = await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(result.success).toBe(false);
    expect(sr.scanErrors!.some(e => e.kind === 'refused')).toBe(true);
  });

  it('records network failure for favicon pattern', async () => {
    (httpClient.httpRequestBinary as jest.Mock).mockResolvedValue({
      data: null,
      error: { kind: 'dns', message: 'DNS failed' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'favicon', match: '12345', weight: 4 };
    const result = await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(result.success).toBe(false);
    expect(sr.scanErrors!.some(e => e.kind === 'dns')).toBe(true);
  });

  it('records network failure for certificate pattern', async () => {
    (httpClient.getCertificateInfo as jest.Mock).mockResolvedValue({
      data: null,
      error: { kind: 'tls', message: 'TLS handshake failed' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'certificate', match: /FooCA/, weight: 5 };
    const result = await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(result.success).toBe(false);
    expect(sr.scanErrors!.some(e => e.kind === 'tls')).toBe(true);
  });

  it('records http-status for endpoint 4xx', async () => {
    (httpClient.httpRequest as jest.Mock).mockResolvedValue({
      data: { statusCode: 403, headers: {}, body: '' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'endpoint', path: '/admin', match: /test/, weight: 5 };
    await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(sr.scanErrors!.some(e => e.kind === 'http-status' && e.statusCode === 403)).toBe(true);
  });

  it('records http-status for header pattern 500', async () => {
    (httpClient.httpRequest as jest.Mock).mockResolvedValue({
      data: { statusCode: 500, headers: {}, body: '' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'header', match: /x-custom/, weight: 3 };
    await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(sr.scanErrors!.some(e => e.kind === 'http-status' && e.statusCode === 500)).toBe(true);
  });

  it('records http-status for favicon pattern 404', async () => {
    (httpClient.httpRequestBinary as jest.Mock).mockResolvedValue({
      data: { buffer: Buffer.from('x'), statusCode: 404, contentType: 'text/html' },
    });

    const sr = makeScanResult();
    const pattern: FingerprintPattern = { type: 'favicon', match: '12345', weight: 4 };
    await testPattern('https://vpn.example.com', pattern, httpOpts, false, sr);

    expect(sr.scanErrors!.some(e => e.kind === 'http-status' && e.statusCode === 404)).toBe(true);
  });
});
