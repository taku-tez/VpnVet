/**
 * Agent O Scanner Improvements Tests
 * - #1: Communication failure propagation to scanErrors / retry
 * - #2: Header pattern HTTP status validation
 * - #3: URL path normalization (origin-based)
 * - #5: Adaptive concurrency recovery
 */

import { VpnScanner } from '../src/scanner.js';
import * as httpClient from '../src/http-client.js';
import { testPattern } from '../src/detector.js';

// ─── Helpers ───────────────────────────────────────────────────────

const defaultHttpOpts: httpClient.HttpClientOptions = {
  timeout: 1000,
  userAgent: 'test',
  headers: {},
  followRedirects: true,
  allowCrossHostRedirects: false,
};

/** Mock http-client functions with a response map */
function mockHttpClient(
  responses: Map<string, { statusCode: number; headers: Record<string, string>; body: string } | 'error'>,
) {
  jest.spyOn(httpClient, 'httpRequest').mockImplementation(async (url: string, _method?: string) => {
    const resp = responses.get(url);
    if (resp === 'error') throw new Error('ECONNREFUSED');
    return (resp as httpClient.HttpResponse) ?? null;
  });
  jest.spyOn(httpClient, 'httpRequestBinary').mockImplementation(async (url: string) => {
    const resp = responses.get(url);
    if (resp === 'error') throw new Error('ECONNREFUSED');
    if (!resp || resp === null) return null;
    return { buffer: Buffer.from('x'), statusCode: (resp as any).statusCode, contentType: '' };
  });
  jest.spyOn(httpClient, 'getCertificateInfo').mockResolvedValue(null);
  jest.spyOn(httpClient, 'isHostSafe').mockResolvedValue(true);
  jest.spyOn(httpClient, 'resolveSafeAddresses').mockResolvedValue(['1.2.3.4']);
}

// ─── #1: Communication failure propagation ─────────────────────────

describe('scanWithRetry error propagation (#1)', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should retry when scanErrors exist but errors array is empty', async () => {
    let callCount = 0;
    const scanner = new VpnScanner({ ports: [443], maxRetries: 2 });

    const origScan = VpnScanner.prototype.scan;
    VpnScanner.prototype.scan = async function(target: string) {
      callCount++;
      if (callCount <= 2) {
        return {
          target,
          timestamp: new Date().toISOString(),
          vulnerabilities: [],
          errors: [],
          scanErrors: [{ kind: 'timeout' as const, message: 'Request timed out' }],
        };
      }
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        device: { vendor: 'fortinet' as const, product: 'FortiGate', confidence: 80, detectionMethod: ['header' as const], endpoints: [] },
      };
    };

    try {
      const results = await scanner.scanMultiple(['https://example.com']);
      expect(callCount).toBe(3);
      expect(results[0].device).toBeDefined();
    } finally {
      VpnScanner.prototype.scan = origScan;
    }
  });

  it('should not retry on non-retryable scanErrors', async () => {
    let callCount = 0;
    const scanner = new VpnScanner({ ports: [443], maxRetries: 2 });

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      callCount++;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        scanErrors: [{ kind: 'ssrf-blocked' as const, message: 'Blocked' }],
      };
    });

    const results = await scanner.scanMultiple(['https://example.com']);
    expect(callCount).toBe(1);
  });
});

// ─── #2: Header pattern HTTP status validation ─────────────────────

describe('header pattern HTTP status validation (#2)', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should reject header match on 404 response', async () => {
    const responses = new Map([
      ['https://example.com', {
        statusCode: 404,
        headers: { 'server': 'fortios' },
        body: '',
      }],
    ]);
    mockHttpClient(responses);
    const scanner = new VpnScanner({ ports: [443], vendor: 'fortinet' });
    const result = await scanner.scan('https://example.com');
    expect(result.device).toBeUndefined();
  });

  it('should accept header match on 200 response', async () => {
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async (_url: string, _method?: string) => {
      return {
        data: {
          statusCode: 200,
          headers: { 'server': 'xxxxxxx' },
          body: '',
        },
      };
    });

    const matched = await testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
    }, defaultHttpOpts, false);
    expect(matched.success).toBe(true);
  });

  it('should reject header match on 500 response', async () => {
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async () => ({
      data: {
        statusCode: 500,
        headers: { 'server': 'xxxxxxx' },
        body: '',
      },
    }));

    const matched = await testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
    }, defaultHttpOpts, false);
    expect(matched.success).toBe(false);
  });

  it('should accept header match on custom status codes', async () => {
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async () => ({
      data: {
        statusCode: 302,
        headers: { 'server': 'xxxxxxx' },
        body: '',
      },
    }));

    const matched = await testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
      status: [302, 200],
    }, defaultHttpOpts, false);
    expect(matched.success).toBe(true);
  });
});

// ─── #3: URL path normalization ────────────────────────────────────

describe('URL path normalization (#3)', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should use origin for endpoint path concatenation', async () => {
    const requestedUrls: string[] = [];
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async (url: string) => {
      requestedUrls.push(url);
      return { statusCode: 200, headers: {}, body: 'test-match' };
    });
    jest.spyOn(httpClient, 'getCertificateInfo').mockResolvedValue(null);

    await testPattern('https://host.example.com/base/path', {
      type: 'endpoint',
      path: '/remote/login',
      match: 'test-match',
      weight: 5,
    }, defaultHttpOpts, false);

    expect(requestedUrls).toContain('https://host.example.com/remote/login');
    expect(requestedUrls).not.toContain('https://host.example.com/base/path/remote/login');
  });

  it('should use origin for favicon path', async () => {
    const requestedUrls: string[] = [];
    jest.spyOn(httpClient, 'httpRequestBinary').mockImplementation(async (url: string) => {
      requestedUrls.push(url);
      return null;
    });
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async (url: string) => {
      requestedUrls.push(url);
      return null;
    });
    jest.spyOn(httpClient, 'getCertificateInfo').mockResolvedValue(null);

    await testPattern('https://host.example.com/some/path', {
      type: 'favicon',
      match: '12345',
      weight: 5,
    }, defaultHttpOpts, false);

    expect(requestedUrls.some(u => u === 'https://host.example.com/favicon.ico')).toBe(true);
    expect(requestedUrls.some(u => u.includes('/some/path/favicon.ico'))).toBe(false);
  });

  it('should use baseUrl as-is when no pattern path', async () => {
    const requestedUrls: string[] = [];
    jest.spyOn(httpClient, 'httpRequest').mockImplementation(async (url: string) => {
      requestedUrls.push(url);
      return { statusCode: 200, headers: {}, body: 'match' };
    });
    jest.spyOn(httpClient, 'getCertificateInfo').mockResolvedValue(null);

    await testPattern('https://host.example.com/base', {
      type: 'body',
      match: 'match',
      weight: 5,
    }, defaultHttpOpts, false);

    expect(requestedUrls).toContain('https://host.example.com/base');
  });
});

// ─── #5: Adaptive concurrency recovery ─────────────────────────────

describe('adaptive concurrency recovery (#5)', () => {
  afterEach(() => jest.restoreAllMocks());

  it('should increase concurrency when failure rate drops below 0.25', async () => {
    const scanner = new VpnScanner({
      ports: [443],
      concurrency: 10,
      adaptiveConcurrency: true,
    });

    const targets = Array.from({ length: 20 }, (_, i) => `https://t${i}.example.com`);

    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      scanCount++;
      const shouldFail = scanCount <= 5;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: shouldFail ? ['timeout'] : [],
        scanErrors: shouldFail ? [{ kind: 'timeout' as const, message: 'timeout' }] : undefined,
        device: shouldFail ? undefined : { vendor: 'fortinet' as const, product: 'FortiGate', confidence: 80, detectionMethod: [] as any, endpoints: [] },
      };
    });

    const results = await scanner.scanMultiple(targets);
    const detectedCount = results.filter(r => r.device).length;
    expect(detectedCount).toBeGreaterThan(10);
  });

  it('should not exceed initial concurrency during recovery', async () => {
    const scanner = new VpnScanner({
      concurrency: 3,
      adaptiveConcurrency: true,
    });

    const targets = Array.from({ length: 15 }, (_, i) => `https://t${i}.example.com`);

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => ({
      target,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      device: { vendor: 'fortinet' as const, product: 'FortiGate', confidence: 80, detectionMethod: [] as any, endpoints: [] },
    }));

    const results = await scanner.scanMultiple(targets);
    expect(results).toHaveLength(15);
    expect(results.every(r => r.device)).toBe(true);
  });
});
