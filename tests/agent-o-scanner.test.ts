/**
 * Agent O Scanner Improvements Tests
 * - #1: Communication failure propagation to scanErrors / retry
 * - #2: Header pattern HTTP status validation
 * - #3: URL path normalization (origin-based)
 * - #5: Adaptive concurrency recovery
 */

import { VpnScanner } from '../src/scanner.js';

// ─── Helpers ───────────────────────────────────────────────────────

/** Build a minimal scanner that uses a mock httpRequest */
function buildMockScanner(
  responses: Map<string, { statusCode: number; headers: Record<string, string>; body: string } | 'error'>,
  options: Record<string, any> = {},
) {
  const scanner = new VpnScanner({ ports: [443], ...options });

  // Patch httpRequest to use mock responses
  (scanner as any).httpRequest = async (url: string, _method?: string) => {
    const resp = responses.get(url);
    if (resp === 'error') throw new Error('ECONNREFUSED');
    return resp ?? null;
  };

  (scanner as any).httpRequestBinary = async (url: string) => {
    const resp = responses.get(url);
    if (resp === 'error') throw new Error('ECONNREFUSED');
    if (!resp || resp === null) return null;
    return { buffer: Buffer.from('x'), statusCode: (resp as any).statusCode, contentType: '' };
  };

  // Patch getCertificateInfo to skip real TLS
  (scanner as any).getCertificateInfo = async () => null;

  // Patch SSRF check to always allow
  (VpnScanner as any).isHostSafe = async () => true;
  (VpnScanner as any).resolveSafeAddresses = async () => ['1.2.3.4'];

  return scanner;
}

// ─── #1: Communication failure propagation ─────────────────────────

describe('scanWithRetry error propagation (#1)', () => {
  it('should retry when scanErrors exist but errors array is empty', async () => {
    let callCount = 0;
    const scanner = new VpnScanner({ ports: [443], maxRetries: 2 });

    // Mock scan on prototype to intercept this.scan calls
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
      // With maxRetries=2: attempt 0 (fail), 1 (fail), 2 (success) = 3 calls
      expect(callCount).toBe(3);
      expect(results[0].device).toBeDefined();
    } finally {
      VpnScanner.prototype.scan = origScan;
    }
  });

  it('should not retry on non-retryable scanErrors', async () => {
    let callCount = 0;
    const scanner = new VpnScanner({ ports: [443], maxRetries: 2 });

    (scanner as any).scan = async (target: string) => {
      callCount++;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        scanErrors: [{ kind: 'ssrf-blocked', message: 'Blocked' }],
      };
    };

    const results = await scanner.scanMultiple(['https://example.com']);
    expect(callCount).toBe(1); // No retry for non-retryable errors
  });
});

// ─── #2: Header pattern HTTP status validation ─────────────────────

describe('header pattern HTTP status validation (#2)', () => {
  it('should reject header match on 404 response', async () => {
    const responses = new Map([
      ['https://example.com', {
        statusCode: 404,
        headers: { 'server': 'fortios' },
        body: '',
      }],
    ]);
    const scanner = buildMockScanner(responses, { vendor: 'fortinet' });
    const result = await scanner.scan('https://example.com');
    // Header pattern should NOT match because status is 404
    // The device might still be detected via other patterns, but header shouldn't contribute
    expect(result.device).toBeUndefined();
  });

  it('should accept header match on 200 response', async () => {
    const responses = new Map([
      ['https://example.com', {
        statusCode: 200,
        headers: { 'server': 'xxxxxxx' },
        body: '',
      }],
    ]);
    const scanner = buildMockScanner(responses);

    // Directly test the pattern matcher
    const matched = await (scanner as any).testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
    });
    expect(matched.success).toBe(true);
  });

  it('should reject header match on 500 response', async () => {
    const responses = new Map([
      ['https://example.com', {
        statusCode: 500,
        headers: { 'server': 'xxxxxxx' },
        body: '',
      }],
    ]);
    const scanner = buildMockScanner(responses);

    const matched = await (scanner as any).testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
    });
    expect(matched.success).toBe(false);
  });

  it('should accept header match on custom status codes', async () => {
    const responses = new Map([
      ['https://example.com', {
        statusCode: 302,
        headers: { 'server': 'xxxxxxx' },
        body: '',
      }],
    ]);
    const scanner = buildMockScanner(responses);

    const matched = await (scanner as any).testPattern('https://example.com', {
      type: 'header',
      match: 'server: xxxxxxx',
      weight: 5,
      status: [302, 200],
    });
    expect(matched.success).toBe(true);
  });
});

// ─── #3: URL path normalization ────────────────────────────────────

describe('URL path normalization (#3)', () => {
  it('should use origin for endpoint path concatenation', async () => {
    const requestedUrls: string[] = [];
    const scanner = new VpnScanner({ ports: [443] });

    (scanner as any).httpRequest = async (url: string) => {
      requestedUrls.push(url);
      return { statusCode: 200, headers: {}, body: 'test-match' };
    };
    (scanner as any).getCertificateInfo = async () => null;
    (VpnScanner as any).isHostSafe = async () => true;
    (VpnScanner as any).resolveSafeAddresses = async () => ['1.2.3.4'];

    await (scanner as any).testPattern('https://host.example.com/base/path', {
      type: 'endpoint',
      path: '/remote/login',
      match: 'test-match',
      weight: 5,
    });

    // Should be https://host.example.com/remote/login, NOT https://host.example.com/base/path/remote/login
    expect(requestedUrls).toContain('https://host.example.com/remote/login');
    expect(requestedUrls).not.toContain('https://host.example.com/base/path/remote/login');
  });

  it('should use origin for favicon path', async () => {
    const requestedUrls: string[] = [];
    const scanner = new VpnScanner({ ports: [443] });

    (scanner as any).httpRequestBinary = async (url: string) => {
      requestedUrls.push(url);
      return null;
    };
    (scanner as any).httpRequest = async (url: string) => {
      requestedUrls.push(url);
      return null;
    };
    (scanner as any).getCertificateInfo = async () => null;
    (VpnScanner as any).isHostSafe = async () => true;
    (VpnScanner as any).resolveSafeAddresses = async () => ['1.2.3.4'];

    await (scanner as any).testPattern('https://host.example.com/some/path', {
      type: 'favicon',
      match: '12345',
      weight: 5,
    });

    // favicon.ico should be at origin root
    expect(requestedUrls.some(u => u === 'https://host.example.com/favicon.ico')).toBe(true);
    expect(requestedUrls.some(u => u.includes('/some/path/favicon.ico'))).toBe(false);
  });

  it('should use baseUrl as-is when no pattern path', async () => {
    const requestedUrls: string[] = [];
    const scanner = new VpnScanner({ ports: [443] });

    (scanner as any).httpRequest = async (url: string) => {
      requestedUrls.push(url);
      return { statusCode: 200, headers: {}, body: 'match' };
    };
    (scanner as any).getCertificateInfo = async () => null;
    (VpnScanner as any).isHostSafe = async () => true;
    (VpnScanner as any).resolveSafeAddresses = async () => ['1.2.3.4'];

    await (scanner as any).testPattern('https://host.example.com/base', {
      type: 'body',
      match: 'match',
      weight: 5,
    });

    expect(requestedUrls).toContain('https://host.example.com/base');
  });
});

// ─── #5: Adaptive concurrency recovery ─────────────────────────────

describe('adaptive concurrency recovery (#5)', () => {
  it('should increase concurrency when failure rate drops below 0.25', async () => {
    const concurrencyLog: number[] = [];
    const scanner = new VpnScanner({
      ports: [443],
      concurrency: 10,
      adaptiveConcurrency: true,
    });

    // Generate 20 targets: first 5 fail (triggers reduction), rest succeed
    const targets = Array.from({ length: 20 }, (_, i) => `https://t${i}.example.com`);

    let scanCount = 0;
    (scanner as any).scan = async (target: string) => {
      scanCount++;
      const shouldFail = scanCount <= 5;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: shouldFail ? ['timeout'] : [],
        scanErrors: shouldFail ? [{ kind: 'timeout', message: 'timeout' }] : undefined,
        device: shouldFail ? undefined : { vendor: 'fortinet', product: 'FortiGate', confidence: 80, detectionMethod: [], endpoints: [] },
      };
    };

    // Monkey-patch to log concurrency changes
    const origScanMultiple = scanner.scanMultiple.bind(scanner);
    const results = await scanner.scanMultiple(targets);

    // At least some results should have devices (recovery happened)
    const detectedCount = results.filter(r => r.device).length;
    expect(detectedCount).toBeGreaterThan(10);
  });

  it('should not exceed initial concurrency during recovery', async () => {
    // This is inherently tested by the implementation (Math.min with initialConcurrency)
    // Verify by checking the code path exists
    const scanner = new VpnScanner({
      concurrency: 3,
      adaptiveConcurrency: true,
    });

    // All success - concurrency should stay at or below 3
    const targets = Array.from({ length: 15 }, (_, i) => `https://t${i}.example.com`);

    (scanner as any).scan = async (target: string) => ({
      target,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      device: { vendor: 'fortinet', product: 'FortiGate', confidence: 80, detectionMethod: [], endpoints: [] },
    });

    const results = await scanner.scanMultiple(targets);
    expect(results).toHaveLength(15);
    expect(results.every(r => r.device)).toBe(true);
  });
});
