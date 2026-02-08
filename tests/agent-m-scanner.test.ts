/**
 * Agent M: scanner improvements
 * - #2: scanMultiple retry only on transient errors
 * - #3: testPattern exception collection
 * - #4: SSRF-blocked deduplication
 */

import { VpnScanner } from '../src/scanner.js';
import * as httpClient from '../src/http-client.js';
import { testPattern } from '../src/detector.js';
import type { ScanResult, ScanError } from '../src/types.js';

// Helper to create a scanner with short timeout
function makeScanner(opts = {}) {
  return new VpnScanner({ timeout: 1000, ports: [443], ...opts });
}

describe('#2 scanMultiple retry conditions', () => {
  it('does NOT retry ssrf-blocked errors', async () => {
    const scanner = makeScanner({ maxRetries: 2 });
    let scanCount = 0;
    const ssrfResult: ScanResult = {
      target: 'https://192.168.1.1',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: ['SSRF blocked'],
      scanErrors: [{ kind: 'ssrf-blocked', message: 'SSRF blocked', url: 'https://192.168.1.1' }],
    };
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      return { ...ssrfResult };
    });

    const results = await scanner.scanMultiple(['https://192.168.1.1']);
    expect(scanCount).toBe(1); // No retries for permanent error
    expect(results[0].scanErrors![0].kind).toBe('ssrf-blocked');
  });

  it('does NOT retry invalid-url errors', async () => {
    const scanner = makeScanner({ maxRetries: 2 });
    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      return {
        target: ':::bad',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: ['Invalid URL'],
        scanErrors: [{ kind: 'invalid-url', message: 'Invalid URL' }],
      };
    });

    await scanner.scanMultiple([':::bad']);
    expect(scanCount).toBe(1);
  });

  it('does NOT retry http-status errors', async () => {
    const scanner = makeScanner({ maxRetries: 2 });
    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      return {
        target: 'https://example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: ['HTTP 403'],
        scanErrors: [{ kind: 'http-status', message: 'HTTP 403', statusCode: 403 }],
      };
    });

    await scanner.scanMultiple(['https://example.com']);
    expect(scanCount).toBe(1);
  });

  it('retries timeout errors up to maxRetries', async () => {
    const scanner = makeScanner({ maxRetries: 2 });
    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      return {
        target: 'https://slow.example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: ['Timeout'],
        scanErrors: [{ kind: 'timeout', message: 'Timeout' }],
      };
    });

    await scanner.scanMultiple(['https://slow.example.com']);
    expect(scanCount).toBe(3); // 1 initial + 2 retries
  });

  it('retries dns errors', async () => {
    const scanner = makeScanner({ maxRetries: 1 });
    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      return {
        target: 'https://flaky.example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: ['DNS failed'],
        scanErrors: [{ kind: 'dns', message: 'DNS failed' }],
      };
    });

    await scanner.scanMultiple(['https://flaky.example.com']);
    expect(scanCount).toBe(2); // 1 initial + 1 retry
  });

  it('stops retrying on success', async () => {
    const scanner = makeScanner({ maxRetries: 3 });
    let scanCount = 0;
    jest.spyOn(scanner, 'scan').mockImplementation(async () => {
      scanCount++;
      if (scanCount < 2) {
        return {
          target: 'https://example.com',
          timestamp: new Date().toISOString(),
          vulnerabilities: [],
          errors: ['Timeout'],
          scanErrors: [{ kind: 'timeout', message: 'Timeout' }],
        };
      }
      return {
        target: 'https://example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        device: { vendor: 'fortinet', product: 'FortiGate', confidence: 80, detectionMethod: ['endpoint'], endpoints: [] },
      };
    });

    const results = await scanner.scanMultiple(['https://example.com']);
    expect(scanCount).toBe(2);
    expect(results[0].device).toBeDefined();
  });
});

describe('#3 testPattern exception collection', () => {
  afterEach(() => jest.restoreAllMocks());

  const defaultHttpOpts: httpClient.HttpClientOptions = {
    timeout: 100,
    userAgent: 'test',
    headers: {},
    followRedirects: true,
    allowCrossHostRedirects: false,
  };

  it('collects pattern-error in scanErrors', async () => {
    const scanResult: ScanResult = {
      target: 'https://example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanErrors: [],
    };

    // Mock httpRequest to throw
    jest.spyOn(httpClient, 'httpRequest').mockRejectedValue(new Error('test network error'));

    const result = await testPattern('https://example.com', {
      type: 'endpoint',
      path: '/test',
      match: /test/,
      weight: 5,
    }, defaultHttpOpts, false, scanResult);

    expect(result.success).toBe(false);
    expect(scanResult.scanErrors!.length).toBe(1);
    expect(scanResult.scanErrors![0].kind).toBe('pattern-error');
    expect(scanResult.scanErrors![0].message).toBe('test network error');
    expect(scanResult.scanErrors![0].url).toBe('https://example.com/test');
  });

  it('deduplicates identical pattern-error entries', async () => {
    const scanResult: ScanResult = {
      target: 'https://example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanErrors: [],
    };

    jest.spyOn(httpClient, 'httpRequest').mockRejectedValue(new Error('same error'));
    const pattern = { type: 'endpoint' as const, path: '/test', match: /x/, weight: 5 };

    await testPattern('https://example.com', pattern, defaultHttpOpts, false, scanResult);
    await testPattern('https://example.com', pattern, defaultHttpOpts, false, scanResult);

    const patternErrors = scanResult.scanErrors!.filter(e => e.kind === 'pattern-error');
    expect(patternErrors.length).toBe(1);
  });
});

describe('#4 SSRF-blocked deduplication', () => {
  it('produces only one ssrf-blocked error for multiple ports', async () => {
    // 192.168.1.1 is a private IP, should be blocked by SSRF check
    const scanner = makeScanner({ ports: [443, 8443, 10443], timeout: 1000 });
    const result = await scanner.scan('https://192.168.1.1');

    const ssrfErrors = result.scanErrors?.filter(e => e.kind === 'ssrf-blocked') ?? [];
    expect(ssrfErrors.length).toBe(1);
    expect(result.errors.filter(e => e.includes('SSRF blocked')).length).toBe(1);
  });

  it('produces only one ssrf-blocked error for 127.0.0.1 with multiple ports', async () => {
    const scanner = makeScanner({ ports: [443, 8443, 10443, 4433], timeout: 1000 });
    const result = await scanner.scan('https://127.0.0.1');

    const ssrfErrors = result.scanErrors?.filter(e => e.kind === 'ssrf-blocked') ?? [];
    expect(ssrfErrors.length).toBe(1);
  });
});
