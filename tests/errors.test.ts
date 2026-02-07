/**
 * Error Handling Tests
 *
 * Tests scanner behavior under various error conditions.
 * Uses mocks for network-dependent scenarios so tests run without real connections.
 *
 * NOTE: Constructor defaults, options merging, scanMultiple basics, and result
 * structure tests live in scanner.test.ts — only error-specific cases here.
 */

import { VpnScanner } from '../src/scanner.js';

/**
 * Helper: mock all network I/O on a VpnScanner instance so scan() never
 * touches the network.  `httpRequestImpl` controls what httpRequest returns.
 */
function mockNetwork(
  scanner: VpnScanner,
  httpRequestImpl: (...args: any[]) => any = () => Promise.resolve(null),
) {
  jest.spyOn(scanner as any, 'httpRequest').mockImplementation(httpRequestImpl);
  jest.spyOn(scanner as any, 'httpRequestBinary').mockResolvedValue(null);
  jest.spyOn(scanner as any, 'getCertificateInfo').mockResolvedValue(null);
}

describe('Error Handling', () => {
  afterEach(() => jest.restoreAllMocks());

  describe('Invalid targets', () => {
    it('should handle empty target gracefully', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      const result = await scanner.scan('');
      expect(result).toBeDefined();
      expect(result.target).toBe('');
      expect(result.device).toBeUndefined();
    });

    it('should handle malformed URL gracefully', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      const result = await scanner.scan('not-a-valid-url-!@#$%');
      expect(result).toBeDefined();
      expect(result.device).toBeUndefined();
    });
  });

  describe('Network errors (mocked)', () => {
    it('should handle connection refused', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      mockNetwork(scanner, () =>
        Promise.reject(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })),
      );

      const result = await scanner.scan('127.0.0.1:59999');
      expect(result).toBeDefined();
      expect(result.device).toBeUndefined();
    });

    it('should handle DNS resolution failure', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      mockNetwork(scanner, () =>
        Promise.reject(Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' })),
      );

      const result = await scanner.scan('no-such-host.invalid');
      expect(result).toBeDefined();
      expect(result.device).toBeUndefined();
    });

    it('should handle socket timeout', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      mockNetwork(scanner, () =>
        Promise.reject(Object.assign(new Error('socket hang up'), { code: 'ETIMEDOUT' })),
      );

      const result = await scanner.scan('10.255.255.1');
      expect(result).toBeDefined();
      expect(result.device).toBeUndefined();
    });

    it('should handle unreachable host (null response)', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      mockNetwork(scanner); // default returns null

      const result = await scanner.scan('192.0.2.1');
      expect(result).toBeDefined();
      expect(result.device).toBeUndefined();
    });
  });

  describe('Timeout defaults', () => {
    it('should use default timeout of 10000ms if not specified', () => {
      const scanner = new VpnScanner();
      const options = (scanner as any).options;
      expect(options.timeout).toBe(10000);
    });
  });

  describe('Multiple targets error handling', () => {
    it('should handle empty targets array', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      const results = await scanner.scanMultiple([]);
      expect(results).toEqual([]);
    });

    it('should handle multiple failing targets via mock', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      mockNetwork(scanner);

      const results = await scanner.scanMultiple(['bad1.invalid', 'bad2.invalid']);
      expect(results.length).toBe(2);
      expect(results[0].device).toBeUndefined();
      expect(results[1].device).toBeUndefined();
    });
  });
});
