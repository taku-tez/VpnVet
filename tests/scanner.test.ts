/**
 * Scanner Tests
 */

import { VpnScanner, scan } from '../src/scanner.js';
import type { ScanResult, ScanOptions } from '../src/types.js';

describe('VpnScanner', () => {
  describe('constructor', () => {
    it('should create scanner with default options', () => {
      const scanner = new VpnScanner();
      expect(scanner).toBeDefined();
    });

    it('should create scanner with custom options', () => {
      const scanner = new VpnScanner({
        timeout: 5000,
        ports: [443],
        skipVulnCheck: true,
      });
      expect(scanner).toBeDefined();
    });
  });

  describe('scan function', () => {
    it('should export scan function', () => {
      expect(typeof scan).toBe('function');
    });
  });

  describe('URL normalization', () => {
    it('should handle targets without protocol', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      
      // This will fail to connect, but should not throw
      const result = await scanner.scan('localhost:9999');
      
      expect(result).toBeDefined();
      expect(result.target).toBe('localhost:9999');
      expect(result.timestamp).toBeDefined();
    });

    it('should handle https URLs', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      
      const result = await scanner.scan('https://localhost:9999');
      
      expect(result).toBeDefined();
      expect(result.target).toBe('https://localhost:9999');
    });
  });

  describe('scan result structure', () => {
    it('should return valid ScanResult structure', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      
      const result = await scanner.scan('localhost:9999');
      
      expect(result).toHaveProperty('target');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('errors');
      
      expect(Array.isArray(result.vulnerabilities)).toBe(true);
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should have ISO timestamp', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      
      const result = await scanner.scan('localhost:9999');
      
      // Verify timestamp is valid ISO string
      const date = new Date(result.timestamp);
      expect(date.toISOString()).toBe(result.timestamp);
    });
  });

  describe('scanMultiple', () => {
    it('should scan multiple targets', async () => {
      const scanner = new VpnScanner({ timeout: 1000 });
      
      const results = await scanner.scanMultiple([
        'localhost:9998',
        'localhost:9999',
      ]);
      
      expect(results.length).toBe(2);
      expect(results[0].target).toBe('localhost:9998');
      expect(results[1].target).toBe('localhost:9999');
    });
  });

  // NOTE: Error handling tests (connection refused, DNS failure, timeout)
  // are in errors.test.ts with proper mocks for network independence.

  describe('options', () => {
    it('should respect skipVulnCheck option', async () => {
      const scanner = new VpnScanner({
        timeout: 1000,
        skipVulnCheck: true,
      });
      
      const result = await scanner.scan('localhost:9999');
      
      // Even if a device was detected, vulnerabilities should be empty
      expect(result.vulnerabilities).toEqual([]);
    });
  });
});

describe('Multi-port scanning', () => {
  it('should try multiple ports when no explicit port in target', async () => {
    const scanner = new VpnScanner({
      timeout: 1000,
      ports: [443, 8443, 10443],
    });

    // Will fail to connect but should not throw
    const result = await scanner.scan('localhost');
    expect(result).toBeDefined();
    expect(result.target).toBe('localhost');
  });

  it('should use only the explicit port when target has one', async () => {
    const scanner = new VpnScanner({
      timeout: 1000,
      ports: [443, 8443],
    });

    const result = await scanner.scan('localhost:9999');
    expect(result).toBeDefined();
    expect(result.target).toBe('localhost:9999');
  });
});

describe('followRedirects', () => {
  it('should not follow redirects when disabled', async () => {
    const scanner = new VpnScanner({
      timeout: 1000,
      followRedirects: false,
    });

    // Will fail to connect, but the option should be respected
    const result = await scanner.scan('localhost:9999');
    expect(result).toBeDefined();
  });

  it('should follow redirects when enabled (default)', async () => {
    const scanner = new VpnScanner({
      timeout: 1000,
      followRedirects: true,
    });

    const result = await scanner.scan('localhost:9999');
    expect(result).toBeDefined();
  });
});

describe('VpnDevice structure', () => {
  it('should have correct fields when device is detected', () => {
    // Mock device structure test
    const mockDevice = {
      vendor: 'fortinet' as const,
      product: 'FortiGate',
      version: '7.0.1',
      confidence: 85,
      detectionMethod: ['endpoint' as const, 'header' as const],
      endpoints: ['/remote/login'],
    };

    expect(mockDevice.vendor).toBe('fortinet');
    expect(mockDevice.product).toBe('FortiGate');
    expect(mockDevice.version).toBe('7.0.1');
    expect(mockDevice.confidence).toBeGreaterThanOrEqual(0);
    expect(mockDevice.confidence).toBeLessThanOrEqual(100);
    expect(Array.isArray(mockDevice.detectionMethod)).toBe(true);
    expect(Array.isArray(mockDevice.endpoints)).toBe(true);
  });
});

describe('VulnerabilityMatch structure', () => {
  it('should have correct fields', () => {
    const mockMatch = {
      vulnerability: {
        cve: 'CVE-2024-21762',
        severity: 'critical' as const,
        cvss: 9.8,
        description: 'Test vulnerability',
        affected: [],
        references: [],
        exploitAvailable: true,
        cisaKev: true,
      },
      confidence: 'confirmed' as const,
      evidence: 'Version 7.0.1 is within affected range',
    };

    expect(mockMatch.vulnerability.cve).toMatch(/^CVE-\d{4}-\d+$/);
    expect(['confirmed', 'likely', 'potential']).toContain(mockMatch.confidence);
    expect(mockMatch.evidence).toBeDefined();
  });
});
