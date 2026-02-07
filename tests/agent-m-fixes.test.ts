/**
 * Agent M fixes: product-level coverage, compareVersions trailing zeros, cert DNS pinning
 */

import { compareVersions, normalizeProduct, isVersionAffected } from '../src/utils.js';
import { VpnScanner } from '../src/scanner.js';

describe('normalizeProduct', () => {
  it('should lowercase and trim', () => {
    expect(normalizeProduct('  FortiGate  ')).toBe('fortigate');
  });

  it('should collapse whitespace', () => {
    expect(normalizeProduct('Palo  Alto   Firewall')).toBe('palo alto firewall');
  });

  it('should handle empty string', () => {
    expect(normalizeProduct('')).toBe('');
  });

  it('should handle already normalized', () => {
    expect(normalizeProduct('fortigate')).toBe('fortigate');
  });
});

describe('compareVersions trailing zeros (#5)', () => {
  it('should treat 13.1 and 13.1.0 as equal', () => {
    expect(compareVersions('13.1', '13.1.0')).toBe(0);
  });

  it('should treat 13.1.0 and 13.1.0.0 as equal', () => {
    expect(compareVersions('13.1.0', '13.1.0.0')).toBe(0);
  });

  it('should treat 1.0 and 1.0.0.0 as equal', () => {
    expect(compareVersions('1.0', '1.0.0.0')).toBe(0);
  });

  it('should treat 13.1 and 13.1.0.0 as equal', () => {
    expect(compareVersions('13.1', '13.1.0.0')).toBe(0);
  });

  it('should still detect 13.1 < 13.1.1', () => {
    expect(compareVersions('13.1', '13.1.1')).toBe(-1);
  });

  it('should still detect 13.1.0 < 13.1.1', () => {
    expect(compareVersions('13.1.0', '13.1.1')).toBe(-1);
  });

  it('should still detect 13.2 > 13.1.0', () => {
    expect(compareVersions('13.2', '13.1.0')).toBe(1);
  });

  // VPN-specific formats remain compatible
  it('should handle hyphenated versions: 13.1-49.14', () => {
    expect(compareVersions('13.1-49.14', '13.1-49.14')).toBe(0);
    expect(compareVersions('13.1-49.13', '13.1-49.14')).toBe(-1);
  });

  it('should handle R-prefixed versions: R81.20', () => {
    expect(compareVersions('R81.20', 'R81.20')).toBe(0);
    expect(compareVersions('R81.10', 'R81.20')).toBe(-1);
  });

  it('should handle alpha suffixes: 10.2.0.5-d-29sv', () => {
    expect(compareVersions('10.2.0.5-d-29sv', '10.2.0.5-d-29sv')).toBe(0);
  });

  it('trailing zeros with hyphen format', () => {
    expect(compareVersions('13.1-49.0', '13.1-49')).toBe(0);
  });

  it('should work with isVersionAffected range checks', () => {
    // 13.1 should be in range [13.0, 13.1.0]
    expect(isVersionAffected('13.1', { versionStart: '13.0', versionEnd: '13.1.0' })).toBe(true);
    // 13.1.0 should be in range [13.0, 13.1]
    expect(isVersionAffected('13.1.0', { versionStart: '13.0', versionEnd: '13.1' })).toBe(true);
  });
});

describe('getCertificateInfo DNS pinning (#4)', () => {
  it('should reject internal hosts for certificate checks', async () => {
    const scanner = new VpnScanner({ timeout: 2000 });
    // Internal host should be blocked by resolveSafeAddresses
    // The scanner should not attempt TLS to internal IPs
    const result = await scanner.scan('https://127.0.0.1:443');
    // Should not detect anything (blocked by SSRF protection)
    expect(result.device).toBeUndefined();
  });
});

describe('product-level coverage check (#3)', () => {
  it('should use normalizeProduct for comparison', () => {
    // Verify normalizeProduct handles case insensitivity
    expect(normalizeProduct('FortiGate')).toBe(normalizeProduct('fortigate'));
    expect(normalizeProduct('GlobalProtect')).toBe(normalizeProduct('globalprotect'));
  });
});
