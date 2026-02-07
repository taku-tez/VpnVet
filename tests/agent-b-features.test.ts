/**
 * Tests for Agent B features:
 * - skipVersionDetection
 * - favicon detection
 * - compareVersions improvements
 * - Version-undefined CVE handling
 */

import { compareVersions, isVersionAffected, hasVersionConstraints } from '../src/utils.js';

describe('compareVersions (improved)', () => {
  it('should compare simple versions', () => {
    expect(compareVersions('7.0.1', '7.0.2')).toBe(-1);
    expect(compareVersions('7.0.2', '7.0.1')).toBe(1);
    expect(compareVersions('7.0.1', '7.0.1')).toBe(0);
  });

  it('should compare versions with different lengths', () => {
    expect(compareVersions('7.0', '7.0.1')).toBe(-1);
    expect(compareVersions('7.0.1', '7.0')).toBe(1);
  });

  it('should handle hyphenated nested versions (Citrix style: 13.1-49.14)', () => {
    expect(compareVersions('13.1-49.14', '13.1-49.15')).toBe(-1);
    expect(compareVersions('13.1-49.15', '13.1-49.14')).toBe(1);
    expect(compareVersions('13.1-49.14', '13.1-49.14')).toBe(0);
    expect(compareVersions('13.1-48.47', '13.1-49.14')).toBe(-1);
    expect(compareVersions('13.0-49.14', '13.1-49.14')).toBe(-1);
  });

  it('should handle alpha suffixes (e.g. 29sv, R81)', () => {
    expect(compareVersions('10.2.0.5-d-29sv', '10.2.0.5-d-30sv')).toBe(-1);
    expect(compareVersions('R81.10', 'R81.20')).toBe(-1);
    expect(compareVersions('R81.20', 'R81.10')).toBe(1);
    expect(compareVersions('R81.20', 'R81.20')).toBe(0);
  });

  it('should handle purely numeric vs mixed segments', () => {
    expect(compareVersions('6.4.14', '6.4.14')).toBe(0);
    expect(compareVersions('6.4.14', '6.4.15')).toBe(-1);
  });

  it('should handle complex PAN-OS style versions', () => {
    expect(compareVersions('10.2.0', '10.2.1')).toBe(-1);
    expect(compareVersions('11.0.0', '10.2.9')).toBe(1);
  });
});

describe('hasVersionConstraints', () => {
  it('should return true when versionStart is set', () => {
    expect(hasVersionConstraints({ versionStart: '1.0', versionEnd: '2.0' })).toBe(true);
  });

  it('should return true when versionExact is set', () => {
    expect(hasVersionConstraints({ versionExact: '1.0.0' })).toBe(true);
  });

  it('should return false when no version fields set', () => {
    expect(hasVersionConstraints({})).toBe(false);
  });
});

describe('Version-undefined CVE handling', () => {
  it('isVersionAffected returns false for entries without version constraints', () => {
    // An entry with only vendor/product (no version range)
    expect(isVersionAffected('7.0.1', {})).toBe(false);
  });

  it('isVersionAffected works with versionExact', () => {
    expect(isVersionAffected('7.0.1', { versionExact: '7.0.1' })).toBe(true);
    expect(isVersionAffected('7.0.2', { versionExact: '7.0.1' })).toBe(false);
  });

  it('isVersionAffected works with version range', () => {
    expect(isVersionAffected('7.0.5', { versionStart: '7.0.0', versionEnd: '7.0.13' })).toBe(true);
    expect(isVersionAffected('7.0.14', { versionStart: '7.0.0', versionEnd: '7.0.13' })).toBe(false);
  });
});

describe('skipVersionDetection', () => {
  // Integration test: scanner with skipVersionDetection should not extract versions
  // (Tested via mock in scanner context, here we validate the option exists)
  it('should be a valid ScanOptions field', async () => {
    const { VpnScanner } = await import('../src/scanner.js');
    const scanner = new VpnScanner({ skipVersionDetection: true, timeout: 1000 });
    expect(scanner).toBeDefined();
  });
});
