/**
 * Version boundary tests for compareVersions and isVersionAffected
 */

import { compareVersions, isVersionAffected } from '../src/utils.js';

describe('compareVersions boundary cases', () => {
  // Basic comparisons
  it.each([
    ['1.0.0', '1.0.0', 0],
    ['1.0.0', '1.0.1', -1],
    ['1.0.1', '1.0.0', 1],
    ['2.0.0', '1.9.9', 1],
  ])('compareVersions(%s, %s) = %i', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
  });

  // Trailing zeros equivalence
  it.each([
    ['13.1', '13.1.0', 0],
    ['13.1.0', '13.1.0.0', 0],
    ['7.0', '7.0.0.0', 0],
  ])('trailing zeros: %s == %s', (a, b) => {
    expect(compareVersions(a, b)).toBe(0);
  });

  // VPN-specific formats
  describe('VPN-specific version formats', () => {
    // Citrix/NetScaler: 13.1-49.14
    it('Citrix hyphenated: 13.1-49.14 < 13.1-50.0', () => {
      expect(compareVersions('13.1-49.14', '13.1-50.0')).toBe(-1);
    });
    it('Citrix hyphenated: 13.1-49.14 == 13.1-49.14', () => {
      expect(compareVersions('13.1-49.14', '13.1-49.14')).toBe(0);
    });

    // Check Point: R81.20
    it('Check Point: R81.10 < R81.20', () => {
      expect(compareVersions('R81.10', 'R81.20')).toBe(-1);
    });
    it('Check Point: R80.40 < R81.10', () => {
      expect(compareVersions('R80.40', 'R81.10')).toBe(-1);
    });

    // FortiGate build format: 7.0.16 build 0000
    // compareVersions splits on . and -, so "7.0.16" part is what matters
    it('Fortinet: 7.0.15 < 7.0.16', () => {
      expect(compareVersions('7.0.15', '7.0.16')).toBe(-1);
    });

    // Alpha suffixes: 10.2.0.5-d-29sv
    it('alpha suffix: 10.2.0.5-d-29sv > 10.2.0.5-d-28sv', () => {
      expect(compareVersions('10.2.0.5-d-29sv', '10.2.0.5-d-28sv')).toBe(1);
    });

    // Ivanti: 22.7R2.5
    it('Ivanti: 22.7R2.4 < 22.7R2.5', () => {
      expect(compareVersions('22.7R2.4', '22.7R2.5')).toBe(-1);
    });
  });
});

describe('isVersionAffected boundary tests', () => {
  // Inclusive range: versionStart <= version <= versionEnd
  describe('versionStart/versionEnd (inclusive)', () => {
    const range = { versionStart: '7.0.0', versionEnd: '7.0.13' };

    it('version == versionStart → affected', () => {
      expect(isVersionAffected('7.0.0', range)).toBe(true);
    });
    it('version == versionEnd → affected', () => {
      expect(isVersionAffected('7.0.13', range)).toBe(true);
    });
    it('version inside range → affected', () => {
      expect(isVersionAffected('7.0.5', range)).toBe(true);
    });
    it('version below versionStart → not affected', () => {
      expect(isVersionAffected('6.4.99', range)).toBe(false);
    });
    it('version above versionEnd → not affected', () => {
      expect(isVersionAffected('7.0.14', range)).toBe(false);
    });
  });

  // versionExact
  describe('versionExact', () => {
    const exact = { versionExact: '7.2.1' };

    it('exact match → affected', () => {
      expect(isVersionAffected('7.2.1', exact)).toBe(true);
    });
    it('different version → not affected', () => {
      expect(isVersionAffected('7.2.0', exact)).toBe(false);
    });
    it('trailing zero not equal if string differs', () => {
      // versionExact uses strict === comparison
      expect(isVersionAffected('7.2.1.0', exact)).toBe(false);
    });
  });

  // Only versionStart (no upper bound)
  describe('versionStart only', () => {
    const range = { versionStart: '6.0.0' };

    it('version == versionStart → affected', () => {
      expect(isVersionAffected('6.0.0', range)).toBe(true);
    });
    it('version > versionStart → affected', () => {
      expect(isVersionAffected('99.0.0', range)).toBe(true);
    });
    it('version < versionStart → not affected', () => {
      expect(isVersionAffected('5.9.9', range)).toBe(false);
    });
  });

  // Only versionEnd (no lower bound)
  describe('versionEnd only', () => {
    const range = { versionEnd: '3.0.0' };

    it('version == versionEnd → affected', () => {
      expect(isVersionAffected('3.0.0', range)).toBe(true);
    });
    it('version < versionEnd → affected', () => {
      expect(isVersionAffected('1.0.0', range)).toBe(true);
    });
    it('version > versionEnd → not affected', () => {
      expect(isVersionAffected('3.0.1', range)).toBe(false);
    });
  });

  // No constraints
  describe('no version constraints', () => {
    it('returns false when no constraints defined', () => {
      expect(isVersionAffected('7.0.0', {})).toBe(false);
    });
    it('returns false with undefined values', () => {
      expect(isVersionAffected('1.0', {
        versionStart: undefined,
        versionEnd: undefined,
        versionExact: undefined,
      })).toBe(false);
    });
  });

  // VPN-specific version ranges
  describe('VPN-specific version ranges', () => {
    it('Citrix range: 13.1-49.13 in [13.1-48.47, 13.1-49.15]', () => {
      expect(isVersionAffected('13.1-49.13', {
        versionStart: '13.1-48.47',
        versionEnd: '13.1-49.15',
      })).toBe(true);
    });

    it('Check Point range: R81.10 in [R80.40, R81.20]', () => {
      expect(isVersionAffected('R81.10', {
        versionStart: 'R80.40',
        versionEnd: 'R81.20',
      })).toBe(true);
    });
  });
});
