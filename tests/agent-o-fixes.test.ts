/**
 * Agent O Fixes Tests
 * - normalizeProduct comparison in checkVulnerabilities (#2)
 * - formatTable vendor display (#5)
 */

import { normalizeProduct, formatVendorName } from '../src/utils.js';
import type { VpnVendor } from '../src/types.js';

describe('normalizeProduct comparison (#2)', () => {
  it('should match products with different casing', () => {
    expect(normalizeProduct('FortiGate')).toBe(normalizeProduct('fortigate'));
  });

  it('should match products with extra spaces', () => {
    expect(normalizeProduct('Connect  Secure')).toBe(normalizeProduct('Connect Secure'));
  });

  it('should match products with leading/trailing spaces', () => {
    expect(normalizeProduct('  FortiGate  ')).toBe(normalizeProduct('FortiGate'));
  });

  it('should not match different products', () => {
    expect(normalizeProduct('FortiGate')).not.toBe(normalizeProduct('FortiProxy'));
  });
});

describe('formatVendorName in formatTable (#5)', () => {
  const cases: [VpnVendor, string][] = [
    ['fortinet', 'Fortinet'],
    ['paloalto', 'Palo Alto'],
    ['cisco', 'Cisco'],
    ['checkpoint', 'Check Point'],
    ['f5', 'F5 Networks'],
    ['sonicwall', 'SonicWall'],
  ];

  for (const [vendor, expected] of cases) {
    it(`should format "${vendor}" as "${expected}"`, () => {
      expect(formatVendorName(vendor)).toBe(expected);
    });
  }
});
