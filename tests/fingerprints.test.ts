/**
 * Fingerprint Tests
 */

import { fingerprints, getFingerprintsByVendor, getAllVendors } from '../src/fingerprints/index.js';

describe('Fingerprints', () => {
  describe('fingerprints database', () => {
    it('should have fingerprints for major vendors', () => {
      const vendors = getAllVendors();
      
      expect(vendors).toContain('fortinet');
      expect(vendors).toContain('paloalto');
      expect(vendors).toContain('cisco');
      expect(vendors).toContain('pulse');
      expect(vendors).toContain('ivanti');
      expect(vendors).toContain('sonicwall');
      expect(vendors).toContain('checkpoint');
      expect(vendors).toContain('citrix');
      expect(vendors).toContain('openvpn');
    });

    it('should have at least 9 vendors', () => {
      const vendors = getAllVendors();
      expect(vendors.length).toBeGreaterThanOrEqual(9);
    });

    it('should have valid fingerprint structure', () => {
      for (const fp of fingerprints) {
        expect(fp.vendor).toBeDefined();
        expect(fp.product).toBeDefined();
        expect(Array.isArray(fp.patterns)).toBe(true);
        expect(fp.patterns.length).toBeGreaterThan(0);

        for (const pattern of fp.patterns) {
          expect(pattern.type).toBeDefined();
          expect(pattern.match).toBeDefined();
          expect(typeof pattern.weight).toBe('number');
          expect(pattern.weight).toBeGreaterThanOrEqual(1);
          expect(pattern.weight).toBeLessThanOrEqual(10);
        }
      }
    });
  });

  describe('getFingerprintsByVendor', () => {
    it('should return fingerprints for fortinet', () => {
      const fortinet = getFingerprintsByVendor('fortinet');
      expect(fortinet.length).toBeGreaterThan(0);
      expect(fortinet[0].vendor).toBe('fortinet');
    });

    it('should return empty array for unknown vendor', () => {
      const unknown = getFingerprintsByVendor('unknown-vendor');
      expect(unknown).toEqual([]);
    });
  });

  describe('FortiGate patterns', () => {
    it('should have /remote/login endpoint pattern', () => {
      const fortinet = getFingerprintsByVendor('fortinet')[0];
      const loginPattern = fortinet.patterns.find(
        p => p.type === 'endpoint' && p.path === '/remote/login'
      );
      expect(loginPattern).toBeDefined();
      expect(loginPattern?.weight).toBeGreaterThanOrEqual(8);
    });

    it('should have SVPNCOOKIE header pattern', () => {
      const fortinet = getFingerprintsByVendor('fortinet')[0];
      const cookiePattern = fortinet.patterns.find(
        p => p.type === 'header' && String(p.match).includes('SVPNCOOKIE')
      );
      expect(cookiePattern).toBeDefined();
    });
  });

  describe('Palo Alto patterns', () => {
    it('should have GlobalProtect endpoint patterns', () => {
      const paloalto = getFingerprintsByVendor('paloalto')[0];
      const gpPattern = paloalto.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('global-protect')
      );
      expect(gpPattern).toBeDefined();
    });
  });

  describe('Cisco patterns', () => {
    it('should have AnyConnect endpoint patterns', () => {
      const cisco = getFingerprintsByVendor('cisco')[0];
      const anyconnectPattern = cisco.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('CSCOE')
      );
      expect(anyconnectPattern).toBeDefined();
    });
  });

  describe('Pulse/Ivanti patterns', () => {
    it('should have dana-na endpoint patterns', () => {
      const pulse = getFingerprintsByVendor('pulse')[0];
      const danaPattern = pulse.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('dana-na')
      );
      expect(danaPattern).toBeDefined();
    });
  });

  describe('Citrix patterns', () => {
    it('should have NetScaler/Gateway patterns', () => {
      const citrix = getFingerprintsByVendor('citrix')[0];
      const citrixPattern = citrix.patterns.find(
        p => p.type === 'endpoint' && (p.path?.includes('vpn') || p.path?.includes('logon'))
      );
      expect(citrixPattern).toBeDefined();
    });
  });
});
